// Command server runs the AlfaGen PII protection service.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/alfagen/pii-service/internal/llm"
	"github.com/alfagen/pii-service/internal/pii"
	"github.com/alfagen/pii-service/internal/pii/detectors"
	"github.com/alfagen/pii-service/internal/pii/engine"
	"github.com/alfagen/pii-service/internal/pii/store"
	"github.com/alfagen/pii-service/internal/platform/config"
	"github.com/alfagen/pii-service/internal/platform/observability"
	"github.com/alfagen/pii-service/internal/proxy"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
)

const (
	defaultConfigPath = "config.example.yaml"
	defaultPoll       = 5 * time.Second

	deploymentProfileLocal      = "local"
	deploymentProfileProduction = "production"
)

// runOptions carries startup inputs. Tests inject a Source and poll interval
// directly; production builds them from the CLI flag and environment.
type runOptions struct {
	configPath string
	source     config.Source
	poll       time.Duration
	// ready, when non-nil, receives the bound listen address once the HTTP
	// server is listening. It is used by tests to learn the ephemeral port.
	ready chan string
	// manager and registry, when non-nil, receive the built Manager and
	// Prometheus registry so tests can drive reloads and inspect metrics.
	manager  **config.Manager
	registry **prometheus.Registry
}

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", defaultConfigPath, "path to config file")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, runOptions{configPath: configPath}); err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

// run selects the config source, builds the Manager and the HTTP components
// from the first accepted snapshot, then serves until ctx is cancelled or the
// server fails. The Manager is passed as the SystemResolver so hot reloads
// update the policy for new requests without restarting the process.
func run(ctx context.Context, opts runOptions) error {
	src, poll, err := buildSource(opts)
	if err != nil {
		return err
	}

	// The registry must exist before the Manager so reload metrics are recorded.
	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	metrics := observability.NewMetrics(reg)

	mgr, err := config.NewManagerFromSource(ctx, src, poll, metrics)
	if err != nil {
		return err
	}
	if opts.manager != nil {
		*opts.manager = mgr
	}
	if opts.registry != nil {
		*opts.registry = reg
	}

	cfg := mgr.Initial()

	// Production validation runs after the first snapshot has fully resolved
	// every secret file (NewManagerFromSource/Validate above) but before any
	// store, provider or listener goroutine starts.
	if err := validateDeploymentProfile(cfg); err != nil {
		return err
	}

	logger, err := observability.NewLogger(cfg.Security.LogLevel)
	if err != nil {
		return err
	}
	metrics.AttachLogger(logger)

	var draining atomic.Bool
	comps, err := buildComponents(cfg, metrics, logger, draining.Load)
	if err != nil {
		return err
	}
	if comps.redisClient != nil {
		defer comps.redisClient.Close()
		registerRedisMetrics(reg, comps.redisClient)
	}
	// The Manager, not the static Config, resolves systems so hot reloads apply.
	comps.srv.ConfigureSystems(mgr, cfg.Default)

	mux := http.NewServeMux()
	apiHandler := comps.srv.Handler()
	mux.Handle("/", apiHandler)
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))

	httpServer := &http.Server{
		Addr:              cfg.Server.Addr,
		Handler:           mux,
		ReadHeaderTimeout: cfg.Server.ReadHeaderTimeout,
		ReadTimeout:       cfg.Server.ReadTimeout,
		WriteTimeout:      cfg.Server.WriteTimeout,
		IdleTimeout:       cfg.Server.IdleTimeout,
	}

	// TTL cleanup loop for the in-memory store.
	cleanupCtx, cleanupCancel := context.WithCancel(ctx)
	defer cleanupCancel()
	go cleanupMemoryStore(cleanupCtx, comps.memoryStore, cfg.Store.CleanupEvery)

	// Stop the watcher before run returns, including startup and serve errors.
	watchCtx, stopWatcher := context.WithCancel(ctx)
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		mgr.Run(watchCtx)
	}()
	defer func() {
		stopWatcher()
		<-watcherDone
	}()

	ln, err := net.Listen("tcp", cfg.Server.Addr)
	if err != nil {
		return err
	}
	addr := ln.Addr().String()
	if opts.ready != nil {
		select {
		case opts.ready <- addr:
		default:
		}
	}

	logger.Info("server starting", "addr", addr, "system", cfg.Default)
	return serveUntilStopped(ctx, httpServer, ln, cfg.Server, &draining, logger)
}

// validateDeploymentProfile enforces the production startup gate. It reads
// ALFAGEN_DEPLOYMENT_PROFILE (default "local"); an unknown value is a safe
// startup error. "production" additionally requires process-only runtime,
// Redis store and file-backed encryption keys only (no literals). An enabled
// system must then choose exactly one access mode: explicit anonymous access
// without an API key, or an authenticated file-backed API key. Errors never
// include secret values or raw config; system/key IDs are configuration
// identifiers, not secrets.
func validateDeploymentProfile(cfg *config.Config) error {
	profile := os.Getenv("ALFAGEN_DEPLOYMENT_PROFILE")
	if profile == "" {
		profile = deploymentProfileLocal
	}
	if profile != deploymentProfileLocal && profile != deploymentProfileProduction {
		return fmt.Errorf("config: invalid ALFAGEN_DEPLOYMENT_PROFILE")
	}
	if profile != deploymentProfileProduction {
		return nil
	}

	if cfg.Runtime.Mode != config.RuntimeProcessOnly {
		return fmt.Errorf("config: production requires runtime.mode=process_only")
	}
	if cfg.Store.Mode != "redis" {
		return fmt.Errorf("config: production requires store.mode=redis")
	}
	if cfg.Security.ActiveKeyID == "" {
		return fmt.Errorf("config: production requires an active encryption key")
	}
	if len(cfg.Security.EncryptionKeys) > 0 {
		return fmt.Errorf("config: production forbids literal encryption keys")
	}
	if _, ok := cfg.Security.EncryptionKeyFiles[cfg.Security.ActiveKeyID]; !ok {
		return fmt.Errorf("config: production requires a file-backed active encryption key")
	}

	return validateProductionSystems(cfg.Systems)
}

// buildSource resolves the config Source and poll interval from opts or the
// environment. An injected Source takes precedence so tests can use fakes.
func buildSource(opts runOptions) (config.Source, time.Duration, error) {
	if opts.source != nil {
		if opts.poll <= 0 {
			return nil, 0, fmt.Errorf("config: poll interval must be positive")
		}
		return opts.source, opts.poll, nil
	}

	sourceMode := os.Getenv("ALFAGEN_CONFIG_SOURCE")
	if sourceMode == "" {
		sourceMode = "file"
	}
	pollStr := os.Getenv("ALFAGEN_CONFIG_POLL")
	if pollStr == "" {
		pollStr = "5s"
	}
	poll, err := time.ParseDuration(pollStr)
	if err != nil {
		return nil, 0, fmt.Errorf("config: invalid ALFAGEN_CONFIG_POLL")
	}

	switch sourceMode {
	case "file":
		path := opts.configPath
		if env := os.Getenv("ALFAGEN_CONFIG_FILE"); env != "" {
			path = env
		}
		return config.NewFileSource(path), poll, nil
	case "kubernetes":
		namespace, name, key := kubernetesSourceLocation()
		src, err := config.NewInClusterSecretSource(namespace, name, key)
		if err != nil {
			return nil, 0, err
		}
		return src, poll, nil
	default:
		return nil, 0, fmt.Errorf("config: invalid ALFAGEN_CONFIG_SOURCE")
	}
}

// defaultNamespace reads the in-cluster namespace file, returning "" when it is
// unavailable so the kubernetes source fails with a safe validation error.
func defaultNamespace() string {
	data, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// components bundles the store, processor, server and provider built from a
// single immutable Config snapshot.
type components struct {
	store       store.Store
	memoryStore *store.TTLStore
	redisClient *redis.Client
	proc        *engine.Processor
	srv         *proxy.Server
	provider    *llm.HTTPProvider
}

// buildComponents builds the store, processor, server and provider from cfg.
// The server's systems resolver is configured by the caller (run passes the
// Manager) so hot reloads apply. draining, when non-nil, is wired into the
// Server so SIGTERM handling in run can flip it without rebuilding anything.
func buildComponents(cfg *config.Config, metrics *observability.Metrics, logger *observability.Logger, draining func() bool) (*components, error) {
	comps, err := buildStorage(cfg)
	if err != nil {
		return nil, err
	}
	st := comps.store
	success := false
	defer func() {
		if !success && comps.redisClient != nil {
			comps.redisClient.Close()
		}
	}()

	customDetectors, err := cfg.CustomDetectors()
	if err != nil {
		return nil, err
	}
	detReg := pii.NewRegistry(append(detectors.All(), customDetectors...)...)
	proc := engine.New(st, detReg, metrics)

	// The provider is only constructed for the test-only test_generate mode.
	// process_only never calls the provider factory and never dials it: cfg.Provider
	// is nil in that mode (enforced by config.Validate), so any unguarded access
	// here would panic rather than silently phone home.
	enableGenerate := cfg.Runtime.Mode == config.RuntimeTestGenerate

	srvCfg := &proxy.ServerConfig{
		MaxBodyBytes:     cfg.Server.MaxBodyBytes,
		ConcurrencyLimit: cfg.Server.ConcurrencyLimit,
		RequestTimeout:   cfg.Server.RequestTimeout,
		RateLimitRPS:     cfg.Server.RateLimitRPS,
		RateLimitBurst:   cfg.Server.RateLimitBurst,
		EnableGenerate:   enableGenerate,
		Draining:         draining,
	}
	if enableGenerate {
		srvCfg.AllowedModels = cfg.Provider.Models
	}
	srv := proxy.NewServer(proc, metrics, logger, proc, srvCfg)

	var provider *llm.HTTPProvider
	if enableGenerate {
		var err error
		provider, err = llm.NewHTTPProvider(cfg.Provider.BaseURL, &http.Client{
			Timeout: cfg.Provider.Timeout,
			Transport: &http.Transport{
				MaxIdleConns:        512,
				MaxIdleConnsPerHost: 256,
				IdleConnTimeout:     90 * time.Second,
			},
		}, cfg.Provider.Models)
		if err != nil {
			return nil, err
		}
		srv.ConfigureProvider(provider)
	}

	comps.proc, comps.srv, comps.provider = proc, srv, provider
	success = true
	return comps, nil
}

func registerRedisMetrics(reg *prometheus.Registry, client *redis.Client) {
	reg.MustRegister(
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "redis_pool_connections", Help: "Open Redis pool connections."}, func() float64 { return float64(client.PoolStats().TotalConns) }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "redis_pool_idle_connections", Help: "Idle Redis pool connections."}, func() float64 { return float64(client.PoolStats().IdleConns) }),
		prometheus.NewCounterFunc(prometheus.CounterOpts{Name: "redis_pool_timeouts_total", Help: "Timeouts waiting for a Redis connection."}, func() float64 { return float64(client.PoolStats().Timeouts) }),
		prometheus.NewCounterFunc(prometheus.CounterOpts{Name: "redis_pool_misses_total", Help: "Redis pool connection misses."}, func() float64 { return float64(client.PoolStats().Misses) }),
	)
}

func cleanupMemoryStore(ctx context.Context, memoryStore *store.TTLStore, interval time.Duration) {
	if memoryStore == nil {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			memoryStore.Cleanup()
		}
	}
}

func serveUntilStopped(ctx context.Context, httpServer *http.Server, ln net.Listener, settings config.ServerConfig, draining *atomic.Bool, logger *observability.Logger) error {
	errCh := make(chan error, 1)
	go func() {
		errCh <- httpServer.Serve(ln)
	}()

	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			return err
		}
	case <-ctx.Done():
		logger.Info("shutdown signal")
		// Atomically stop readiness and new business requests first, then
		// give in-flight callers and load balancers time to notice before
		// closing listeners. A second cancellation during the wait (e.g. a
		// repeated signal) does not block or re-enter this path.
		draining.Store(true)
		timer := time.NewTimer(settings.DrainDelay)
		defer timer.Stop()
		<-timer.C
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), settings.ShutdownTimeout)
	defer shutdownCancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		return err
	}
	logger.Info("server stopped")
	return nil
}

func validateProductionSystems(systems []config.SystemConfig) error {
	enabledSystems := 0
	for _, s := range systems {
		enabled := s.Enabled == nil || *s.Enabled
		if !enabled {
			continue
		}
		enabledSystems++
		if s.APIKey != "" {
			return fmt.Errorf("config: production forbids a literal api_key for system %q", s.ID)
		}
		if s.AllowAnonymous {
			if s.APIKeyFile != "" {
				return fmt.Errorf("config: production anonymous system %q must not configure api_key_file", s.ID)
			}
			continue
		}
		if s.APIKeyFile == "" {
			return fmt.Errorf("config: production requires a file-backed api_key for system %q", s.ID)
		}
	}
	if enabledSystems == 0 {
		return fmt.Errorf("config: production requires at least one enabled system")
	}
	return nil
}

func kubernetesSourceLocation() (namespace, name, key string) {
	namespace = os.Getenv("ALFAGEN_CONFIG_NAMESPACE")
	if namespace == "" {
		namespace = defaultNamespace()
	}
	name = os.Getenv("ALFAGEN_CONFIG_SECRET")
	if name == "" {
		name = "backend-config"
	}
	key = os.Getenv("ALFAGEN_CONFIG_KEY")
	if key == "" {
		key = "config.json"
	}
	return
}

func buildStorage(cfg *config.Config) (*components, error) {
	var st store.Store
	var memoryStore *store.TTLStore
	var redisClient *redis.Client
	if cfg.Store.Mode == "redis" {
		codec, err := buildCodec(cfg)
		if err != nil {
			return nil, err
		}
		redisClient = redis.NewClient(&redis.Options{Addr: cfg.Store.RedisAddr, Password: cfg.Store.RedisPassword, DB: cfg.Store.RedisDB, ContextTimeoutEnabled: true, DialTimeout: 3 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second, PoolSize: cfg.Store.PoolSize, MinIdleConns: cfg.Store.MinIdleConns, PoolTimeout: cfg.Store.PoolTimeout})
		pingCtx, pingCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer pingCancel()
		if err := redisClient.Ping(pingCtx).Err(); err != nil {
			redisClient.Close()
			return nil, fmt.Errorf("redis unavailable: %w", err)
		}
		st, err = store.NewRedisStore(redisClient, codec, cfg.Store.TTL, cfg.Store.KeyPrefix)
		if err != nil {
			redisClient.Close()
			return nil, err
		}
	} else {
		memoryStore = store.NewTTLStore(cfg.Store.TTL)
		st = memoryStore
	}

	return &components{store: st, memoryStore: memoryStore, redisClient: redisClient}, nil
}

func buildCodec(cfg *config.Config) (*store.Codec, error) {
	resolvedKeys, err := cfg.ResolvedEncryptionKeys()
	if err != nil {
		return nil, err
	}
	keys := make(map[string][]byte, len(resolvedKeys))
	for id, value := range resolvedKeys {
		decoded, err := store.DecodeKey(value)
		if err != nil {
			return nil, fmt.Errorf("encryption key %q: %w", id, err)
		}
		keys[id] = decoded
	}
	return store.NewCodec(cfg.Security.ActiveKeyID, keys)
}
