// Command admin runs the private AlfaGen operator control plane.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/alfagen/pii-service/internal/admin"
)

func main() {
	maintain := flag.Bool("maintain-crl", false, "renew CRL periodically without serving admin HTTP")
	refresh := flag.Bool("refresh-crl", false, "refresh CRL once and exit")
	lifetime := flag.Duration("crl-lifetime", 7*24*time.Hour, "CRL validity, capped at CA expiry")
	flag.Parse()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	store, err := admin.NewStore(admin.StoreOptions{
		BackendConfigPath: env("ALFAGEN_ADMIN_BACKEND_CONFIG", "/run/alfagen/backend/config.yaml"),
		MockConfigPath:    env("ALFAGEN_ADMIN_MOCK_CONFIG", "/run/alfagen/mock-client/config.json"),
		APIKeyDir:         env("ALFAGEN_ADMIN_API_KEY_DIR", "/run/alfagen/admin/api-keys"),
		RuntimeAPIKeyDir:  env("ALFAGEN_ADMIN_RUNTIME_API_KEY_DIR", "/run/alfagen/api-keys"),
		MTLSDir:           env("ALFAGEN_ADMIN_MTLS_DIR", "/run/alfagen/mtls"),
		StatusPath:        env("ALFAGEN_ADMIN_STATUS", "/run/alfagen/reports/status.json"),
		ReportPath:        env("ALFAGEN_ADMIN_REPORT", "/run/alfagen/reports/load-report.json"),
		AuditPath:         env("ALFAGEN_ADMIN_AUDIT", "/run/alfagen/admin/audit.jsonl"),
		CRLLifetime:       *lifetime,
		CertificateTTL:    envDuration("ALFAGEN_ADMIN_CERT_TTL", 365*24*time.Hour),
	})
	if err != nil {
		fatal(logger, err)
	}
	if *maintain || *refresh {
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		maintainCRL(ctx, store, logger, *refresh)
		return
	}
	server, err := admin.NewServer(store, admin.ServerOptions{
		PrometheusURL:       env("ALFAGEN_ADMIN_PROMETHEUS_URL", ""),
		ProcessURL:          env("ALFAGEN_ADMIN_PROCESS_URL", "http://proxy:8080/process"),
		DisableCertificates: envBool("ALFAGEN_ADMIN_DISABLE_CERTIFICATES", false),
		AdminTokenFile:      env("ALFAGEN_ADMIN_TOKEN_FILE", "/run/secrets/admin-token"),
		SecureCookies:       envBool("ALFAGEN_ADMIN_SECURE_COOKIES", true),
		SessionTTL:          envDuration("ALFAGEN_ADMIN_SESSION_TTL", 8*time.Hour),
		Logger:              logger,
	})
	if err != nil {
		fatal(logger, err)
	}
	httpServer := &http.Server{Addr: env("ALFAGEN_ADMIN_ADDR", ":8090"), Handler: server.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errCh := make(chan error, 1)
	go func() {
		logger.Info("admin server starting", "addr", httpServer.Addr)
		errCh <- httpServer.ListenAndServe()
	}()
	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			fatal(logger, err)
		}
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdown); err != nil {
			fatal(logger, err)
		}
	}
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
func envDuration(name string, fallback time.Duration) time.Duration {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		panic(fmt.Sprintf("%s: %v", name, err))
	}
	return parsed
}
func envBool(name string, fallback bool) bool {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		panic(fmt.Sprintf("%s: %v", name, err))
	}
	return parsed
}
func fatal(logger *slog.Logger, err error) { logger.Error("fatal", "error", err); os.Exit(1) }

func maintainCRL(ctx context.Context, store *admin.Store, logger *slog.Logger, once bool) {
	if err := store.RefreshCRL(time.Now(), once); err != nil {
		fatal(logger, err)
	}
	if once {
		return
	}
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			if err := store.RefreshCRL(now, false); err != nil {
				logger.Error("CRL renewal failed", "error", err)
			}
		}
	}
}
