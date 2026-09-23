package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/alfagen/pii-service/internal/platform/config"
)

const configErrorFormat = "mock-client config: %w"

// DocConfig is the on-disk or Kubernetes Secret configuration for the mock
// client, matching the mock-client-config/config.json schema.
type DocConfig struct {
	RunID            string             `json:"run_id,omitempty"`
	Version          string             `json:"version"`
	Enabled          bool               `json:"enabled"`
	Mode             string             `json:"mode"`
	Scenario         string             `json:"scenario,omitempty"`
	TargetURL        string             `json:"target_url"`
	Seed             int64              `json:"seed"`
	RatePerSecond    float64            `json:"rate_per_second"`
	Duration         string             `json:"duration,omitempty"`
	Concurrency      int                `json:"concurrency,omitempty"`
	MaxInFlight      int                `json:"max_in_flight"`
	RequestTimeout   string             `json:"request_timeout"`
	OperationLimit   int64              `json:"operation_limit,omitempty"`
	PayloadProfile   string             `json:"payload_profile"`
	OperationWeights map[string]float64 `json:"operation_weights,omitempty"`
	SystemID         string             `json:"system_id"`
	APIKeyEnv        string             `json:"api_key_env"`
	// APIKeyFile supports runtime-mounted secrets and can be changed together
	// with a hot-reloaded test configuration. It is mutually exclusive with
	// APIKeyEnv; the secret value is never included in reports.
	APIKeyFile string `json:"api_key_file,omitempty"`
}

// Validate rejects missing or invalid required fields.
func (c *DocConfig) Validate() error {
	if c.Version == "" {
		return errors.New("mock-client config: version required")
	}
	switch c.Mode {
	case ModeProcess, ModeGenerate:
	default:
		return fmt.Errorf("mock-client config: unknown mode %q", c.Mode)
	}
	if err := c.validateScenario(); err != nil {
		return err
	}
	if err := (Config{Mode: c.Mode, TargetURL: c.TargetURL, RatePerSecond: c.RatePerSecond}).validateTarget(); err != nil {
		return fmt.Errorf(configErrorFormat, err)
	}
	if c.MaxInFlight <= 0 {
		return errors.New("mock-client config: max_in_flight must be positive")
	}
	if c.Concurrency < 0 {
		return errors.New("mock-client config: concurrency must not be negative")
	}
	if err := c.validateDurations(); err != nil {
		return err
	}
	if c.OperationLimit < 0 {
		return errors.New("mock-client config: operation_limit must not be negative")
	}
	if c.PayloadProfile == "" {
		return errors.New("mock-client config: payload_profile required")
	}
	if c.SystemID == "" {
		return errors.New("mock-client config: system_id required")
	}
	if err := c.validateCredentials(); err != nil {
		return err
	}
	if c.Scenario == ScenarioMixed {
		if err := validateOperationWeights(c.OperationWeights); err != nil {
			return fmt.Errorf(configErrorFormat, err)
		}
	}
	return nil
}

// RunnerConfig converts the document configuration into a runner Config. The
// API key is resolved from the environment variable named by APIKeyEnv.
func (c *DocConfig) RunnerConfig() (Config, error) {
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	timeout, err := time.ParseDuration(c.RequestTimeout)
	if err != nil {
		return Config{}, fmt.Errorf("mock-client config: request_timeout: %w", err)
	}
	duration := time.Duration(0)
	if c.Duration != "" {
		duration, err = time.ParseDuration(c.Duration)
		if err != nil {
			return Config{}, fmt.Errorf("mock-client config: duration: %w", err)
		}
	}
	concurrency := c.Concurrency
	if concurrency == 0 {
		concurrency = c.MaxInFlight
	}
	apiKey := ""
	if c.APIKeyEnv != "" {
		apiKey = envOr(c.APIKeyEnv, "")
	}
	if c.APIKeyFile != "" {
		raw, readErr := os.ReadFile(c.APIKeyFile)
		if readErr != nil {
			return Config{}, errors.New("mock-client config: API key file unavailable")
		}
		if len(raw) > 4096 {
			return Config{}, errors.New("mock-client config: API key file is too large")
		}
		apiKey = strings.TrimSpace(string(raw))
		if apiKey == "" {
			return Config{}, errors.New("mock-client config: API key file is empty")
		}
	}
	return Config{
		Version:          c.Version,
		Mode:             c.Mode,
		Scenario:         c.Scenario,
		TargetURL:        c.TargetURL,
		Seed:             c.Seed,
		RatePerSecond:    c.RatePerSecond,
		Duration:         duration,
		Concurrency:      concurrency,
		MaxInFlight:      c.MaxInFlight,
		RequestTimeout:   timeout,
		OperationLimit:   c.OperationLimit,
		PayloadProfile:   c.PayloadProfile,
		SystemID:         c.SystemID,
		APIKey:           apiKey,
		Enabled:          c.Enabled,
		OperationWeights: copyFloat64Map(c.OperationWeights),
	}, nil
}

func copyFloat64Map(source map[string]float64) map[string]float64 {
	copy := make(map[string]float64, len(source))
	for key, value := range source {
		copy[key] = value
	}
	return copy
}

// Reloader reads a mock-client document from a config.Source and atomically
// publishes snapshots. A new version replaces the snapshot entirely; the same
// version with different content is an error; the same version with the same
// content is a no-op. A read or validation error keeps the last working
// snapshot.
type Reloader struct {
	source  config.Source
	poll    time.Duration
	mu      sync.RWMutex
	current *DocConfig
	raw     []byte
	version string
	runOnce sync.Once
}

// NewReloader reads the first document synchronously. An error here means the
// process must not become ready.
func NewReloader(ctx context.Context, src config.Source, poll time.Duration) (*Reloader, error) {
	if poll <= 0 {
		return nil, errors.New("mock-client config: poll interval must be positive")
	}
	r := &Reloader{source: src, poll: poll}
	if err := r.ReloadContext(ctx); err != nil {
		return nil, err
	}
	return r, nil
}

// Current returns a copy of the current document configuration.
func (r *Reloader) Current() *DocConfig {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.current == nil {
		return nil
	}
	c := *r.current
	c.OperationWeights = copyFloat64Map(r.current.OperationWeights)
	return &c
}

// ReloadContext reads and atomically publishes a new snapshot.
func (r *Reloader) ReloadContext(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reloadLocked(ctx)
}

// Run reloads on the poll interval until ctx is cancelled.
func (r *Reloader) Run(ctx context.Context) {
	r.runOnce.Do(func() {
		ticker := time.NewTicker(r.poll)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = r.ReloadContext(ctx)
			}
		}
	})
}

// Watch reloads on the poll interval and emits the current document whenever
// the version changes. The channel is closed when ctx is cancelled.
func (r *Reloader) Watch(ctx context.Context) <-chan *DocConfig {
	ch := make(chan *DocConfig, 1)
	go r.watchSnapshots(ctx, ch)
	return ch
}

func (r *Reloader) watchSnapshots(ctx context.Context, ch chan<- *DocConfig) {
	defer close(ch)
	ticker := time.NewTicker(r.poll)
	defer ticker.Stop()
	lastVersion := ""
	if cur := r.Current(); cur != nil {
		lastVersion = cur.Version
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cur := r.changedSnapshot(ctx, lastVersion)
			if cur == nil {
				continue
			}
			lastVersion = cur.Version
			select {
			case ch <- cur:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (r *Reloader) changedSnapshot(ctx context.Context, version string) *DocConfig {
	if err := r.ReloadContext(ctx); err != nil {
		return nil
	}
	cur := r.Current()
	if cur == nil || cur.Version == version {
		return nil
	}
	return cur
}

func (r *Reloader) reloadLocked(ctx context.Context) error {
	doc, err := r.source.Read(ctx)
	if err != nil {
		return err
	}
	var cfg DocConfig
	dec := json.NewDecoder(bytes.NewReader(doc.Data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return fmt.Errorf(configErrorFormat, err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return errors.New("mock-client config: expected one JSON document")
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	if r.current != nil {
		if cfg.Version == r.version {
			if bytes.Equal(doc.Data, r.raw) {
				return nil
			}
			return fmt.Errorf("mock-client config: version %q unchanged but content differs", cfg.Version)
		}
	}
	cfg.OperationWeights = copyFloat64Map(cfg.OperationWeights)
	r.current = &cfg
	r.raw = append([]byte(nil), doc.Data...)
	r.version = cfg.Version
	return nil
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func (c *DocConfig) validateDurations() error {
	if c.Duration != "" {
		if duration, err := time.ParseDuration(c.Duration); err != nil || duration < 0 {
			return errors.New("mock-client config: duration must be a non-negative duration")
		}
	}
	if timeout, err := time.ParseDuration(c.RequestTimeout); err != nil || timeout <= 0 {
		return errors.New("mock-client config: request_timeout must be a positive duration")
	}
	return nil
}

func (c *DocConfig) validateScenario() error {
	if c.Scenario != "" && c.Scenario != ScenarioRequest && c.Scenario != ScenarioMaskOnly && c.Scenario != ScenarioRoundTrip && c.Scenario != ScenarioStableRetry && c.Scenario != ScenarioExpectedConflict && c.Scenario != ScenarioMixed {
		return fmt.Errorf("mock-client config: unknown scenario %q", c.Scenario)
	}
	if c.Scenario != "" && c.Scenario != ScenarioRequest && c.Mode != ModeProcess {
		return fmt.Errorf("mock-client config: %s scenario requires process mode", c.Scenario)
	}
	return nil
}

func (c *DocConfig) validateCredentials() error {
	if c.APIKeyEnv != "" && c.APIKeyFile != "" {
		return errors.New("mock-client config: api_key_env and api_key_file are mutually exclusive")
	}
	if c.APIKeyFile != "" && !filepath.IsAbs(c.APIKeyFile) {
		return errors.New("mock-client config: api_key_file must be absolute")
	}
	return nil
}
