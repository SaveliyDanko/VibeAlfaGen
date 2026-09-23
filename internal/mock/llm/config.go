package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/alfagen/pii-service/internal/platform/config"
)

// DocConfig is the on-disk or Kubernetes Secret configuration for the mock
// LLM, matching the mock-llm-config/config.json schema.
type DocConfig struct {
	Version      string `json:"version"`
	Enabled      bool   `json:"enabled"`
	Addr         string `json:"addr"`
	Mode         string `json:"mode"`
	Seed         int64  `json:"seed"`
	Delay        string `json:"delay"`
	Status       int    `json:"status"`
	CaptureTTL   string `json:"capture_ttl"`
	CaptureLimit int    `json:"capture_limit"`
}

// Validate rejects missing or invalid required fields. The listen address is
// immutable after the first accepted document.
func (c *DocConfig) Validate() error {
	if c.Version == "" {
		return errors.New("mock-llm config: version required")
	}
	if c.Addr == "" {
		return errors.New("mock-llm config: addr required")
	}
	switch c.Mode {
	case "", ModeEcho, ModeReorder, ModeCorrupt:
	default:
		return fmt.Errorf("mock-llm config: unknown mode %q", c.Mode)
	}
	if _, err := time.ParseDuration(c.Delay); err != nil || c.Delay == "" {
		return errors.New("mock-llm config: delay must be a valid duration")
	}
	if c.Status != 0 && c.Status != 200 && (c.Status < 400 || c.Status > 599) {
		return fmt.Errorf("mock-llm config: invalid status %d", c.Status)
	}
	if _, err := time.ParseDuration(c.CaptureTTL); err != nil || c.CaptureTTL == "" {
		return errors.New("mock-llm config: capture_ttl must be a valid duration")
	}
	if c.CaptureLimit < 0 {
		return errors.New("mock-llm config: capture_limit must not be negative")
	}
	return nil
}

// HandlerConfig converts the document configuration into a mock LLM Config.
func (c *DocConfig) HandlerConfig() (Config, error) {
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	delay, err := time.ParseDuration(c.Delay)
	if err != nil {
		return Config{}, fmt.Errorf("mock-llm config: delay: %w", err)
	}
	captureTTL, err := time.ParseDuration(c.CaptureTTL)
	if err != nil {
		return Config{}, fmt.Errorf("mock-llm config: capture_ttl: %w", err)
	}
	return Config{
		Disabled:     !c.Enabled,
		Mode:         c.Mode,
		Seed:         c.Seed,
		Delay:        delay,
		Status:       c.Status,
		CaptureTTL:   captureTTL,
		CaptureLimit: c.CaptureLimit,
	}, nil
}

// Reloader reads a mock-LLM document from a config.Source and atomically
// publishes snapshots. A new version replaces the snapshot entirely; the same
// version with different content is an error; the same version with the same
// content is a no-op. A read or validation error keeps the last working
// snapshot. The listen address is immutable: a change is rejected.
type Reloader struct {
	source  config.Source
	poll    time.Duration
	mu      sync.RWMutex
	current *DocConfig
	raw     []byte
	version string
	addr    string
	runOnce sync.Once
}

// NewReloader reads the first document synchronously. An error here means the
// process must not become ready.
func NewReloader(ctx context.Context, src config.Source, poll time.Duration) (*Reloader, error) {
	if poll <= 0 {
		return nil, errors.New("mock-llm config: poll interval must be positive")
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
	return &c
}

// Addr returns the immutable listen address from the first accepted document.
func (r *Reloader) Addr() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.addr
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
		return fmt.Errorf("mock-llm config: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return errors.New("mock-llm config: expected one JSON document")
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	if r.current != nil {
		if cfg.Addr != r.addr {
			return fmt.Errorf("mock-llm config: listen address is immutable")
		}
		if cfg.Version == r.version {
			if bytes.Equal(doc.Data, r.raw) {
				return nil
			}
			return fmt.Errorf("mock-llm config: version %q unchanged but content differs", cfg.Version)
		}
	}
	r.current = &cfg
	r.raw = doc.Data
	r.version = cfg.Version
	r.addr = cfg.Addr
	return nil
}
