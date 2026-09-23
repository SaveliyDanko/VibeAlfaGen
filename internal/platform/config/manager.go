package config

import (
	"context"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"sync"
	"time"

	"github.com/alfagen/pii-service/internal/contracts"
	"github.com/alfagen/pii-service/internal/platform/observability"
)

// Manager atomically reloads a validated config file and publishes an
// immutable snapshot of resolved consumers. A failed update keeps the last
// working snapshot. Only Version and Systems are hot; the remaining fields are
// compared against the initial configuration and reject the whole update if
// changed.
type Manager struct {
	source       Source
	pollInterval time.Duration
	metrics      *observability.Metrics

	reloadMu sync.Mutex
	mu       sync.RWMutex
	current  *snapshot
	initial  *Config
	runOnce  sync.Once
}

// snapshot is an immutable published configuration view.
type snapshot struct {
	version string
	systems map[string]contracts.Consumer
}

var _ contracts.SystemResolver = (*Manager)(nil)

// NewManagerFromSource loads the first snapshot synchronously from src. A
// source, configuration or non-positive interval error returns an error without
// a working Manager. No background goroutine or ticker is created here.
func NewManagerFromSource(ctx context.Context, src Source, pollInterval time.Duration, metrics *observability.Metrics) (*Manager, error) {
	if pollInterval <= 0 {
		return nil, fmt.Errorf("config: poll interval must be positive")
	}
	m := &Manager{source: src, pollInterval: pollInterval, metrics: metrics}
	cand, cfg, err := m.buildCandidate(ctx)
	if err != nil {
		m.record("error")
		return nil, err
	}
	m.initial = deepCopyConfig(cfg)
	m.current = cand
	m.record("success")
	return m, nil
}

// NewManager loads the first snapshot synchronously from the file at path. It
// is a convenience wrapper around NewManagerFromSource.
func NewManager(path string, pollInterval time.Duration, metrics *observability.Metrics) (*Manager, error) {
	return NewManagerFromSource(context.Background(), NewFileSource(path), pollInterval, metrics)
}

// ResolveSystem returns a detached Consumer with all nested slices copied.
// Mutating the returned object does not affect the Manager or other requests.
func (m *Manager) ResolveSystem(id string) (contracts.Consumer, bool) {
	m.mu.RLock()
	c, ok := m.current.systems[id]
	m.mu.RUnlock()
	if !ok {
		return contracts.Consumer{}, false
	}
	return copyConsumer(c), true
}

// ReloadContext reads, validates and atomically publishes a new snapshot using
// ctx for the source read. Parallel reloads are serialized; readers observe
// either the whole old or the whole new snapshot. A failed update keeps the
// last working snapshot.
func (m *Manager) ReloadContext(ctx context.Context) error {
	m.reloadMu.Lock()
	defer m.reloadMu.Unlock()

	cand, _, err := m.buildCandidate(ctx)
	if err != nil {
		m.record("error")
		return err
	}

	m.mu.RLock()
	cur := m.current
	m.mu.RUnlock()

	if cand.version == cur.version {
		if systemsEqual(cand.systems, cur.systems) {
			m.record("noop")
			return nil
		}
		m.record("error")
		return fmt.Errorf("config: version %q unchanged but parameters differ", cand.version)
	}

	m.mu.Lock()
	m.current = cand
	m.mu.Unlock()
	m.record("success")
	return nil
}

// Reload reads, validates and atomically publishes a new snapshot. It is a
// convenience wrapper around ReloadContext.
func (m *Manager) Reload() error {
	return m.ReloadContext(context.Background())
}

// Initial returns a deep copy of the first accepted Config. Mutating the
// returned value does not affect the Manager.
func (m *Manager) Initial() *Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return deepCopyConfig(m.initial)
}

// Run blocks the caller until ctx is cancelled, reloading on the poll interval.
// Only one Run is active per Manager; the ticker is released on exit.
func (m *Manager) Run(ctx context.Context) {
	m.runOnce.Do(func() {
		ticker := time.NewTicker(m.pollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = m.ReloadContext(ctx)
			}
		}
	})
}

// Version returns the version of the currently published snapshot.
func (m *Manager) Version() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.current.version
}

func (m *Manager) buildCandidate(ctx context.Context) (*snapshot, *Config, error) {
	doc, err := m.source.Read(ctx)
	if err != nil {
		return nil, nil, err
	}
	cfg, err := parseDocument(doc)
	if err != nil {
		return nil, nil, err
	}
	if m.initial != nil && !immutableEqual(cfg, m.initial) {
		return nil, nil, fmt.Errorf("config: immutable fields changed")
	}
	snap := &snapshot{version: cfg.Version, systems: make(map[string]contracts.Consumer, len(cfg.Systems))}
	for _, s := range cfg.Systems {
		c, ok := buildConsumer(s, cfg.Version, cfg.Store.TTL)
		if !ok {
			enabled := s.Enabled == nil || *s.Enabled
			if enabled {
				return nil, nil, fmt.Errorf("config: system %q has unresolvable api key without anonymous access", s.ID)
			}
			continue
		}
		snap.systems[s.ID] = c
	}
	return snap, cfg, nil
}

func (m *Manager) record(status string) {
	if m.metrics != nil {
		m.metrics.ConfigReloads.WithLabelValues(status).Inc()
	}
}

func immutableEqual(a, b *Config) bool {
	return a.Runtime == b.Runtime &&
		reflect.DeepEqual(a.Server, b.Server) &&
		reflect.DeepEqual(a.Provider, b.Provider) &&
		reflect.DeepEqual(a.Store, b.Store) &&
		reflect.DeepEqual(a.Security, b.Security) &&
		reflect.DeepEqual(a.CustomPIITypes, b.CustomPIITypes) &&
		a.Default == b.Default
}

func systemsEqual(a, b map[string]contracts.Consumer) bool {
	if len(a) != len(b) {
		return false
	}
	for id, ca := range a {
		cb, ok := b[id]
		if !ok || !consumerEqual(ca, cb) {
			return false
		}
	}
	return true
}

func consumerEqual(a, b contracts.Consumer) bool {
	if a.ID != b.ID || a.Enabled != b.Enabled || a.APIKey != b.APIKey {
		return false
	}
	pa, pb := a.Policy, b.Policy
	if pa.DetectionProfile != pb.DetectionProfile || pa.Version != pb.Version || pa.Mode != pb.Mode || pa.AllowDemask != pb.AllowDemask || pa.TTL != pb.TTL {
		return false
	}
	if !stringSliceEqual(pa.DetectTypes, pb.DetectTypes) || !stringSliceEqual(pa.MaskTypes, pb.MaskTypes) {
		return false
	}
	if len(pa.Rules) != len(pb.Rules) {
		return false
	}
	for i := range pa.Rules {
		if pa.Rules[i].Type != pb.Rules[i].Type || !stringSliceEqual(pa.Rules[i].Requires, pb.Rules[i].Requires) {
			return false
		}
	}
	return true
}

func stringSliceEqual(a, b []string) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func buildConsumer(s SystemConfig, version string, ttl time.Duration) (contracts.Consumer, bool) {
	pol, err := buildPolicy(s)
	if err != nil {
		return contracts.Consumer{}, false
	}
	pol.Version = version
	pol.TTL = ttl
	enabled := s.Enabled == nil || *s.Enabled
	apiKey, hasKey, secretErr := resolveSecret(s.APIKey, s.APIKeyFile)
	if enabled && (secretErr != nil || (!hasKey && !s.AllowAnonymous)) {
		return contracts.Consumer{}, false
	}
	return contracts.Consumer{ID: s.ID, Enabled: pol.Enabled, APIKey: apiKey, Policy: pol.Contract()}, true
}

func copyConsumer(c contracts.Consumer) contracts.Consumer {
	out := c
	if c.Policy.DetectTypes != nil {
		out.Policy.DetectTypes = append([]string{}, c.Policy.DetectTypes...)
	}
	if c.Policy.MaskTypes != nil {
		out.Policy.MaskTypes = append([]string{}, c.Policy.MaskTypes...)
	}
	if c.Policy.Rules != nil {
		out.Policy.Rules = make([]contracts.PolicyRule, len(c.Policy.Rules))
		for i, r := range c.Policy.Rules {
			out.Policy.Rules[i] = r
			if r.Requires != nil {
				out.Policy.Rules[i].Requires = append([]string{}, r.Requires...)
			}
		}
	}
	return out
}

// deepCopyConfig returns a deep copy of c so that mutating the result never
// affects the original. Maps, slices and pointer fields are copied.
func deepCopyConfig(c *Config) *Config {
	if c == nil {
		return nil
	}
	out := *c
	out.CustomPIITypes = slices.Clone(c.CustomPIITypes)
	if c.Provider != nil {
		provider := *c.Provider
		provider.Models = slices.Clone(c.Provider.Models)
		out.Provider = &provider
	}
	out.Security.EncryptionKeys = maps.Clone(c.Security.EncryptionKeys)
	out.Security.EncryptionKeyFiles = maps.Clone(c.Security.EncryptionKeyFiles)
	out.Systems = slices.Clone(c.Systems)
	for i, system := range out.Systems {
		out.Systems[i] = copySystemConfig(system)
	}
	return &out
}

func copySystemConfig(s SystemConfig) SystemConfig {
	s.DetectTypes = slices.Clone(s.DetectTypes)
	s.MaskTypes = slices.Clone(s.MaskTypes)
	s.Types = slices.Clone(s.Types)
	s.Enabled = copyBool(s.Enabled)
	s.AllowDemask = copyBool(s.AllowDemask)
	s.Rules = slices.Clone(s.Rules)
	for i := range s.Rules {
		s.Rules[i].Requires = slices.Clone(s.Rules[i].Requires)
	}
	return s
}

func copyBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
