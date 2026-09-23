// Package config loads and validates service configuration.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/alfagen/pii-service/internal/contracts"
	"github.com/alfagen/pii-service/internal/pii"
	"github.com/alfagen/pii-service/internal/pii/detectors"
	"github.com/alfagen/pii-service/internal/pii/policy"
)

// RuntimeMode selects the service's production surface. process_only is the
// safe default: no provider is created and no /v1/generate route exists.
// test_generate additionally requires and wires a provider; it is a temporary
// test profile, not a production configuration.
type RuntimeMode string

const (
	RuntimeProcessOnly  RuntimeMode = "process_only"
	RuntimeTestGenerate RuntimeMode = "test_generate"
)

// RuntimeConfig is immutable for the lifetime of a Manager.
type RuntimeConfig struct {
	Mode RuntimeMode `yaml:"mode" json:"mode"`
}

// Config is the top-level service configuration.
type Config struct {
	Version  string          `yaml:"version"`
	Runtime  RuntimeConfig   `yaml:"runtime" json:"runtime"`
	Server   ServerConfig    `yaml:"server"`
	Provider *ProviderConfig `yaml:"provider,omitempty" json:"provider,omitempty"`
	Store    StoreConfig     `yaml:"store"`
	Security SecurityConfig  `yaml:"security"`
	Systems  []SystemConfig  `yaml:"systems"`
	Default  string          `yaml:"default_system"`
	// CustomPIITypes extends the detected PII categories via config alone
	// (ТЗ 4.1 extensibility requirement), without adding a Go detector file.
	CustomPIITypes []CustomPIIType `yaml:"custom_pii_types,omitempty" json:"custom_pii_types,omitempty"`
}

// CustomPIIType defines a personal-data category recognized by a single
// configured regular expression.
type CustomPIIType struct {
	Type       string `yaml:"type" json:"type"`
	Pattern    string `yaml:"pattern" json:"pattern"`
	Confidence string `yaml:"confidence" json:"confidence"`
}

// confidence maps the configured low/medium/high label to a pii.Confidence.
func (ct CustomPIIType) confidence() (pii.Confidence, error) {
	switch ct.Confidence {
	case "low":
		return pii.ConfidenceLow, nil
	case "medium":
		return pii.ConfidenceMedium, nil
	case "high":
		return pii.ConfidenceHigh, nil
	default:
		return 0, fmt.Errorf("confidence must be low, medium or high, got %q", ct.Confidence)
	}
}

// detector builds the runtime detector for this custom type, validating the
// pattern eagerly so a broken regex fails at config load, not at request time.
func (ct CustomPIIType) detector() (*detectors.PatternDetector, error) {
	confidence, err := ct.confidence()
	if err != nil {
		return nil, err
	}
	return detectors.NewPatternDetector(pii.PIIType(ct.Type), ct.Pattern, confidence)
}

// CustomDetectors builds one pii.Detector per configured custom_pii_types
// entry. Config validation already checked every pattern compiles, so an
// error here would only mean the config changed after loading.
func (c *Config) CustomDetectors() ([]pii.Detector, error) {
	out := make([]pii.Detector, 0, len(c.CustomPIITypes))
	for _, ct := range c.CustomPIITypes {
		d, err := ct.detector()
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

type ProviderConfig struct {
	BaseURL string        `yaml:"base_url"`
	Timeout time.Duration `yaml:"timeout"`
	Models  []string      `yaml:"models"`
}

// ServerConfig holds HTTP server settings.
type ServerConfig struct {
	Addr              string        `yaml:"addr"`
	ReadHeaderTimeout time.Duration `yaml:"read_header_timeout"`
	ReadTimeout       time.Duration `yaml:"read_timeout"`
	WriteTimeout      time.Duration `yaml:"write_timeout"`
	IdleTimeout       time.Duration `yaml:"idle_timeout"`
	MaxBodyBytes      int64         `yaml:"max_body_bytes"`
	ConcurrencyLimit  int           `yaml:"concurrency_limit"`
	RequestTimeout    time.Duration `yaml:"request_timeout"`
	RateLimitRPS      float64       `yaml:"rate_limit_rps"`
	RateLimitBurst    int           `yaml:"rate_limit_burst"`
	// DrainDelay is how long the server keeps failing readiness/new business
	// requests before calling http.Server.Shutdown on SIGTERM. Immutable,
	// must be positive.
	DrainDelay time.Duration `yaml:"drain_delay" json:"drain_delay"`
	// ShutdownTimeout bounds http.Server.Shutdown after DrainDelay. Immutable,
	// must be positive and not less than RequestTimeout.
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout" json:"shutdown_timeout"`
}

// StoreConfig holds store settings.
type StoreConfig struct {
	TTL           time.Duration `yaml:"ttl"`
	CleanupEvery  time.Duration `yaml:"cleanup_every"`
	Mode          string        `yaml:"mode"`
	RedisAddr     string        `yaml:"redis_addr"`
	RedisPassword string        `yaml:"redis_password"`
	RedisDB       int           `yaml:"redis_db"`
	PoolSize      int           `yaml:"pool_size"`
	MinIdleConns  int           `yaml:"min_idle_conns"`
	PoolTimeout   time.Duration `yaml:"pool_timeout"`
	KeyPrefix     string        `yaml:"key_prefix"`
}

// SecurityConfig holds security settings.
type SecurityConfig struct {
	// LogLevel is the slog level.
	LogLevel       string            `yaml:"log_level"`
	ActiveKeyID    string            `yaml:"active_key_id"`
	EncryptionKeys map[string]string `yaml:"encryption_keys"`
	// EncryptionKeyFiles maps a key ID to an absolute, read-only secret file.
	// A key ID must use exactly one of EncryptionKeys or EncryptionKeyFiles.
	EncryptionKeyFiles map[string]string `yaml:"encryption_key_files" json:"encryption_key_files"`
}

// SystemConfig configures a consumer system.
type SystemConfig struct {
	DetectionProfile string   `yaml:"detection_profile"`
	AllowAnonymous   bool     `yaml:"allow_anonymous"`
	DetectTypes      []string `yaml:"detect_types"`
	MaskTypes        []string `yaml:"mask_types"`
	ID               string   `yaml:"id"`
	Enabled          *bool    `yaml:"enabled"`
	Types            []string `yaml:"types"`
	MaskMode         string   `yaml:"mask_mode"`
	AllowDemask      *bool    `yaml:"allow_demask"`
	APIKey           string   `yaml:"api_key"`
	// APIKeyFile is an absolute, read-only secret file; mutually exclusive
	// with APIKey.
	APIKeyFile string    `yaml:"api_key_file" json:"api_key_file"`
	Rules      []RuleCfg `yaml:"rules"`
}

// RuleCfg is a conditional rule.
type RuleCfg struct {
	Type     string   `yaml:"type"`
	Requires []string `yaml:"requires"`
}

// Default returns a Config with sensible defaults. Runtime.Mode defaults to
// process_only; Provider is nil so a document that omits it stays valid in
// the default mode. A document that explicitly configures test_generate must
// also configure a full provider section.
func Default() *Config {
	return &Config{
		Version: "v1",
		Runtime: RuntimeConfig{Mode: RuntimeProcessOnly},
		Server: ServerConfig{
			Addr:              ":8080",
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxBodyBytes:      2 << 20, // 2 MiB
			ConcurrencyLimit:  256,
			RequestTimeout:    10 * time.Second,
			RateLimitRPS:      10000,
			RateLimitBurst:    1000,
			DrainDelay:        5 * time.Second,
			ShutdownTimeout:   15 * time.Second,
		},
		Store: StoreConfig{
			TTL:          24 * time.Hour,
			CleanupEvery: time.Hour,
			Mode:         "memory",
			KeyPrefix:    "alfagen:context:",
			PoolSize:     128,
			MinIdleConns: 16,
			PoolTimeout:  time.Second,
		},
		Security: SecurityConfig{
			LogLevel: "info",
		},
		Default: "benchmark",
	}
}

// Load reads and validates a YAML config file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	return parseYAML(data)
}

// Validate checks the config for errors.
func (c *Config) Validate() error {
	if c.Version == "" {
		return fmt.Errorf("config: version is required")
	}
	for _, validate := range []func() error{c.validateServer, c.validateRuntime, c.validateStore, c.validateKeyFiles, c.validateSystems} {
		if err := validate(); err != nil {
			return err
		}
	}
	return nil
}

func (c *Config) validateServer() error {
	if c.Store.CleanupEvery <= 0 || c.Server.ReadHeaderTimeout <= 0 || c.Server.ReadTimeout <= 0 || c.Server.WriteTimeout <= 0 || c.Server.IdleTimeout <= 0 {
		return fmt.Errorf("config: timeouts and cleanup interval must be positive")
	}
	if c.Server.MaxBodyBytes <= 0 {
		return fmt.Errorf("config: max_body_bytes must be positive")
	}
	if c.Server.ConcurrencyLimit <= 0 {
		return fmt.Errorf("config: concurrency_limit must be positive")
	}
	if c.Server.RequestTimeout <= 0 || c.Server.RateLimitRPS <= 0 || c.Server.RateLimitBurst <= 0 {
		return fmt.Errorf("config: request timeout and rate limits must be positive")
	}
	if c.Server.DrainDelay <= 0 || c.Server.ShutdownTimeout <= 0 {
		return fmt.Errorf("config: drain_delay and shutdown_timeout must be positive")
	}
	if c.Server.ShutdownTimeout < c.Server.RequestTimeout {
		return fmt.Errorf("config: shutdown_timeout must not be less than request_timeout")
	}

	return nil
}

func (c *Config) validateRuntime() error {
	if c.Runtime.Mode == "" {
		c.Runtime.Mode = RuntimeProcessOnly
	}
	switch c.Runtime.Mode {
	case RuntimeProcessOnly:
		if c.Provider != nil {
			return fmt.Errorf("config: provider_forbidden")
		}
	case RuntimeTestGenerate:
		if c.Provider == nil || c.Provider.BaseURL == "" || c.Provider.Timeout <= 0 || len(c.Provider.Models) == 0 {
			return fmt.Errorf("config: provider base_url, positive timeout and models are required")
		}
	default:
		return fmt.Errorf("config: runtime.mode must be process_only or test_generate")
	}

	return nil
}

func (c *Config) validateStore() error {
	if c.Store.TTL <= 0 {
		return fmt.Errorf("config: store ttl must be positive")
	}
	if c.Store.Mode == "" {
		c.Store.Mode = "memory"
	}
	if c.Store.Mode != "memory" && c.Store.Mode != "redis" {
		return fmt.Errorf("config: store mode must be memory or redis")
	}
	if c.Store.Mode == "redis" {
		return c.validateRedis()
	}

	return nil
}

func (c *Config) validateKeyFiles() error {
	for id := range c.Security.EncryptionKeyFiles {
		if _, ok := c.Security.EncryptionKeys[id]; ok {
			return fmt.Errorf("config: security encryption key %q has conflicting literal and file", id)
		}
		if !filepath.IsAbs(c.Security.EncryptionKeyFiles[id]) {
			return fmt.Errorf("config: security encryption key %q file must be an absolute path", id)
		}
	}

	return nil
}

func (c *Config) validateSystems() error {
	if c.Default == "" {
		return fmt.Errorf("config: default_system is required")
	}
	if err := c.validateCustomTypes(); err != nil {
		return err
	}
	// Computed once and reused for every per-field/per-rule membership check
	// below and for the final policy-contract check, instead of each system
	// re-scanning pii.AllTypes plus c.CustomPIITypes on every call.
	validTypes := c.allValidTypes()
	seen := map[string]bool{}
	for _, s := range c.Systems {
		if s.ID == "" {
			return fmt.Errorf("config: system with empty id")
		}
		if seen[s.ID] {
			return fmt.Errorf("config: duplicate system id %q", s.ID)
		}
		seen[s.ID] = true
		if err := validateSystem(s, validTypes); err != nil {
			return err
		}
		pol, err := c.PolicyFor(s.ID)
		if err != nil {
			return err
		}
		if err := policy.ValidateContract(pol.Contract(), validTypes); err != nil {
			return fmt.Errorf("config: invalid policy for system %q", s.ID)
		}
	}
	if !seen[c.Default] {
		return fmt.Errorf("config: default_system %q not found in systems", c.Default)
	}

	return nil
}

func validateSystem(s SystemConfig, validTypes map[string]bool) error {
	if s.APIKey != "" && s.APIKeyFile != "" {
		return fmt.Errorf("config: system %q api_key and api_key_file conflict", s.ID)
	}
	if s.APIKeyFile != "" && !filepath.IsAbs(s.APIKeyFile) {
		return fmt.Errorf("config: system %q api_key_file must be an absolute path", s.ID)
	}
	if s.MaskMode != "" && s.MaskMode != string(policy.MaskModeFormat) && s.MaskMode != string(policy.MaskModeToken) {
		return fmt.Errorf("config: system %q unknown mask_mode %q", s.ID, s.MaskMode)
	}

	return validateSystemTypes(s, validTypes)
}

func validateSystemTypes(s SystemConfig, validTypes map[string]bool) error {
	for _, t := range append(append(append([]string{}, s.Types...), s.DetectTypes...), s.MaskTypes...) {
		if !validTypes[t] {
			return fmt.Errorf("config: system %q unknown type %q", s.ID, t)
		}
	}
	for _, r := range s.Rules {
		if !validTypes[r.Type] {
			return fmt.Errorf("config: system %q rule unknown type %q", s.ID, r.Type)
		}
		for _, req := range r.Requires {
			if !validTypes[req] {
				return fmt.Errorf("config: system %q rule requires unknown type %q", s.ID, req)
			}
		}
	}
	return nil
}

// PolicyFor returns the policy for the given system ID, or nil if unknown.
func (c *Config) PolicyFor(systemID string) (*policy.Policy, error) {
	for _, s := range c.Systems {
		if s.ID == systemID {
			pol, err := buildPolicy(s)
			if err == nil {
				pol.Version = c.Version
				pol.TTL = c.Store.TTL
			}
			return pol, err
		}
	}
	return nil, fmt.Errorf("config: unknown system %q", systemID)
}

// ResolveSystem implements contracts.SystemResolver without importing the HTTP
// package. It returns a fresh immutable policy snapshot for the request.
func (c *Config) ResolveSystem(systemID string) (contracts.Consumer, bool) {
	for _, system := range c.Systems {
		if system.ID != systemID {
			continue
		}
		pol, err := c.PolicyFor(systemID)
		if err != nil {
			return contracts.Consumer{}, false
		}
		apiKey, hasKey, err := resolveSecret(system.APIKey, system.APIKeyFile)
		if err != nil || (!hasKey && !system.AllowAnonymous) {
			return contracts.Consumer{}, false
		}
		return contracts.Consumer{ID: systemID, Enabled: pol.Enabled, APIKey: apiKey, Policy: pol.Contract()}, true
	}
	return contracts.Consumer{}, false
}

// ResolvedEncryptionKeys returns secret values after environment/file
// resolution. Callers must never log the returned map. An error means a
// configured key (literal env reference or secret file) could not be safely
// resolved; the error never contains the path or the secret value.
func (c *Config) ResolvedEncryptionKeys() (map[string]string, error) {
	resolved := make(map[string]string, len(c.Security.EncryptionKeys)+len(c.Security.EncryptionKeyFiles))
	for id, value := range c.Security.EncryptionKeys {
		resolved[id] = expandEnvironment(value)
	}
	for id, path := range c.Security.EncryptionKeyFiles {
		value, err := readSecretFile(path)
		if err != nil {
			return nil, err
		}
		resolved[id] = value
	}
	return resolved, nil
}

// encryptionKeyAvailable reports whether id resolves to a non-empty value via
// either the literal (env-expanded) map or a secret file. An error means the
// key is configured but the secret file could not be safely resolved.
func (c *Config) encryptionKeyAvailable(id string) (bool, error) {
	if literal, ok := c.Security.EncryptionKeys[id]; ok {
		return expandEnvironment(literal) != "", nil
	}
	if path, ok := c.Security.EncryptionKeyFiles[id]; ok {
		if _, err := readSecretFile(path); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

func expandEnvironment(value string) string {
	if len(value) > 3 && value[0:2] == "${" && value[len(value)-1] == '}' {
		return os.Getenv(value[2 : len(value)-1])
	}
	return value
}

// errSecretUnresolved marks a literal secret reference (e.g. "${ENV}") that
// expanded to an empty value. It never contains the reference or value.
var errSecretUnresolved = errors.New("config: secret is unresolved")

// errSecretFileInvalid marks a secret file that is missing, not an absolute
// path, not a regular non-symlink file, unreadable, empty, or multi-line. It
// never contains the path or file contents.
var errSecretFileInvalid = errors.New("config: secret file is invalid")

// resolveSecret resolves a literal/file secret pair. ok=false with a nil
// error means neither literal nor file was configured, so callers may apply
// their own anonymous-access policy. A non-nil error means a configured
// secret (literal env reference or file) could not be safely resolved;
// callers must not silently fall back to anonymous/default access in that
// case.
func resolveSecret(literal, file string) (value string, ok bool, err error) {
	if literal != "" {
		v := expandEnvironment(literal)
		if v == "" {
			return "", false, errSecretUnresolved
		}
		return v, true, nil
	}
	if file != "" {
		v, err := readSecretFile(file)
		if err != nil {
			return "", false, err
		}
		return v, true, nil
	}
	return "", false, nil
}

// readSecretFile reads a production secret from an absolute, read-only,
// regular, non-symlink file. Exactly one trailing newline is accepted; the
// content must otherwise be a single non-empty line. The path and file
// contents are never included in the returned error.
func readSecretFile(path string) (string, error) {
	if path == "" || !filepath.IsAbs(path) {
		return "", errSecretFileInvalid
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", errSecretFileInvalid
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", errSecretFileInvalid
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", errSecretFileInvalid
	}
	content := strings.TrimSuffix(string(data), "\n")
	if content == "" || strings.ContainsRune(content, '\n') {
		return "", errSecretFileInvalid
	}
	return content, nil
}

func buildPolicy(s SystemConfig) (*policy.Policy, error) {
	p := policy.New(s.ID)
	if s.DetectionProfile != "" {
		p.DetectionProfile = s.DetectionProfile
	}
	if s.DetectTypes != nil {
		p.DetectTypes = append([]string{}, s.DetectTypes...)
	}
	if s.Enabled != nil {
		p.Enabled = *s.Enabled
	}
	if s.AllowDemask != nil {
		p.AllowDemask = *s.AllowDemask
	}
	if s.MaskMode != "" {
		p.MaskMode = policy.MaskMode(s.MaskMode)
	}
	if len(s.Types) > 0 {
		p.Types = map[pii.PIIType]bool{}
		for _, t := range s.Types {
			p.Types[pii.PIIType(t)] = true
		}
	}
	if s.MaskTypes != nil {
		p.Types = map[pii.PIIType]bool{}
		for _, typ := range s.MaskTypes {
			p.Types[pii.PIIType(typ)] = true
		}
	}
	for _, r := range s.Rules {
		rule := policy.Rule{Type: pii.PIIType(r.Type)}
		for _, req := range r.Requires {
			rule.Requires = append(rule.Requires, pii.PIIType(req))
		}
		p.Rules = append(p.Rules, rule)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return p, nil
}

// validCustomTypeName restricts custom_pii_types names to snake_case
// identifiers: lowercase ASCII letters, digits and underscores, starting with
// a letter. This is not cosmetic: tokens.token (internal/pii/engine) embeds
// strings.ToUpper(type) verbatim inside a `<TYPE_HEX_N>` marker that
// markerPattern must later parse back out to demask. Any other character
// (hyphen, space, punctuation, non-ASCII) would silently break that round
// trip for `mask_mode: token`, leaving the marker unresolved in the output.
func validCustomTypeName(t string) bool {
	if t == "" || t[0] < 'a' || t[0] > 'z' {
		return false
	}
	for i := 1; i < len(t); i++ {
		c := t[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

func validBuiltinType(t string) bool {
	for _, at := range pii.AllTypes {
		if string(at) == t {
			return true
		}
	}
	return false
}

func (c *Config) validateRedis() error {
	if c.Store.PoolSize < 0 || c.Store.MinIdleConns < 0 || c.Store.PoolTimeout < 0 || (c.Store.PoolSize > 0 && c.Store.MinIdleConns > c.Store.PoolSize) {
		return fmt.Errorf("config: invalid redis pool settings")
	}
	if c.Store.RedisAddr == "" || c.Security.ActiveKeyID == "" {
		return fmt.Errorf("config: redis address and active encryption key are required")
	}
	available, err := c.encryptionKeyAvailable(c.Security.ActiveKeyID)
	if err != nil {
		return fmt.Errorf("config: active encryption key is unavailable")
	}
	if !available {
		return fmt.Errorf("config: active encryption key is unavailable")
	}
	return nil
}

func (c *Config) validateCustomTypes() error {
	seenCustomTypes := map[string]bool{}
	for i, ct := range c.CustomPIITypes {
		if ct.Type == "" {
			return fmt.Errorf("config: custom_pii_types[%d].type is required", i)
		}
		if !validCustomTypeName(ct.Type) {
			return fmt.Errorf("config: custom_pii_types[%d].type %q must be snake_case: lowercase letters, digits and underscores, starting with a letter", i, ct.Type)
		}
		if validBuiltinType(ct.Type) {
			return fmt.Errorf("config: custom_pii_types[%d] type %q collides with a built-in type", i, ct.Type)
		}
		if seenCustomTypes[ct.Type] {
			return fmt.Errorf("config: duplicate custom_pii_types type %q", ct.Type)
		}
		seenCustomTypes[ct.Type] = true
		if _, err := ct.detector(); err != nil {
			return fmt.Errorf("config: invalid custom_pii_types[%d]: %w", i, err)
		}
	}
	return nil
}

func (c *Config) allValidTypes() map[string]bool {
	types := policy.BuiltinTypes()
	for _, ct := range c.CustomPIITypes {
		types[ct.Type] = true
	}
	return types
}
