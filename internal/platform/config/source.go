package config

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

const (
	jsonParseErrorFormat = "config: parse json: %w"
	jsonFieldErrorFormat = "config: %s: %w"
)

// Document is a raw configuration payload produced by a Source.
type Document struct {
	Data     []byte
	Format   string // "yaml" or "json"
	Revision string // opaque source version; not a Prometheus label
}

// Source reads a configuration document. Read may block and must respect ctx.
type Source interface {
	Read(context.Context) (Document, error)
}

// NewFileSource returns a Source that reads the file at path on each Read.
func NewFileSource(path string) Source {
	return fileSource{path: path}
}

type fileSource struct {
	path string
}

func (f fileSource) Read(ctx context.Context) (Document, error) {
	if err := ctx.Err(); err != nil {
		return Document{}, err
	}
	data, err := os.ReadFile(f.path)
	if err != nil {
		return Document{}, fmt.Errorf("config: read %s: %w", f.path, err)
	}
	if err := ctx.Err(); err != nil {
		return Document{}, err
	}
	return Document{Data: data, Format: "yaml"}, nil
}

// parseDocument dispatches on the document format.
func parseDocument(doc Document) (*Config, error) {
	switch doc.Format {
	case "yaml":
		return parseYAML(doc.Data)
	case "json":
		return parseJSON(doc.Data)
	default:
		return nil, fmt.Errorf("config: unsupported format %q", doc.Format)
	}
}

// parseYAML decodes a YAML config starting from defaults.
func parseYAML(data []byte) (*Config, error) {
	cfg := Default()
	cfg.Version = "" // Documents must provide an explicit version.
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(cfg); err != nil {
		return nil, fmt.Errorf("config: parse yaml: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("config: expected one document")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// parseJSON decodes a strict JSON config starting from defaults. Only fields
// present in the document override the defaults.
func parseJSON(data []byte) (*Config, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, fmt.Errorf("config: empty json document")
	}
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("config: invalid utf-8 in json document")
	}
	if err := rejectDuplicateKeys(data); err != nil {
		return nil, err
	}
	cfg := Default()
	cfg.Version = "" // Documents must provide an explicit version.
	dec := json.NewDecoder(bytes.NewReader(data))
	top := map[string]json.RawMessage{}
	if err := dec.Decode(&top); err != nil {
		return nil, fmt.Errorf(jsonParseErrorFormat, err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("config: expected one json document")
	}
	if err := parseJSONConfig(top, cfg); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// rejectDuplicateKeys walks the JSON and rejects any object with a repeated
// key. It tracks whether the next string token is a key or a value so that
// identical string values (e.g. two durations both "30s") are not mistaken for
// duplicate keys.
func rejectDuplicateKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf(jsonParseErrorFormat, err)
		}
		if err := checkJSONValue(dec, tok); err != nil {
			return err
		}
	}
}

func checkJSONValue(dec *json.Decoder, tok json.Token) error {
	switch tok {
	case json.Delim('{'):
		return checkJSONObject(dec)
	case json.Delim('['):
		for dec.More() {
			value, err := dec.Token()
			if err != nil {
				return fmt.Errorf(jsonParseErrorFormat, err)
			}
			if err := checkJSONValue(dec, value); err != nil {
				return err
			}
		}
		_, err := dec.Token()
		return err
	default:
		return nil
	}
}

func checkJSONObject(dec *json.Decoder) error {
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf(jsonParseErrorFormat, err)
		}
		key, ok := tok.(string)
		if !ok {
			return fmt.Errorf("config: expected json key")
		}
		if seen[key] {
			return fmt.Errorf("config: duplicate json key %q", key)
		}
		seen[key] = true
		value, err := dec.Token()
		if err != nil {
			return fmt.Errorf(jsonParseErrorFormat, err)
		}
		if err := checkJSONValue(dec, value); err != nil {
			return err
		}
	}
	_, err := dec.Token()
	return err
}

// parseDuration parses a Go duration string.
func parseDuration(s string) (time.Duration, error) {
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("config: invalid duration")
	}
	return d, nil
}

var configJSONFields = map[string]bool{
	"version": true, "runtime": true, "server": true, "provider": true, "store": true,
	"security": true, "systems": true, "default_system": true, "custom_pii_types": true,
}

var runtimeJSONFields = map[string]bool{"mode": true}

var serverJSONFields = map[string]bool{
	"addr": true, "read_header_timeout": true, "read_timeout": true,
	"write_timeout": true, "idle_timeout": true, "max_body_bytes": true,
	"concurrency_limit": true, "request_timeout": true, "rate_limit_rps": true,
	"rate_limit_burst": true, "drain_delay": true, "shutdown_timeout": true,
}

var providerJSONFields = map[string]bool{"base_url": true, "timeout": true, "models": true}

var storeJSONFields = map[string]bool{
	"ttl": true, "cleanup_every": true, "mode": true, "redis_addr": true,
	"redis_password": true, "redis_db": true, "key_prefix": true,
	"pool_size": true, "min_idle_conns": true, "pool_timeout": true,
}

var securityJSONFields = map[string]bool{
	"log_level": true, "active_key_id": true, "encryption_keys": true,
	"encryption_key_files": true,
}

var systemJSONFields = map[string]bool{
	"allow_anonymous": true, "detect_types": true, "mask_types": true, "id": true,
	"enabled": true, "types": true, "mask_mode": true, "allow_demask": true,
	"api_key": true, "api_key_file": true, "rules": true, "detection_profile": true,
}

var ruleJSONFields = map[string]bool{"type": true, "requires": true}

var customPIITypeJSONFields = map[string]bool{"type": true, "pattern": true, "confidence": true}

func checkUnknown(m map[string]json.RawMessage, known map[string]bool, where string) error {
	for k := range m {
		if !known[k] {
			return fmt.Errorf("config: %s: unknown field %q", where, k)
		}
	}
	return nil
}

func parseJSONConfig(m map[string]json.RawMessage, cfg *Config) error {
	if err := checkUnknown(m, configJSONFields, "config"); err != nil {
		return err
	}
	return readJSONFields(m, "config",
		jsonValue("version", &cfg.Version, stringField),
		jsonSection("runtime", &cfg.Runtime, parseJSONRuntime),
		jsonSection("server", &cfg.Server, parseJSONServer),
		jsonField{"provider", func(raw json.RawMessage, _ string) error {
			section, err := objectField(raw, "provider")
			if err != nil {
				return err
			}
			if cfg.Provider == nil {
				cfg.Provider = &ProviderConfig{}
			}
			return parseJSONProvider(section, cfg.Provider)
		}},
		jsonSection("store", &cfg.Store, parseJSONStore),
		jsonSection("security", &cfg.Security, parseJSONSecurity),
		jsonValue("systems", &cfg.Systems, func(raw json.RawMessage, _ string) ([]SystemConfig, error) {
			return jsonList(raw, "systems", parseJSONSystem)
		}),
		jsonValue("default_system", &cfg.Default, stringField),
		jsonValue("custom_pii_types", &cfg.CustomPIITypes, func(raw json.RawMessage, _ string) ([]CustomPIIType, error) {
			return jsonList(raw, "custom_pii_types", parseJSONCustomPIIType)
		}),
	)
}

func parseJSONServer(m map[string]json.RawMessage, s *ServerConfig) error {
	if err := checkUnknown(m, serverJSONFields, "server"); err != nil {
		return err
	}
	return readJSONFields(m, "server",
		jsonValue("addr", &s.Addr, stringField),
		jsonValue("read_header_timeout", &s.ReadHeaderTimeout, durationField),
		jsonValue("read_timeout", &s.ReadTimeout, durationField),
		jsonValue("write_timeout", &s.WriteTimeout, durationField),
		jsonValue("idle_timeout", &s.IdleTimeout, durationField),
		jsonValue("max_body_bytes", &s.MaxBodyBytes, int64Field),
		jsonValue("concurrency_limit", &s.ConcurrencyLimit, intField),
		jsonValue("request_timeout", &s.RequestTimeout, durationField),
		jsonValue("rate_limit_rps", &s.RateLimitRPS, floatField),
		jsonValue("rate_limit_burst", &s.RateLimitBurst, intField),
		jsonValue("drain_delay", &s.DrainDelay, durationField),
		jsonValue("shutdown_timeout", &s.ShutdownTimeout, durationField),
	)
}

func parseJSONRuntime(m map[string]json.RawMessage, r *RuntimeConfig) error {
	if err := checkUnknown(m, runtimeJSONFields, "runtime"); err != nil {
		return err
	}
	if raw, ok := m["mode"]; ok {
		v, err := stringField(raw, "runtime.mode")
		if err != nil {
			return err
		}
		r.Mode = RuntimeMode(v)
	}
	return nil
}

func parseJSONProvider(m map[string]json.RawMessage, p *ProviderConfig) error {
	if err := checkUnknown(m, providerJSONFields, "provider"); err != nil {
		return err
	}
	if raw, ok := m["base_url"]; ok {
		v, err := stringField(raw, "provider.base_url")
		if err != nil {
			return err
		}
		p.BaseURL = v
	}
	if raw, ok := m["timeout"]; ok {
		v, err := durationField(raw, "provider.timeout")
		if err != nil {
			return err
		}
		p.Timeout = v
	}
	if raw, ok := m["models"]; ok {
		v, err := stringSliceField(raw, "provider.models")
		if err != nil {
			return err
		}
		p.Models = v
	}
	return nil
}

func parseJSONStore(m map[string]json.RawMessage, s *StoreConfig) error {
	if err := checkUnknown(m, storeJSONFields, "store"); err != nil {
		return err
	}
	return readJSONFields(m, "store",
		jsonValue("pool_size", &s.PoolSize, nonNullIntField),
		jsonValue("min_idle_conns", &s.MinIdleConns, nonNullIntField),
		jsonValue("pool_timeout", &s.PoolTimeout, durationField),
		jsonValue("ttl", &s.TTL, durationField),
		jsonValue("cleanup_every", &s.CleanupEvery, durationField),
		jsonValue("mode", &s.Mode, stringField),
		jsonValue("redis_addr", &s.RedisAddr, stringField),
		jsonValue("redis_password", &s.RedisPassword, stringField),
		jsonValue("redis_db", &s.RedisDB, intField),
		jsonValue("key_prefix", &s.KeyPrefix, stringField),
	)
}

func parseJSONSecurity(m map[string]json.RawMessage, s *SecurityConfig) error {
	if err := checkUnknown(m, securityJSONFields, "security"); err != nil {
		return err
	}
	if raw, ok := m["log_level"]; ok {
		v, err := stringField(raw, "security.log_level")
		if err != nil {
			return err
		}
		s.LogLevel = v
	}
	if raw, ok := m["active_key_id"]; ok {
		v, err := stringField(raw, "security.active_key_id")
		if err != nil {
			return err
		}
		s.ActiveKeyID = v
	}
	if raw, ok := m["encryption_keys"]; ok {
		v, err := stringMapField(raw, "security.encryption_keys")
		if err != nil {
			return err
		}
		s.EncryptionKeys = v
	}
	if raw, ok := m["encryption_key_files"]; ok {
		v, err := stringMapField(raw, "security.encryption_key_files")
		if err != nil {
			return err
		}
		s.EncryptionKeyFiles = v
	}
	return nil
}

func parseJSONSystem(m map[string]json.RawMessage, s *SystemConfig) error {
	if err := readJSONFields(m, "system", jsonValue("detection_profile", &s.DetectionProfile, detectionProfileField)); err != nil {
		return err
	}
	if err := checkUnknown(m, systemJSONFields, "system"); err != nil {
		return err
	}
	return readJSONFields(m, "system",
		jsonValue("allow_anonymous", &s.AllowAnonymous, boolField),
		jsonValue("detect_types", &s.DetectTypes, stringSliceField),
		jsonValue("mask_types", &s.MaskTypes, stringSliceField),
		jsonValue("id", &s.ID, stringField),
		jsonValue("enabled", &s.Enabled, boolPtrField),
		jsonValue("types", &s.Types, stringSliceField),
		jsonValue("mask_mode", &s.MaskMode, stringField),
		jsonValue("allow_demask", &s.AllowDemask, boolPtrField),
		jsonValue("api_key", &s.APIKey, stringField),
		jsonValue("api_key_file", &s.APIKeyFile, stringField),
		jsonValue("rules", &s.Rules, rulesField),
	)
}

func parseJSONCustomPIIType(m map[string]json.RawMessage, ct *CustomPIIType) error {
	if err := checkUnknown(m, customPIITypeJSONFields, "custom_pii_type"); err != nil {
		return err
	}
	if raw, ok := m["type"]; ok {
		v, err := stringField(raw, "custom_pii_type.type")
		if err != nil {
			return err
		}
		ct.Type = v
	}
	if raw, ok := m["pattern"]; ok {
		v, err := stringField(raw, "custom_pii_type.pattern")
		if err != nil {
			return err
		}
		ct.Pattern = v
	}
	if raw, ok := m["confidence"]; ok {
		v, err := stringField(raw, "custom_pii_type.confidence")
		if err != nil {
			return err
		}
		ct.Confidence = v
	}
	return nil
}

func parseJSONRule(m map[string]json.RawMessage, r *RuleCfg) error {
	if err := checkUnknown(m, ruleJSONFields, "rule"); err != nil {
		return err
	}
	if raw, ok := m["type"]; ok {
		v, err := stringField(raw, "rule.type")
		if err != nil {
			return err
		}
		r.Type = v
	}
	if raw, ok := m["requires"]; ok {
		v, err := stringSliceField(raw, "rule.requires")
		if err != nil {
			return err
		}
		r.Requires = v
	}
	return nil
}

func objectField(raw json.RawMessage, where string) (map[string]json.RawMessage, error) {
	m := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf(jsonFieldErrorFormat, where, err)
	}
	return m, nil
}

func durationField(raw json.RawMessage, where string) (time.Duration, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return 0, fmt.Errorf(jsonFieldErrorFormat, where, err)
	}
	d, err := parseDuration(s)
	if err != nil {
		return 0, fmt.Errorf(jsonFieldErrorFormat, where, err)
	}
	return d, nil
}

func stringField(raw json.RawMessage, where string) (string, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", fmt.Errorf(jsonFieldErrorFormat, where, err)
	}
	return s, nil
}

func intField(raw json.RawMessage, where string) (int, error) {
	var v int
	if err := json.Unmarshal(raw, &v); err != nil {
		return 0, fmt.Errorf(jsonFieldErrorFormat, where, err)
	}
	return v, nil
}

func int64Field(raw json.RawMessage, where string) (int64, error) {
	var v int64
	if err := json.Unmarshal(raw, &v); err != nil {
		return 0, fmt.Errorf(jsonFieldErrorFormat, where, err)
	}
	return v, nil
}

func floatField(raw json.RawMessage, where string) (float64, error) {
	var v float64
	if err := json.Unmarshal(raw, &v); err != nil {
		return 0, fmt.Errorf(jsonFieldErrorFormat, where, err)
	}
	return v, nil
}

func boolField(raw json.RawMessage, where string) (bool, error) {
	var v bool
	if err := json.Unmarshal(raw, &v); err != nil {
		return false, fmt.Errorf(jsonFieldErrorFormat, where, err)
	}
	return v, nil
}

func boolPtrField(raw json.RawMessage, where string) (*bool, error) {
	var v bool
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf(jsonFieldErrorFormat, where, err)
	}
	return &v, nil
}

func stringSliceField(raw json.RawMessage, where string) ([]string, error) {
	var v []string
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf(jsonFieldErrorFormat, where, err)
	}
	return v, nil
}

func stringMapField(raw json.RawMessage, where string) (map[string]string, error) {
	v := map[string]string{}
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf(jsonFieldErrorFormat, where, err)
	}
	return v, nil
}

// jsonField reads an optional field while preserving defaults and nil/empty values.
type jsonField struct {
	name string
	read func(json.RawMessage, string) error
}

func jsonValue[T any](name string, dest *T, parse func(json.RawMessage, string) (T, error)) jsonField {
	return jsonField{name, func(raw json.RawMessage, where string) error {
		value, err := parse(raw, where)
		if err != nil {
			return err
		}
		*dest = value
		return nil
	}}
}

func readJSONFields(m map[string]json.RawMessage, where string, fields ...jsonField) error {
	for _, field := range fields {
		raw, ok := m[field.name]
		if !ok {
			continue
		}
		if err := field.read(raw, where+"."+field.name); err != nil {
			return err
		}
	}
	return nil
}

func jsonSection[T any](name string, dest *T, parse func(map[string]json.RawMessage, *T) error) jsonField {
	return jsonField{name, func(raw json.RawMessage, _ string) error {
		section, err := objectField(raw, name)
		if err != nil {
			return err
		}
		return parse(section, dest)
	}}
}

func jsonList[T any](raw json.RawMessage, where string, parse func(map[string]json.RawMessage, *T) error) ([]T, error) {
	var items []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, fmt.Errorf(jsonFieldErrorFormat, where, err)
	}
	values := make([]T, 0, len(items))
	for i, item := range items {
		var value T
		if err := parse(item, &value); err != nil {
			return nil, fmt.Errorf("config: %s[%d]: %w", where, i, err)
		}
		values = append(values, value)
	}
	return values, nil
}

func nonNullIntField(raw json.RawMessage, where string) (int, error) {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return 0, fmt.Errorf("config: %s must be an integer", where)
	}
	return intField(raw, where)
}

func detectionProfileField(raw json.RawMessage, where string) (string, error) {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return "", fmt.Errorf("config: invalid detection_profile")
	}
	value, err := stringField(raw, where)
	if err != nil {
		return "", fmt.Errorf("config: invalid detection_profile")
	}
	return value, nil
}

func rulesField(raw json.RawMessage, where string) ([]RuleCfg, error) {
	return jsonList(raw, where, parseJSONRule)
}
