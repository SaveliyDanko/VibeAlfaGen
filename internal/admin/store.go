// Package admin implements the private AlfaGen operator control plane.
package admin

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/alfagen/pii-service/internal/mock/client"
	"github.com/alfagen/pii-service/internal/pii/policy"
	"github.com/alfagen/pii-service/internal/platform/config"
	"gopkg.in/yaml.v3"
)

const maxManagedDocumentBytes = 4 << 20

var managedIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

type StoreOptions struct {
	BackendConfigPath string
	MockConfigPath    string
	APIKeyDir         string
	RuntimeAPIKeyDir  string
	MTLSDir           string
	StatusPath        string
	ReportPath        string
	AuditPath         string
	CertificateTTL    time.Duration
	CRLLifetime       time.Duration
}

type Store struct {
	opts StoreOptions
	mu   sync.Mutex
}

type SystemView struct {
	ID               string   `json:"id"`
	Enabled          bool     `json:"enabled"`
	Default          bool     `json:"default"`
	AccessMode       string   `json:"access_mode"`
	HasAPIKey        bool     `json:"has_api_key"`
	APIKeyFile       string   `json:"api_key_file,omitempty"`
	AllowDemask      bool     `json:"allow_demask"`
	MaskMode         string   `json:"mask_mode"`
	DetectionProfile string   `json:"detection_profile"`
	DetectTypes      []string `json:"detect_types"`
	MaskTypes        []string `json:"mask_types"`
}

type AccessSnapshot struct {
	Revision       string       `json:"revision"`
	Version        string       `json:"version"`
	Systems        []SystemView `json:"systems"`
	AvailableTypes []string     `json:"available_types"`
}

type SystemInput struct {
	Revision         string   `json:"revision"`
	Enabled          bool     `json:"enabled"`
	AccessMode       string   `json:"access_mode"`
	GenerateAPIKey   bool     `json:"generate_api_key"`
	AllowDemask      bool     `json:"allow_demask"`
	MaskMode         string   `json:"mask_mode"`
	DetectionProfile string   `json:"detection_profile"`
	DetectTypes      []string `json:"detect_types"`
	MaskTypes        []string `json:"mask_types"`
}

type MutationResult struct {
	Revision string `json:"revision"`
	Version  string `json:"version"`
	APIKey   string `json:"api_key,omitempty"`
	Message  string `json:"message,omitempty"`
}

type TestSnapshot struct {
	Status   client.RunStatus `json:"status"`
	Revision string           `json:"revision"`
	Config   client.DocConfig `json:"config"`
}

type TestInput struct {
	Revision string           `json:"revision"`
	Config   client.DocConfig `json:"config"`
}

type AuditEntry struct {
	Time     time.Time `json:"time"`
	Action   string    `json:"action"`
	Resource string    `json:"resource"`
	Result   string    `json:"result"`
}

func NewStore(opts StoreOptions) (*Store, error) {
	if opts.BackendConfigPath == "" || opts.MockConfigPath == "" || opts.APIKeyDir == "" || opts.MTLSDir == "" {
		return nil, errors.New("admin: backend config, mock config, API key dir and mTLS dir are required")
	}
	if opts.RuntimeAPIKeyDir == "" {
		opts.RuntimeAPIKeyDir = opts.APIKeyDir
	}
	if !filepath.IsAbs(opts.RuntimeAPIKeyDir) {
		return nil, errors.New("admin: runtime API key directory must be absolute")
	}
	if opts.CertificateTTL <= 0 {
		opts.CertificateTTL = 365 * 24 * time.Hour
	}
	if opts.AuditPath == "" {
		opts.AuditPath = filepath.Join(filepath.Dir(opts.BackendConfigPath), "audit.jsonl")
	}
	return &Store{opts: opts}, nil
}

func (s *Store) AccessSnapshot() (AccessSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg, raw, err := s.loadBackendLocked()
	if err != nil {
		return AccessSnapshot{}, err
	}
	return accessSnapshot(cfg, revision(raw)), nil
}

func accessSnapshot(cfg *config.Config, rev string) AccessSnapshot {
	views := make([]SystemView, 0, len(cfg.Systems))
	for _, system := range cfg.Systems {
		enabled := system.Enabled == nil || *system.Enabled
		allowDemask := system.AllowDemask == nil || *system.AllowDemask
		mode := "api_key"
		if system.AllowAnonymous {
			mode = "anonymous"
		}

		maskMode := system.MaskMode
		if maskMode == "" {
			maskMode = "format"
		}
		keyFile := ""
		if system.APIKeyFile != "" {
			keyFile = filepath.Base(system.APIKeyFile)
		}
		views = append(views, SystemView{
			ID: system.ID, Enabled: enabled, Default: system.ID == cfg.Default,
			AccessMode: mode, HasAPIKey: system.APIKey != "" || system.APIKeyFile != "",
			APIKeyFile: keyFile, AllowDemask: allowDemask, MaskMode: maskMode,
			DetectionProfile: system.DetectionProfile,
			DetectTypes:      slices.Clone(system.DetectTypes),
			MaskTypes:        effectiveMaskTypes(system),
		})
	}
	sort.Slice(views, func(i, j int) bool { return views[i].ID < views[j].ID })
	return AccessSnapshot{Revision: rev, Version: cfg.Version, Systems: views, AvailableTypes: availableTypes(cfg)}
}

func availableTypes(cfg *config.Config) []string {
	known := policy.BuiltinTypes()
	for _, custom := range cfg.CustomPIITypes {
		known[custom.Type] = true
	}
	types := make([]string, 0, len(known))
	for typ := range known {
		types = append(types, typ)
	}
	sort.Strings(types)
	return types
}

func (s *Store) UpsertSystem(id string, input SystemInput) (MutationResult, error) {
	if !managedIDPattern.MatchString(id) {
		return MutationResult{}, errors.New("admin: invalid system id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg, raw, err := s.loadBackendLocked()
	if err != nil {
		return MutationResult{}, err
	}
	if err := matchRevision(input.Revision, raw); err != nil {
		return MutationResult{}, err
	}

	index := systemIndex(cfg, id)
	if index < 0 {
		cfg.Systems = append(cfg.Systems, config.SystemConfig{ID: id})
		index = len(cfg.Systems) - 1
	}

	system := cfg.Systems[index]
	system.ID = id
	system.Enabled = boolPointer(input.Enabled)
	system.AllowDemask = boolPointer(input.AllowDemask)
	system.MaskMode = input.MaskMode
	if system.MaskMode == "" {
		system.MaskMode = "format"
	}
	system.DetectionProfile = input.DetectionProfile
	system.DetectTypes = copyStrings(input.DetectTypes)
	system.MaskTypes = copyStrings(input.MaskTypes)
	system.Types = nil // The explicit editor replaces the legacy fallback.

	generatedKey, generatedPath, generatedName, err := s.configureAccess(&system, input)
	if err != nil {
		return MutationResult{}, err
	}

	cfg.Systems[index] = system
	newRaw, err := s.commitBackend(cfg, raw)
	if err != nil {
		if generatedPath != "" {
			_ = os.Remove(generatedPath)
		}
		return MutationResult{}, err
	}

	message := ""
	if generatedName != "" {
		if err := s.syncMockAPIKeyLocked(id, filepath.Join(s.opts.RuntimeAPIKeyDir, generatedName)); err != nil {
			message = "Access policy was updated, but the mock-client credential was not synchronized: " + err.Error()
		}
	}
	_ = s.appendAuditLocked("system.upsert", id, "success")
	return MutationResult{Revision: revision(newRaw), Version: cfg.Version, APIKey: generatedKey, Message: message}, nil
}

func (s *Store) RotateAPIKey(id, expectedRevision string) (MutationResult, error) {
	if !managedIDPattern.MatchString(id) {
		return MutationResult{}, errors.New("admin: invalid system id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg, raw, err := s.loadBackendLocked()
	if err != nil {
		return MutationResult{}, err
	}
	if err := matchRevision(expectedRevision, raw); err != nil {
		return MutationResult{}, err
	}
	index := -1
	for i := range cfg.Systems {
		if cfg.Systems[i].ID == id {
			index = i
			break
		}
	}
	if index < 0 {
		return MutationResult{}, os.ErrNotExist
	}
	key, path, name, err := s.writeAPIKeyLocked(id)
	if err != nil {
		return MutationResult{}, err
	}
	cfg.Systems[index].AllowAnonymous = false
	cfg.Systems[index].APIKey = ""
	cfg.Systems[index].APIKeyFile = filepath.Join(s.opts.RuntimeAPIKeyDir, name)
	cfg.Version, err = nextVersion()
	if err != nil {
		_ = os.Remove(path)
		return MutationResult{}, err
	}
	newRaw, err := marshalBackend(cfg, raw)
	if err == nil {
		err = validateBackendDocument(newRaw)
	}
	if err == nil {
		err = atomicWrite(s.opts.BackendConfigPath, newRaw, 0o600)
	}
	if err != nil {
		_ = os.Remove(path)
		return MutationResult{}, err
	}
	message := ""
	if err := s.syncMockAPIKeyLocked(id, filepath.Join(s.opts.RuntimeAPIKeyDir, name)); err != nil {
		message = "API key was rotated, but the mock-client credential was not synchronized: " + err.Error()
	}
	_ = s.appendAuditLocked("api-key.rotate", id, "success")
	return MutationResult{Revision: revision(newRaw), Version: cfg.Version, APIKey: key, Message: message}, nil
}

func (s *Store) DeleteSystem(id, expectedRevision string) (MutationResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg, raw, err := s.loadBackendLocked()
	if err != nil {
		return MutationResult{}, err
	}
	if err := matchRevision(expectedRevision, raw); err != nil {
		return MutationResult{}, err
	}
	if id == cfg.Default {
		return MutationResult{}, errors.New("admin: default system cannot be deleted")
	}
	filtered := cfg.Systems[:0]
	found := false
	for _, system := range cfg.Systems {
		if system.ID == id {
			found = true
			continue
		}
		filtered = append(filtered, system)
	}
	if !found {
		return MutationResult{}, os.ErrNotExist
	}
	cfg.Systems = filtered
	cfg.Version, err = nextVersion()
	if err != nil {
		return MutationResult{}, err
	}
	newRaw, err := marshalBackend(cfg, raw)
	if err == nil {
		err = validateBackendDocument(newRaw)
	}
	if err == nil {
		err = atomicWrite(s.opts.BackendConfigPath, newRaw, 0o600)
	}
	if err != nil {
		return MutationResult{}, err
	}
	_ = s.appendAuditLocked("system.delete", id, "success")
	return MutationResult{Revision: revision(newRaw), Version: cfg.Version}, nil
}

func (s *Store) TestSnapshot() (TestSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg, raw, err := s.loadMockLocked()
	if err != nil {
		return TestSnapshot{}, err
	}
	return TestSnapshot{Revision: revision(raw), Config: cfg, Status: s.testStatus(cfg)}, nil
}

func (s *Store) UpdateTest(input TestInput) (MutationResult, error) {
	return s.changeTest(input.Revision, &input.Config, nil)
}

// StartTest saves the displayed settings and issues a fresh run in one revision-
// protected write. A failed validation cannot leave a partially started run.
func (s *Store) StartTest(expectedRevision string, cfg *client.DocConfig) (MutationResult, error) {
	return s.changeTest(expectedRevision, cfg, boolPointer(true))
}

func (s *Store) SetTestEnabled(expectedRevision string, enabled bool) (MutationResult, error) {
	return s.changeTest(expectedRevision, nil, &enabled)
}

// Admin-managed tests use one fixed operation limit; standalone CLI remains configurable.
const adminTestParallelism = 512

var ErrTestActive = errors.New("admin: test already active; stop it before starting another run")

func (s *Store) changeTest(expected string, input *client.DocConfig, enabled *bool) (MutationResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, raw, err := s.loadMockLocked()
	if err != nil {
		return MutationResult{}, err
	}
	if err := matchRevision(expected, raw); err != nil {
		return MutationResult{}, err
	}
	cfg := current
	if input != nil {
		cfg = *input
		cfg.Enabled, cfg.RunID = current.Enabled, current.RunID
		// Credential paths are resolved by the server, never copied from a stale form.
		cfg.APIKeyEnv, cfg.APIKeyFile = current.APIKeyEnv, current.APIKeyFile
	}
	// Normalize saved/start settings even for old clients or a start without a body.
	// Stop preserves the running test's parameters and only changes its lifecycle.
	if enabled == nil || *enabled {
		cfg.Concurrency, cfg.MaxInFlight = adminTestParallelism, adminTestParallelism
	}
	cfg.Version, err = nextVersion()
	if err != nil {
		return MutationResult{}, err
	}
	if err := cfg.Validate(); err != nil {
		return MutationResult{}, err
	}
	action, createdKeyPath, err := s.prepareTest(&cfg, current, enabled)
	if err != nil {
		return MutationResult{}, err
	}
	newRaw, err := json.MarshalIndent(cfg, "", "  ")
	if err == nil {
		err = atomicWrite(s.opts.MockConfigPath, append(newRaw, '\n'), 0o600)
	}
	if err != nil {
		if createdKeyPath != "" {
			_ = os.Remove(createdKeyPath)
		}
		return MutationResult{}, err
	}
	_ = s.appendAuditLocked(action, cfg.Scenario, "success")
	return MutationResult{Revision: revision(append(newRaw, '\n')), Version: cfg.Version}, nil
}

func (s *Store) prepareTest(cfg *client.DocConfig, current client.DocConfig, enabled *bool) (string, string, error) {
	if enabled != nil && !*enabled {
		cfg.Enabled = false
		return "test.stop", "", nil // Stopping must also work after the system is disabled/deleted.
	}
	if enabled != nil {
		status := s.testStatus(current)
		if status.State == "running" || status.State == "pending" || status.State == "stopping" {
			return "", "", ErrTestActive
		}
		var err error
		cfg.Enabled = true
		cfg.RunID, err = nextVersion()
		if err != nil {
			return "", "", err
		}
	}
	created, err := s.resolveTestSystem(cfg, current)
	action := "test.configure"
	if enabled != nil {
		action = "test.start"
	}
	return action, created, err
}

func (s *Store) resolveTestSystem(cfg *client.DocConfig, previous client.DocConfig) (string, error) {
	backend, _, err := s.loadBackendLocked()
	if err != nil {
		return "", err
	}
	index := systemIndex(backend, cfg.SystemID)
	if index < 0 {
		return "", errors.New("admin: invalid test system: select a registered system")
	}
	system := backend.Systems[index]
	if system.Enabled != nil && !*system.Enabled {
		return "", errors.New("admin: invalid test system: system is disabled")
	}
	switch {
	case system.AllowAnonymous:
		cfg.APIKeyEnv, cfg.APIKeyFile = "", ""
	case system.APIKeyFile != "":
		if filepath.Dir(system.APIKeyFile) != filepath.Clean(s.opts.RuntimeAPIKeyDir) {
			return s.copyTestAPIKey(cfg, previous, system.APIKeyFile)
		}
		cfg.APIKeyEnv, cfg.APIKeyFile = "", system.APIKeyFile
	case cfg.SystemID != previous.SystemID || (cfg.APIKeyEnv == "" && cfg.APIKeyFile == ""):
		return "", errors.New("admin: invalid test credentials: rotate this system's API key before selecting it")
	}
	return "", nil
}

// Backend-only mounts are not a portable path for mock-client. Copy the same
// credential into the shared managed directory; do not rotate the backend key
// or fall back to an unrelated bootstrap environment secret.
func (s *Store) copyTestAPIKey(cfg *client.DocConfig, previous client.DocConfig, source string) (string, error) {
	file, err := os.Open(source)
	if err != nil {
		return "", errors.New("admin: invalid test credentials: backend API key file unavailable")
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(raw) > 4096 || len(strings.TrimSpace(string(raw))) == 0 {
		return "", errors.New("admin: invalid test credentials: backend API key file must contain 1 to 4096 bytes")
	}
	key := []byte(strings.TrimSpace(string(raw)))
	if previous.SystemID == cfg.SystemID && filepath.Dir(previous.APIKeyFile) == filepath.Clean(s.opts.RuntimeAPIKeyDir) {
		local := filepath.Join(s.opts.APIKeyDir, filepath.Base(previous.APIKeyFile))
		if old, err := os.ReadFile(local); err == nil && bytes.Equal(old, key) {
			cfg.APIKeyEnv, cfg.APIKeyFile = "", previous.APIKeyFile
			return "", nil
		}
	}
	path, name, err := s.writeAPIKeyFileLocked(cfg.SystemID+"-load", key)
	if err != nil {
		return "", err
	}
	cfg.APIKeyEnv, cfg.APIKeyFile = "", filepath.Join(s.opts.RuntimeAPIKeyDir, name)
	return path, nil
}

func (s *Store) ReadReport() (json.RawMessage, error) {
	if s.opts.ReportPath == "" {
		return nil, os.ErrNotExist
	}
	raw, err := readLimited(s.opts.ReportPath)
	if err != nil {
		return nil, err
	}
	if !json.Valid(raw) {
		return nil, errors.New("admin: report is not valid JSON")
	}
	return json.RawMessage(raw), nil
}

func (s *Store) Audit(limit int) ([]AuditEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	raw, err := readLimited(s.opts.AuditPath)
	if errors.Is(err, os.ErrNotExist) {
		return []AuditEntry{}, nil
	}
	if err != nil {
		return nil, err
	}
	lines := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
	start := 0
	if len(lines) > limit {
		start = len(lines) - limit
	}
	entries := make([]AuditEntry, 0, len(lines)-start)
	for _, line := range lines[start:] {
		if len(line) == 0 {
			continue
		}
		var entry AuditEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			return nil, errors.New("admin: invalid audit log")
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func (s *Store) loadBackendLocked() (*config.Config, []byte, error) {
	raw, err := readLimited(s.opts.BackendConfigPath)
	if err != nil {
		return nil, nil, err
	}
	cfg, err := loadBackendDocument(raw)
	if err != nil {
		return nil, nil, err
	}
	return cfg, raw, nil
}

func validateBackendDocument(raw []byte) error {
	_, err := loadBackendDocument(raw)
	return err
}

func loadBackendDocument(raw []byte) (*config.Config, error) {
	tmp, err := os.CreateTemp("", "alfagen-admin-config-*.yaml")
	if err != nil {
		return nil, err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return nil, err
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	return config.Load(name)
}

func (s *Store) loadMockLocked() (client.DocConfig, []byte, error) {
	raw, err := readLimited(s.opts.MockConfigPath)
	if err != nil {
		return client.DocConfig{}, nil, err
	}
	var cfg client.DocConfig
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return client.DocConfig{}, nil, err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return client.DocConfig{}, nil, errors.New("admin: expected one mock config document")
	}
	if err := cfg.Validate(); err != nil {
		return client.DocConfig{}, nil, err
	}
	return cfg, raw, nil
}

func (s *Store) syncMockAPIKeyLocked(systemID, runtimePath string) error {
	cfg, _, err := s.loadMockLocked()
	if err != nil {
		return err
	}
	if cfg.SystemID != systemID {
		return nil
	}
	cfg.APIKeyEnv = ""
	cfg.APIKeyFile = runtimePath
	cfg.Version, err = nextVersion()
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return atomicWrite(s.opts.MockConfigPath, raw, 0o600)
}

func (s *Store) writeAPIKeyLocked(id string) (string, string, string, error) {
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", "", "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(value[:])
	path, name, err := s.writeAPIKeyFileLocked(id, []byte(encoded+"\n"))
	return encoded, path, name, err
}

func (s *Store) writeAPIKeyFileLocked(id string, value []byte) (string, string, error) {
	if err := os.MkdirAll(s.opts.APIKeyDir, 0o700); err != nil {
		return "", "", err
	}
	var suffix [6]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "", "", err
	}
	name := fmt.Sprintf("%s-%x.key", id, suffix)
	path := filepath.Join(s.opts.APIKeyDir, name)
	if err := atomicWrite(path, value, 0o600); err != nil {
		return "", "", err
	}
	return path, name, nil
}

func (s *Store) appendAuditLocked(action, resource, result string) error {
	entry, err := json.Marshal(AuditEntry{Time: time.Now().UTC(), Action: action, Resource: resource, Result: result})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.opts.AuditPath), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(s.opts.AuditPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(append(entry, '\n')); err != nil {
		return err
	}
	return file.Sync()
}

var ErrRevisionConflict = errors.New("admin: configuration changed; reload before saving")

func matchRevision(expected string, raw []byte) error {
	if expected == "" || expected != revision(raw) {
		return ErrRevisionConflict
	}
	return nil
}

func revision(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func nextVersion() (string, error) {
	var suffix [4]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf("admin-%s-%x", time.Now().UTC().Format("20060102T150405.000000000Z"), suffix), nil
}

func readLimited(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxManagedDocumentBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxManagedDocumentBytes {
		return nil, errors.New("admin: document is too large")
	}
	return raw, nil
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	if len(data) > maxManagedDocumentBytes {
		return errors.New("admin: document is too large")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".admin-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := inheritDirectoryOwner(tmp, dir); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func boolPointer(value bool) *bool { return &value }

func copyStrings(values []string) []string {
	if values == nil {
		return nil
	}
	return slices.Clone(values)
}

func systemIndex(cfg *config.Config, id string) int {
	for i, system := range cfg.Systems {
		if system.ID == id {
			return i
		}
	}
	return -1
}

func (s *Store) configureAccess(system *config.SystemConfig, input SystemInput) (string, string, string, error) {
	var err error
	var generatedKey, generatedPath, generatedName string
	switch input.AccessMode {
	case "anonymous":
		system.AllowAnonymous = true
		system.APIKey = ""
		system.APIKeyFile = ""
	case "disabled":
		system.Enabled = boolPointer(false)
	case "api_key":
		system.AllowAnonymous = false
		if input.GenerateAPIKey {
			generatedKey, generatedPath, generatedName, err = s.writeAPIKeyLocked(system.ID)
			if err != nil {
				return "", "", "", err
			}
			system.APIKey = ""
			system.APIKeyFile = filepath.Join(s.opts.RuntimeAPIKeyDir, generatedName)
		}
		if system.APIKey == "" && system.APIKeyFile == "" && input.Enabled {
			return "", "", "", errors.New("admin: enabled API-key system requires key generation")
		}
	default:
		return "", "", "", errors.New("admin: access_mode must be api_key, anonymous or disabled")
	}

	return generatedKey, generatedPath, generatedName, nil
}

func effectiveMaskTypes(system config.SystemConfig) []string {
	if system.MaskTypes == nil && len(system.Types) > 0 {
		return slices.Clone(system.Types)
	}
	return slices.Clone(system.MaskTypes)
}

// yaml.v3 encodes nil slices as []; the policy contract distinguishes all
// (null) from none ([]). Preserve that distinction for every system on edits.
func marshalBackend(cfg *config.Config, original []byte) ([]byte, error) {
	// Leave immutable sections exactly as supplied. Re-encoding defaults would
	// turn nil maps/slices into empty ones and make Manager reject the reload.
	var doc, systems yaml.Node
	if err := yaml.Unmarshal(original, &doc); err != nil {
		return nil, err
	}
	if err := systems.Encode(cfg.Systems); err != nil {
		return nil, err
	}
	for i, system := range cfg.Systems {
		preserveNilTypes(systems.Content[i], "detect_types", system.DetectTypes)
		preserveNilTypes(systems.Content[i], "mask_types", system.MaskTypes)
	}
	root := doc.Content[0]
	setMapping(root, "systems", systems)
	setMapping(root, "version", yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: cfg.Version})
	return yaml.Marshal(&doc)
}

func setMapping(node *yaml.Node, key string, value yaml.Node) {
	if field := mappingValue(node, key); field != nil {
		*field = value
		return
	}
	node.Content = append(node.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, &value)
}

func mappingValue(node *yaml.Node, key string) *yaml.Node {
	for i := 0; i < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

func preserveNilTypes(node *yaml.Node, key string, values []string) {
	if values != nil {
		return
	}
	field := mappingValue(node, key)
	*field = yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null", Value: "null"}
}

func (s *Store) testStatus(cfg client.DocConfig) client.RunStatus {
	status, err := client.ReadRunStatus(s.opts.StatusPath)
	if err != nil || time.Since(status.UpdatedAt) > 10*time.Second {
		return client.RunStatus{State: "unavailable"}
	}
	if cfg.Enabled && cfg.RunID != status.RunID {
		status.State = "pending"
		status.Progress = nil
		status.FailureCode = ""
	}
	if !cfg.Enabled && status.State == "running" {
		status.State = "stopping"
	}
	return status
}

func (s *Store) commitBackend(cfg *config.Config, original []byte) ([]byte, error) {
	var err error
	cfg.Version, err = nextVersion()
	if err != nil {
		return nil, err
	}
	raw, err := marshalBackend(cfg, original)
	if err != nil {
		return nil, err
	}
	if err := validateBackendDocument(raw); err != nil {
		return nil, err
	}
	return raw, atomicWrite(s.opts.BackendConfigPath, raw, 0600)
}
