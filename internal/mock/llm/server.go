package llm

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alfagen/pii-service/internal/contracts"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Mode values supported by the mock provider.
const (
	ModeEcho    = "echo"
	ModeReorder = "reorder"
	ModeCorrupt = "corrupt"
)

// markerRe matches a valid typed marker: <TYPE_<32 hex>_<counter>>.
var markerRe = regexp.MustCompile(`<[A-Z_]+_[a-f0-9]{32}_[0-9]+>`)

type Config struct {
	Disabled     bool
	Mode         string
	Seed         int64
	Delay        time.Duration
	Status       int
	CaptureTTL   time.Duration
	CaptureLimit int
}

// Validate checks the configuration. Zero Mode means echo; zero Seed is a
// valid seed. Zero Status/CaptureTTL/CaptureLimit keep existing defaults.
func (c Config) Validate() error {
	switch c.Mode {
	case "", ModeEcho, ModeReorder, ModeCorrupt:
	default:
		return fmt.Errorf("unknown mode %q", c.Mode)
	}
	if c.Delay < 0 {
		return errors.New("delay must not be negative")
	}
	if c.CaptureTTL < 0 {
		return errors.New("capture TTL must not be negative")
	}
	if c.CaptureLimit < 0 {
		return errors.New("capture limit must not be negative")
	}
	if c.Status != 0 && c.Status != http.StatusOK && (c.Status < 400 || c.Status > 599) {
		return fmt.Errorf("invalid status %d", c.Status)
	}
	return nil
}

type receivedStore struct {
	mu    sync.RWMutex
	items map[string]receivedItem
}

type receivedItem struct {
	text      string
	expiresAt time.Time
}

// metrics holds the per-handler Prometheus collectors.
type metrics struct {
	requestsTotal *prometheus.CounterVec
	duration      *prometheus.HistogramVec
}

func newMetrics(reg *prometheus.Registry) *metrics {
	m := &metrics{
		requestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mock_llm_requests_total",
			Help: "Completed mock LLM generate requests by mode and HTTP status.",
		}, []string{"mode", "status"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "mock_llm_request_duration_seconds",
			Help:    "Mock LLM generate request duration in seconds, including delay and errors.",
			Buckets: prometheus.DefBuckets,
		}, []string{"mode"}),
	}
	reg.MustRegister(m.requestsTotal, m.duration)
	return m
}

// DynamicHandler serves the mock provider and supports hot configuration
// changes via SetConfig. The listen address is not part of the handler config;
// it is fixed by the caller.
type DynamicHandler struct {
	cfg   atomic.Value // Config
	store *receivedStore
	met   *metrics
	reg   *prometheus.Registry
}

// Handler returns an http.Handler for the given configuration. It is a
// convenience wrapper around NewDynamicHandler for callers that never update
// the configuration.
func Handler(cfg Config) http.Handler {
	return NewDynamicHandler(cfg)
}

// NewDynamicHandler builds a handler with the given initial configuration.
func NewDynamicHandler(cfg Config) *DynamicHandler {
	if cfg.Status == 0 {
		cfg.Status = 200
	}
	if cfg.CaptureTTL <= 0 {
		cfg.CaptureTTL = 5 * time.Minute
	}
	if cfg.CaptureLimit <= 0 {
		cfg.CaptureLimit = 1000
	}
	if cfg.Mode == "" {
		cfg.Mode = ModeEcho
	}
	reg := prometheus.NewRegistry()
	h := &DynamicHandler{
		store: &receivedStore{items: make(map[string]receivedItem)},
		met:   newMetrics(reg),
		reg:   reg,
	}
	h.cfg.Store(cfg)
	return h
}

// SetConfig atomically replaces the handler configuration.
func (h *DynamicHandler) SetConfig(cfg Config) {
	if cfg.Status == 0 {
		cfg.Status = 200
	}
	if cfg.CaptureTTL <= 0 {
		cfg.CaptureTTL = 5 * time.Minute
	}
	if cfg.CaptureLimit <= 0 {
		cfg.CaptureLimit = 1000
	}
	if cfg.Mode == "" {
		cfg.Mode = ModeEcho
	}
	h.cfg.Store(cfg)
}

// Registry returns the per-handler Prometheus registry.
func (h *DynamicHandler) Registry() *prometheus.Registry { return h.reg }

// ServeHTTP implements http.Handler.
func (h *DynamicHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	cfg := h.cfg.Load().(Config)
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/generate":
		if cfg.Disabled {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": map[string]any{"code": "disabled", "retryable": true}})
			return
		}
		h.handleGenerate(w, r, cfg)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/__test/received/"):
		h.handleReceived(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/live":
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	case r.Method == http.MethodGet && r.URL.Path == "/ready":
		if cfg.Disabled {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "disabled"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	case r.Method == http.MethodGet && r.URL.Path == "/metrics":
		promhttp.HandlerFor(h.reg, promhttp.HandlerOpts{}).ServeHTTP(w, r)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
	}
}

func (h *DynamicHandler) handleGenerate(w http.ResponseWriter, r *http.Request, cfg Config) {
	start := time.Now()
	var request struct {
		RequestID string  `json:"request_id"`
		Model     string  `json:"model"`
		Text      *string `json:"text"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || request.RequestID == "" || request.Model == "" || request.Text == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]any{"code": "invalid_request", "retryable": false}})
		h.met.requestsTotal.WithLabelValues(cfg.Mode, "400").Inc()
		h.met.duration.WithLabelValues(cfg.Mode).Observe(time.Since(start).Seconds())
		return
	}
	if _, err := decoder.Token(); err != io.EOF {
		writeJSON(w, 400, map[string]any{"error": map[string]any{"code": "invalid_request", "retryable": false}})
		h.met.requestsTotal.WithLabelValues(cfg.Mode, "400").Inc()
		h.met.duration.WithLabelValues(cfg.Mode).Observe(time.Since(start).Seconds())
		return
	}
	if cfg.Delay > 0 {
		timer := time.NewTimer(cfg.Delay)
		defer timer.Stop()
		select {
		case <-r.Context().Done():
			h.met.requestsTotal.WithLabelValues(cfg.Mode, "cancelled").Inc()
			h.met.duration.WithLabelValues(cfg.Mode).Observe(time.Since(start).Seconds())
			return
		case <-timer.C:
		}
	}
	if cfg.Status != http.StatusOK {
		writeJSON(w, cfg.Status, map[string]any{"error": map[string]any{"code": "configured_failure", "retryable": cfg.Status == 429 || cfg.Status >= 500}})
		h.met.requestsTotal.WithLabelValues(cfg.Mode, strconv.Itoa(cfg.Status)).Inc()
		h.met.duration.WithLabelValues(cfg.Mode).Observe(time.Since(start).Seconds())
		return
	}
	// Capture the provider input before any transformation.
	h.store.mu.Lock()
	now := time.Now()
	for id, item := range h.store.items {
		if !now.Before(item.expiresAt) {
			delete(h.store.items, id)
		}
	}
	if len(h.store.items) >= cfg.CaptureLimit {
		for id := range h.store.items {
			delete(h.store.items, id)
			break
		}
	}
	h.store.items[request.RequestID] = receivedItem{text: *request.Text, expiresAt: time.Now().Add(cfg.CaptureTTL)}
	h.store.mu.Unlock()

	out := transform(cfg.Mode, cfg.Seed, *request.Text)
	writeJSON(w, http.StatusOK, contracts.ProviderResponse{RequestID: request.RequestID, Text: out})
	h.met.requestsTotal.WithLabelValues(cfg.Mode, "200").Inc()
	h.met.duration.WithLabelValues(cfg.Mode).Observe(time.Since(start).Seconds())
}

func (h *DynamicHandler) handleReceived(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/__test/received/"):]
	h.store.mu.Lock()
	item, ok := h.store.items[id]
	if ok && !time.Now().Before(item.expiresAt) {
		delete(h.store.items, id)
		ok = false
	}
	h.store.mu.Unlock()
	if !ok || time.Now().After(item.expiresAt) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
		return
	}
	writeJSON(w, http.StatusOK, contracts.ProviderResponse{RequestID: id, Text: item.text})
}

// transform applies the configured mode to the provider input. It is
// deterministic for a given seed and marker layout: the per-request generator
// is seeded by the seed and the number of markers, so a changed nonce or
// request_id does not change the chosen positions.
func transform(mode string, seed int64, text string) string {
	switch mode {
	case ModeReorder:
		return reorder(seed, text)
	case ModeCorrupt:
		return corrupt(seed, text)
	default:
		return text
	}
}

// marker is a located marker occurrence.
type marker struct {
	start int
	end   int
	value string
}

// findMarkers returns all valid marker occurrences in order.
func findMarkers(text string) []marker {
	idx := markerRe.FindAllStringIndex(text, -1)
	if len(idx) == 0 {
		return nil
	}
	out := make([]marker, 0, len(idx))
	for _, loc := range idx {
		out = append(out, marker{start: loc[0], end: loc[1], value: text[loc[0]:loc[1]]})
	}
	return out
}

// reorder permutes whole markers among their original positions. With 0 or 1
// markers the text is returned unchanged; with two or more distinct markers a
// non-trivial permutation is produced.
func reorder(seed int64, text string) string {
	ms := findMarkers(text)
	if len(ms) < 2 {
		return text
	}
	// Distinct marker values.
	seen := make(map[string]bool, len(ms))
	for _, m := range ms {
		seen[m.value] = true
	}
	if len(seen) < 2 {
		return text
	}
	// Deterministic permutation seeded by seed and marker count.
	rng := rand.New(rand.NewSource(seed + int64(len(ms))))
	perm := rng.Perm(len(ms))
	// Ensure a non-trivial permutation: at least one marker moves.
	if isIdentity(perm) {
		swap(perm, 0, 1)
	}
	values := make([]string, len(ms))
	for i, m := range ms {
		values[i] = m.value
	}
	reordered := make([]string, len(ms))
	for i, p := range perm {
		reordered[i] = values[p]
	}
	// A non-identity index permutation can still leave the value sequence
	// unchanged when equal markers trade places. Ensure that at least two
	// different marker values actually move.
	if slices.Equal(values, reordered) {
		for i := 1; i < len(reordered); i++ {
			if reordered[i] != reordered[0] {
				reordered[0], reordered[i] = reordered[i], reordered[0]
				break
			}
		}
	}
	var b strings.Builder
	b.Grow(len(text))
	last := 0
	for i, m := range ms {
		b.WriteString(text[last:m.start])
		b.WriteString(reordered[i])
		last = m.end
	}
	b.WriteString(text[last:])
	return b.String()
}

func isIdentity(perm []int) bool {
	for i, p := range perm {
		if p != i {
			return false
		}
	}
	return true
}

func swap(perm []int, i, j int) {
	perm[i], perm[j] = perm[j], perm[i]
}

// corrupt selects one marker by seed and replaces the first character of its
// nonce with 'g', making the string no longer match a valid marker. Other
// bytes are unchanged; without markers the text is returned unchanged.
func corrupt(seed int64, text string) string {
	ms := findMarkers(text)
	if len(ms) == 0 {
		return text
	}
	rng := rand.New(rand.NewSource(seed + int64(len(ms))))
	chosen := ms[rng.Intn(len(ms))]
	// The nonce is the penultimate underscore-delimited segment. The type may
	// itself contain underscores, so the first underscore is not a delimiter
	// we can use here.
	counterSep := strings.LastIndexByte(chosen.value, '_')
	nonceSep := strings.LastIndexByte(chosen.value[:counterSep], '_')
	nonceStart := nonceSep + 1
	// Replace the first nonce character with 'g' in the original text.
	pos := chosen.start + nonceStart
	return text[:pos] + "g" + text[pos+1:]
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
