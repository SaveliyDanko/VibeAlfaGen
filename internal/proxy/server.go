// Package proxy owns HTTP, authentication and orchestration; PII is an interface.
package proxy

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/alfagen/pii-service/internal/contracts"
	"github.com/alfagen/pii-service/internal/platform/observability"
	"golang.org/x/time/rate"
)

type ServerConfig struct {
	MaxBodyBytes     int64
	ConcurrencyLimit int
	RequestTimeout   time.Duration
	RateLimitRPS     float64
	RateLimitBurst   int
	AllowedModels    []string
	// EnableGenerate registers /v1/generate and requires a configured provider
	// for readiness. It is false (process-only, the safe default) unless the
	// caller explicitly opts into the test-only generate surface.
	EnableGenerate bool
	// Draining, when non-nil and returning true, marks the server draining:
	// /ready and new /process and /v1/generate requests respond 503
	// draining; /live, /healthz and /metrics stay available. It is checked
	// per request, never network-probed, and safe to leave nil (never
	// draining) outside the Kubernetes production lifecycle.
	Draining func() bool
}
type Server struct {
	processor     contracts.PIIProcessor
	metrics       *observability.Metrics
	logger        *observability.Logger
	health        contracts.HealthChecker
	config        ServerConfig
	sem           chan struct{}
	limiter       *rate.Limiter
	systems       contracts.SystemResolver
	defaultSystem string
	provider      contracts.LLMProvider
}

func NewServer(p contracts.PIIProcessor, m *observability.Metrics, l *observability.Logger, health contracts.HealthChecker, cfg *ServerConfig) *Server {
	conf := *cfg
	if conf.RequestTimeout <= 0 {
		conf.RequestTimeout = 10 * time.Second
	}
	if conf.MaxBodyBytes <= 0 {
		conf.MaxBodyBytes = 2 << 20
	}
	if conf.ConcurrencyLimit <= 0 {
		conf.ConcurrencyLimit = 100
	}
	if conf.RateLimitRPS <= 0 {
		conf.RateLimitRPS = 10000
	}
	if conf.RateLimitBurst <= 0 {
		conf.RateLimitBurst = 1000
	}
	if conf.AllowedModels == nil {
		conf.AllowedModels = []string{"mock"}
	}
	conf.AllowedModels = append([]string{}, conf.AllowedModels...)
	return &Server{processor: p, metrics: m, logger: l, health: health, config: conf, sem: make(chan struct{}, conf.ConcurrencyLimit), limiter: rate.NewLimiter(rate.Limit(conf.RateLimitRPS), conf.RateLimitBurst)}
}

// Configure methods are startup-only; hot reload must publish an immutable snapshot.
func (s *Server) ConfigureSystems(resolver contracts.SystemResolver, defaultSystem string) {
	s.systems = resolver
	s.defaultSystem = defaultSystem
}
func (s *Server) ConfigureProvider(provider contracts.LLMProvider) { s.provider = provider }
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/process", s.handleProcess)
	if s.config.EnableGenerate {
		mux.HandleFunc("/v1/generate", s.handleGenerate)
	}
	for _, path := range []string{"/live", "/healthz"} {
		mux.HandleFunc(path, s.handleHealth)
	}
	for _, path := range []string{"/ready", "/readyz"} {
		mux.HandleFunc(path, s.handleReady)
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { writeError(w, 404, "not_found") })
	return s.withMiddleware(mux)
}
func (s *Server) draining() bool {
	return s.config.Draining != nil && s.config.Draining()
}
func (s *Server) consumer(w http.ResponseWriter, r *http.Request) (contracts.Consumer, bool) {
	if s.draining() {
		writeError(w, 503, "draining")
		return contracts.Consumer{}, false
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeError(w, 405, "method_not_allowed")
		return contracts.Consumer{}, false
	}
	if s.systems == nil || s.processor == nil {
		writeError(w, 503, "not_configured")
		return contracts.Consumer{}, false
	}
	id := s.defaultSystem
	if requested := r.Header.Get("X-System-ID"); requested != "" {
		id = requested
	}
	consumer, ok := s.systems.ResolveSystem(id)
	if !ok || !consumer.Enabled {
		writeError(w, 403, "system_unavailable")
		return contracts.Consumer{}, false
	}
	if consumer.APIKey != "" && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-API-Key")), []byte(consumer.APIKey)) != 1 {
		writeError(w, 401, "authentication_failed")
		return contracts.Consumer{}, false
	}
	return consumer, true
}
func (s *Server) handleProcess(w http.ResponseWriter, r *http.Request) {
	consumer, ok := s.consumer(w, r)
	if !ok {
		return
	}
	req, err := decodeRequest(r, s.config.MaxBodyBytes)
	if err != nil {
		writePIIError(w, err)
		return
	}
	result, err := s.processor.Process(r.Context(), contracts.Scope{TenantID: consumer.ID, ContextID: *req.PayloadID, Policy: consumer.Policy}, *req.Payload)
	if err != nil {
		writePIIError(w, err)
		return
	}
	writeJSON(w, 200, response{Result: result})
}

type generateRequest struct {
	RequestID *string `json:"request_id"`
	Model     *string `json:"model"`
	Text      *string `json:"text"`
}

func (s *Server) handleGenerate(w http.ResponseWriter, r *http.Request) {
	consumer, ok := s.consumer(w, r)
	if !ok {
		return
	}
	if s.provider == nil {
		writeError(w, 503, "provider_unavailable")
		return
	}
	var req generateRequest
	if err := decodeObject(r, s.config.MaxBodyBytes, []string{"request_id", "model", "text"}, []**string{&req.RequestID, &req.Model, &req.Text}); err != nil {
		writePIIError(w, err)
		return
	}
	if req.RequestID == nil || *req.RequestID == "" || req.Model == nil || *req.Model == "" || req.Text == nil {
		writeError(w, 400, "missing_field")
		return
	}
	if !slices.Contains(s.config.AllowedModels, *req.Model) {
		writeError(w, 400, "invalid_model")
		return
	}

	scope := contracts.Scope{TenantID: consumer.ID, ContextID: *req.RequestID, Policy: consumer.Policy}
	masked, err := s.processor.Mask(r.Context(), scope, *req.Text)
	if err != nil {
		writePIIError(w, err)
		return
	}
	if err := r.Context().Err(); err != nil {
		writePIIError(w, err)
		return
	}
	// Use an opaque server ID at the provider boundary, not caller-controlled metadata.
	result, err := s.provider.Generate(r.Context(), contracts.ProviderRequest{RequestID: observability.RequestID(r), Model: *req.Model, Text: masked.Text})
	if err != nil {
		writeProviderError(w, err)
		return
	}
	// Demask always sanitizes new PII; AllowDemask controls restoration of originals.
	result, err = s.processor.Demask(r.Context(), scope, result)
	if err != nil {
		writePIIError(w, err)
		return
	}
	writeJSON(w, 200, contracts.ProviderResponse{RequestID: *req.RequestID, Text: result})
}
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]string{"status": "ok"})
}
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if s.draining() {
		writeError(w, 503, "draining")
		return
	}
	if s.systems == nil || s.processor == nil {
		writeError(w, 503, "not_ready")
		return
	}
	// Provider readiness only applies to the test-only generate surface;
	// process-only never constructs a provider and never network-probes it.
	if s.config.EnableGenerate && s.provider == nil {
		writeError(w, 503, "not_ready")
		return
	}
	if _, ok := s.systems.ResolveSystem(s.defaultSystem); !ok {
		writeError(w, 503, "not_ready")
		return
	}
	if s.health != nil {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second)
		defer cancel()
		if err := s.health.Check(ctx); err != nil {
			writeError(w, 503, "dependency_unavailable")
			return
		}
	}
	writeJSON(w, 200, map[string]string{"status": "ready"})
}

type recorder struct {
	http.ResponseWriter
	status int
}

func (w *recorder) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
		w.ResponseWriter.WriteHeader(status)
	}
}
func (w *recorder) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(200)
	}
	return w.ResponseWriter.Write(body)
}
func (w *recorder) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (s *Server) withMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		operation := requestOperation(r.URL.Path)
		start := time.Now()
		rw := &recorder{ResponseWriter: w}
		var reqID string
		defer s.recordRequest(rw, operation, &reqID, start)
		defer func() {
			if recover() != nil {
				s.metrics.ObserveRejected("panic")
				s.logger.Error("request panicked", "request_id", reqID, "operation", operation)
				if rw.status == 0 {
					writeError(rw, 500, "internal_error")
				}
			}
		}()
		reqID = observability.NextRequestID()
		r.Header.Set("X-Request-ID", reqID)
		w.Header().Set("X-Request-ID", reqID)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")

		if operation == "process" || operation == "generate" {
			if !s.acquireRequest(rw) {
				return
			}
			defer func() { <-s.sem }()
			s.metrics.ActiveRequests.Inc()
			defer s.metrics.ActiveRequests.Dec()
		}
		ctx, cancel := context.WithTimeout(r.Context(), s.config.RequestTimeout)
		defer cancel()
		ctx = contracts.WithRequestID(ctx, reqID)
		_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(s.config.RequestTimeout))
		next.ServeHTTP(rw, r.WithContext(ctx))
	})
}
func writePIIError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		writeError(w, 504, "request_timeout")
	case errors.Is(err, contracts.ErrConflict):
		writeError(w, 409, "context_conflict")
	case errors.Is(err, contracts.ErrContextGone):
		writeError(w, 410, "context_gone")
	case errors.Is(err, contracts.ErrDemaskDenied):
		writeError(w, 403, "demask_denied")
	case errors.Is(err, contracts.ErrStoreUnavailable), errors.Is(err, contracts.ErrDetectionUnavailable), errors.Is(err, contracts.ErrInvalidPolicy):
		writeError(w, 503, "pii_unavailable")
	case errors.Is(err, ErrBodyTooLarge):
		writeError(w, 413, "body_too_large")
	case errors.Is(err, ErrInvalidJSON), errors.Is(err, ErrMissingField), errors.Is(err, ErrExtraField), errors.Is(err, contracts.ErrInvalidRequest):
		writeError(w, 400, "invalid_request")
	default:
		writeError(w, 500, "internal_error")
	}
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]any{"error": map[string]any{"code": code, "retryable": status == 429 || status >= 500}})
}

func writeProviderError(w http.ResponseWriter, err error) {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		writeError(w, 504, "request_timeout")
	} else if errors.Is(err, contracts.ErrInvalidModel) {
		writeError(w, 400, "invalid_model")
	} else {
		writeError(w, 502, "provider_failed")
	}
}

func requestOperation(path string) string {
	operation := "other"
	switch path {
	case "/process":
		operation = "process"
	case "/v1/generate":
		operation = "generate"
	case "/live", "/healthz":
		operation = "live"
	case "/ready", "/readyz":
		operation = "ready"
	}
	return operation
}

func (s *Server) acquireRequest(w http.ResponseWriter) bool {
	if !s.limiter.Allow() {
		s.metrics.ObserveRejected("rate_limit")
		w.Header().Set("Retry-After", "1")
		writeError(w, 429, "rate_limit_exceeded")
		return false
	}
	select {
	case s.sem <- struct{}{}:
		return true
	default:
		s.metrics.ObserveRejected("concurrency")
		w.Header().Set("Retry-After", "1")
		writeError(w, 429, "concurrency_exceeded")
		return false
	}
}

func (s *Server) recordRequest(rw *recorder, operation string, reqID *string, start time.Time) {
	status := rw.status
	if status == 0 {
		status = 200
	}
	dur := time.Since(start)
	s.metrics.ObserveRequest(status, operation, "", dur)
	// One line per HTTP request; correlates with pii_operation log
	// lines from the PII engine via request_id. No body/PII fields.
	s.logger.Info("http_request",
		"request_id", *reqID,
		"operation", operation,
		"status", status,
		"duration_ms", dur.Milliseconds(),
	)
}
