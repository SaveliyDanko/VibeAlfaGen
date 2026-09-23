// Package observability provides structured logging and Prometheus metrics.
// Callers must pass only approved technical fields; slog itself is not a PII filter.
package observability

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/alfagen/pii-service/internal/contracts"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// HashID is a stable pseudonym, not an anonymization guarantee for low-entropy IDs.
// HTTP handlers do not log caller-controlled IDs or their hashes.
func HashID(payloadID string) string {
	h := sha256.Sum256([]byte(payloadID))
	return hex.EncodeToString(h[:8])
}

// Metrics holds all Prometheus collectors.
type Metrics struct {
	ContextDecisions *prometheus.CounterVec
	RequestsTotal    *prometheus.CounterVec
	RequestDuration  *prometheus.HistogramVec
	ActiveRequests   prometheus.Gauge
	RejectedTotal    *prometheus.CounterVec
	FindingsTotal    *prometheus.CounterVec
	ProcessedBytes   prometheus.Counter
	ProcessedTokens  prometheus.Counter
	StageDuration    *prometheus.HistogramVec
	ConfigReloads    *prometheus.CounterVec
	PropertyChecks   *prometheus.CounterVec
	StoreErrors      *prometheus.CounterVec
	logger           *Logger
}

var _ contracts.PIIObserver = (*Metrics)(nil)

// NewMetrics registers all collectors.
func NewMetrics(reg *prometheus.Registry) *Metrics {
	f := promauto.With(reg)
	return &Metrics{
		ContextDecisions: f.NewCounterVec(prometheus.CounterOpts{Name: "pii_context_candidates_total", Help: "Contextual promotions and suppressions by type."}, []string{"type", "decision"}),
		RequestsTotal: f.NewCounterVec(prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total requests by status and operation.",
		}, []string{"status", "operation"}),
		RequestDuration: f.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "request_duration_seconds",
			Help:    "Request duration in seconds.",
			Buckets: prometheus.DefBuckets,
		}, []string{"operation"}),
		ActiveRequests: f.NewGauge(prometheus.GaugeOpts{
			Name: "inflight_requests",
			Help: "Number of in-flight requests.",
		}),
		RejectedTotal: f.NewCounterVec(prometheus.CounterOpts{
			Name: "pii_rejected_total",
			Help: "Total rejected requests by reason.",
		}, []string{"reason"}),
		FindingsTotal: f.NewCounterVec(prometheus.CounterOpts{
			Name: "pii_findings_total",
			Help: "Total findings by type.",
		}, []string{"type"}),
		ProcessedBytes: f.NewCounter(prometheus.CounterOpts{
			Name: "pii_processed_bytes_total",
			Help: "Total bytes processed.",
		}),
		ProcessedTokens: f.NewCounter(prometheus.CounterOpts{
			Name: "tokens_processed_total",
			Help: "Estimated tokens (UTF-8 bytes/4); not a tokenizer-based TPS measurement.",
		}),
		StageDuration: f.NewHistogramVec(prometheus.HistogramOpts{
			Name: "pii_stage_duration_seconds", Help: "PII stage duration in seconds.",
		}, []string{"stage"}),
		ConfigReloads: f.NewCounterVec(prometheus.CounterOpts{
			Name: "config_reload_total", Help: "Configuration reload outcomes.",
		}, []string{"status"}),
		PropertyChecks: f.NewCounterVec(prometheus.CounterOpts{
			Name: "property_checks_total", Help: "Property check outcomes.",
		}, []string{"status"}),
		StoreErrors: f.NewCounterVec(prometheus.CounterOpts{
			Name: "context_store_errors_total", Help: "Context store errors by operation.",
		}, []string{"operation"}),
	}
}

func (m *Metrics) ObserveStage(stage string, duration time.Duration) {
	m.StageDuration.WithLabelValues(stage).Observe(duration.Seconds())
}

func (m *Metrics) ObserveStoreError(operation string) {
	m.StoreErrors.WithLabelValues(operation).Inc()
}

// ObserveRequest records a completed request.
func (m *Metrics) ObserveRequest(status int, operation, system string, dur time.Duration) {
	_ = system
	m.RequestsTotal.WithLabelValues(strconv.Itoa(status), operation).Inc()
	m.RequestDuration.WithLabelValues(operation).Observe(dur.Seconds())
}

// ObserveRejected records a rejected request.
func (m *Metrics) ObserveRejected(reason string) {
	m.RejectedTotal.WithLabelValues(reason).Inc()
}

// ObserveFindings records findings by type.
func (m *Metrics) ObserveFindings(types []string) {
	for _, t := range types {
		m.FindingsTotal.WithLabelValues(t).Inc()
	}
}

// ObserveProcessed records processed bytes and tokens.
func (m *Metrics) ObserveProcessed(bytes, tokens int) {
	m.ProcessedBytes.Add(float64(bytes))
	m.ProcessedTokens.Add(float64(tokens))
}

// AttachLogger enables per-operation structured logging (ObserveOperation)
// on this Metrics instance. The NewMetrics constructor signature stays
// unchanged so existing callers/tests are unaffected; without an attached
// logger, ObserveOperation is a no-op and Prometheus counters still work.
// Call during startup before the Metrics instance is used by concurrent requests.
func (m *Metrics) AttachLogger(l *Logger) *Metrics {
	m.logger = l
	return m
}

// ObserveOperation logs one completed PII operation (Process/Mask/Demask) as
// a single structured line, so a demo request can be traced end to end via
// its request_id. Only technical fields are logged: no
// payload text, PII values, or the caller-controlled payload/context ID.
func (m *Metrics) ObserveOperation(e contracts.OperationEvent) {
	if m.logger == nil {
		return
	}
	m.logger.Info("pii_operation",
		"request_id", e.RequestID,
		"system", e.System,
		"operation", e.Operation,
		"outcome", e.Outcome,
		"pii_types", e.Types,
		"bytes", e.Bytes,
		"duration_ms", float64(e.Duration)/float64(time.Millisecond),
	)
}

// Logger wraps slog with a safe interface.
type Logger struct {
	*slog.Logger
}

// NewLogger creates a JSON slog logger at the given level.
func NewLogger(level string) (*Logger, error) {
	return NewLoggerWithWriter(level, os.Stdout)
}

// NewLoggerWithWriter creates a JSON slog logger writing to w.
func NewLoggerWithWriter(level string, w io.Writer) (*Logger, error) {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "info":
		lvl = slog.LevelInfo
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: lvl})
	return &Logger{slog.New(h)}, nil
}

// RequestID returns the request ID from the context or generates one.
func RequestID(r *http.Request) string {
	if id := r.Header.Get("X-Request-ID"); id != "" {
		return id
	}
	return ""
}

// NextRequestID produces an opaque ID across replicas and process restarts.
func NextRequestID() string {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		panic("request ID unavailable")
	}
	return hex.EncodeToString(id[:])
}

// ObserveContextDecision accepts only the resolver's bounded categories.
func (m *Metrics) ObserveContextDecision(typ, decision string, count int) {
	if count <= 0 || (typ != "full_name" && typ != "address") || (decision != "promoted" && decision != "suppressed") {
		return
	}
	m.ContextDecisions.WithLabelValues(typ, decision).Add(float64(count))
}
