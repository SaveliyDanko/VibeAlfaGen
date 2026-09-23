// Package contracts contains dependency-free boundaries shared by the proxy,
// PII engine and provider adapters.
package contracts

import (
	"context"
	"errors"
	"time"
)

type Policy struct {
	DetectionProfile string
	Version          string
	Mode             string
	DetectTypes      []string
	MaskTypes        []string
	AllowDemask      bool
	TTL              time.Duration
	Rules            []PolicyRule
}

// Nil type lists mean all registered types; an explicit empty list means none.
// Values, including slices, are immutable for the lifetime of a request.
type PolicyRule struct {
	Type     string
	Requires []string
}

type Consumer struct {
	ID      string
	Enabled bool
	APIKey  string
	Policy  Policy
}

type SystemResolver interface {
	ResolveSystem(string) (Consumer, bool)
}

type HealthChecker interface{ Check(context.Context) error }

// PIIContextObserver is optional to preserve existing observer adapters.
// Only registered type names and aggregate decisions may be supplied.
type PIIContextObserver interface {
	ObserveContextDecision(typ, decision string, count int)
}

// PIIObserver is implemented by platform metrics without importing PII internals.
type PIIObserver interface {
	ObserveFindings([]string)
	ObserveProcessed(int, int)
	ObserveStage(string, time.Duration)
	ObserveStoreError(string)
	ObserveOperation(OperationEvent)
}

// OperationEvent is one completed PII operation (Process/Mask/Demask), logged
// as a single line so a demo request can be traced end to end. Only
// technical fields are carried: no payload text, PII values,
// or the caller-controlled payload/context ID in the clear.
type OperationEvent struct {
	Operation string   // "process", "mask" or "demask"
	System    string   // resolved consumer/system ID, not PII
	RequestID string   // correlates with the HTTP access log line, see WithRequestID
	Outcome   string   // e.g. "masked_new", "masked_existing", "demasked", "conflict"
	Types     []string // PII types detected during this operation, if any were detected
	Bytes     int      // input size in bytes
	Duration  time.Duration
}

type ctxKey int

const requestIDKey ctxKey = iota

// WithRequestID attaches the server-generated request ID to ctx so PII engine
// logs can be correlated with the HTTP access log line for the same request.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

// RequestIDFromContext returns "" if no request ID was attached.
func RequestIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey).(string)
	return id
}

var (
	ErrConflict             = errors.New("context_conflict")
	ErrContextGone          = errors.New("context_gone")
	ErrDemaskDenied         = errors.New("demask_denied")
	ErrInvalidPolicy        = errors.New("invalid_policy")
	ErrStoreUnavailable     = errors.New("store_unavailable")
	ErrDetectionUnavailable = errors.New("detection_unavailable")
	ErrInvalidRequest       = errors.New("invalid_request")
	ErrInvalidModel         = errors.New("invalid_model")
)

type Scope struct {
	TenantID  string
	ContextID string
	Policy    Policy
}

type Masked struct {
	Text          string
	ContextID     string
	PolicyVersion string
}

type PIIProcessor interface {
	Mask(context.Context, Scope, string) (Masked, error)
	Demask(context.Context, Scope, string) (string, error)
	Process(context.Context, Scope, string) (string, error)
}

type ProviderRequest struct {
	RequestID string `json:"request_id"`
	Model     string `json:"model"`
	Text      string `json:"text"`
}

type ProviderResponse struct {
	RequestID string `json:"request_id"`
	Text      string `json:"text"`
}

type LLMProvider interface {
	Generate(context.Context, ProviderRequest) (string, error)
}
