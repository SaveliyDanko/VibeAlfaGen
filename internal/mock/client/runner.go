package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Mode values supported by the continuous runner.
const (
	ModeProcess  = "process"
	ModeGenerate = "generate"

	requestAttemptsLimit       = 3
	consecutiveInvalidLimit    = 5
	defaultRetryAfter          = time.Second
	firstTransientRetryBackoff = 100 * time.Millisecond
)

// Config configures the continuous paced runner. Planning is independent of
// worker completion: on each planned tick a request is either handed off when
// in-flight capacity is available or counted as dropped, so a slow backend
// never silently lowers the planned rate.
type Config struct {
	Version       string
	Mode          string
	Scenario      string
	TargetURL     string
	Seed          int64
	RatePerSecond float64
	Concurrency   int
	MaxInFlight   int
	// MaxConnections bounds physical connections separately from paced operations.
	// Zero preserves the Go transport's unlimited default; fixed for a run.
	MaxConnections   int
	RequestTimeout   time.Duration
	Duration         time.Duration
	OperationLimit   int64
	PayloadProfile   string
	SystemID         string
	APIKey           string
	Enabled          bool
	OperationWeights map[string]float64
	CommitSHA        string
	ImageTag         string
	RunID            string
	ReplayIndex      *int64
	Environment      ReportEnvironment
	// Payloads are validated, immutable fixtures loaded once before the run.
	Payloads      []string
	DatasetSHA256 string
	IDNamespace   string
	MaskFixtures  []MaskFixture
}

// Validate rejects negative or zero required values. Zero Seed and zero
// Duration are valid (seed 0 is a legal seed; duration 0 means run until the
// context is cancelled).
func (c Config) Validate() error {
	for _, validate := range []func() error{c.validateTarget, c.validateLimits, c.validateScenario, c.validateFixtures} {
		if err := validate(); err != nil {
			return err
		}
	}
	return nil
}

func (c Config) validateTarget() error {
	switch c.Mode {
	case ModeProcess, ModeGenerate:
	default:
		return fmt.Errorf("unknown mode %q", c.Mode)
	}
	if c.TargetURL == "" {
		return errors.New("target URL required")
	}
	if err := validateTargetURL(c.TargetURL); err != nil {
		return err
	}
	if c.RatePerSecond <= 0 || math.IsNaN(c.RatePerSecond) || math.IsInf(c.RatePerSecond, 0) {
		return errors.New("rate per second must be positive")
	}
	if intervalFor(c.RatePerSecond) <= 0 {
		return errors.New("rate per second is too high")
	}
	return nil
}

func validateTargetURL(value string) error {
	u, err := url.Parse(value)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Fragment != "" {
		return errors.New("target URL must be an absolute HTTP(S) URL without credentials or fragment")
	}
	return nil
}

func (c Config) validateLimits() error {
	if c.MaxConnections < 0 {
		return errors.New("max connections must not be negative")
	}
	if c.Concurrency == 0 {
		c.Concurrency = c.MaxInFlight
	}
	if c.Concurrency <= 0 {
		return errors.New("concurrency must be positive")
	}
	if c.MaxInFlight <= 0 {
		return errors.New("max in-flight must be positive")
	}
	if c.RequestTimeout <= 0 {
		return errors.New("request timeout must be positive")
	}
	if c.Duration < 0 {
		return errors.New("duration must not be negative")
	}
	if c.OperationLimit < 0 {
		return errors.New("operation limit must not be negative")
	}
	if c.PayloadProfile == "" {
		return errors.New("payload profile required")
	}
	if c.SystemID == "" {
		return errors.New("system ID required")
	}
	return nil
}

func (c Config) validateScenario() error {
	switch scenarioOf(c) {
	case ScenarioRequest:
	case ScenarioMaskOnly:
		if c.Mode != ModeProcess {
			return errors.New("mask_only scenario requires process mode")
		}
	case ScenarioRoundTrip, ScenarioStableRetry, ScenarioExpectedConflict:
		if c.Mode != ModeProcess {
			return fmt.Errorf("%s scenario requires process mode", scenarioOf(c))
		}
	case ScenarioMixed:
		if c.Mode != ModeProcess {
			return errors.New("mixed scenario requires process mode")
		}
		if err := validateOperationWeights(c.OperationWeights); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown scenario %q", c.Scenario)
	}
	return nil
}

func (c Config) validateFixtures() error {
	if c.ReplayIndex != nil && *c.ReplayIndex < 0 {
		return errors.New("replay index must not be negative")
	}
	if len(c.MaskFixtures) > 0 {
		for i, fixture := range c.MaskFixtures {
			if fixture.Payload == "" {
				return fmt.Errorf("mask fixture %d: payload required", i)
			}
			if len(fixture.Spans) == 0 && fixture.ExpectedMask == "" {
				continue
			}
			if err := validateMaskFixture(fixture); err != nil {
				return fmt.Errorf("mask fixture %d: %w", i, err)
			}
		}
	}
	return nil
}

func validateOperationWeights(weights map[string]float64) error {
	if len(weights) == 0 {
		return errors.New("mixed scenario requires operation weights")
	}
	valid := map[string]bool{
		ScenarioMaskOnly: true, ScenarioRoundTrip: true,
		ScenarioStableRetry: true, ScenarioExpectedConflict: true,
	}
	for name, weight := range weights {
		if !valid[name] {
			return fmt.Errorf("unknown operation weight %q", name)
		}
		if weight < 0 || math.IsNaN(weight) || math.IsInf(weight, 0) {
			return fmt.Errorf("operation weight %q must be finite and non-negative", name)
		}
	}
	sum := weights[ScenarioMaskOnly] + weights[ScenarioRoundTrip] + weights[ScenarioStableRetry] + weights[ScenarioExpectedConflict]
	if sum <= 0 || math.IsNaN(sum) || math.IsInf(sum, 0) {
		return errors.New("operation weights must have a positive finite sum")
	}
	return nil
}

func scenarioOf(c Config) string {
	if c.Scenario == "" {
		return ScenarioRequest
	}
	return c.Scenario
}

// ReportParameters is the immutable parameter snapshot recorded for a run.
type ReportParameters struct {
	TargetRPS        float64            `json:"target_rps"`
	DurationSeconds  float64            `json:"duration_seconds"`
	Concurrency      int                `json:"concurrency"`
	MaxInFlight      int                `json:"max_in_flight"`
	MaxConnections   int                `json:"max_connections_per_host,omitempty"`
	RequestTimeoutMS int64              `json:"request_timeout_ms"`
	PayloadProfile   string             `json:"payload_profile"`
	OperationWeights map[string]float64 `json:"operation_weights"`
}

// ReportCounts separates logical operations, HTTP attempts and completed pairs.
type ReportCounts struct {
	PlannedOperations    int64 `json:"planned_operations"`
	SentRequests         int64 `json:"sent_requests"`
	DroppedOperations    int64 `json:"dropped_operations"`
	SuccessfulOperations int64 `json:"successful_operations"`
	FailedOperations     int64 `json:"failed_operations"`
	Timeouts             int64 `json:"timeouts"`
	HTTPRequests         int64 `json:"http_requests"`
	CompletedPairs       int64 `json:"completed_pairs"`
	Retries              int64 `json:"retries"`
	FinalRateLimited     int64 `json:"final_rate_limited"`
	MaxInvalidStreak     int64 `json:"max_invalid_streak"`
}

// ReportLatency stores milliseconds so the JSON format is language-neutral.
type ReportLatency struct {
	P50       float64 `json:"p50"`
	P95       float64 `json:"p95"`
	P99       float64 `json:"p99"`
	Max       float64 `json:"max"`
	Target    float64 `json:"target"`
	TargetMet bool    `json:"target_met"`
}

// ReportEnvironment contains only safe, explicitly supplied labels.
type ReportEnvironment struct {
	Runner         string             `json:"runner"`
	Host           string             `json:"host"`
	ResourceLimits map[string]float64 `json:"resource_limits"`
}

// Report summarises a completed run. The json-visible fields are exactly the
// alfagen.load.v1 contract; compatibility fields remain available to callers
// but are intentionally excluded from JSON.
type Report struct {
	SchemaVersion string            `json:"schema_version"`
	RunID         string            `json:"run_id"`
	Seed          int64             `json:"seed"`
	Scenario      string            `json:"scenario"`
	CommitSHA     string            `json:"commit_sha"`
	ImageTag      string            `json:"image_tag"`
	StartedAt     time.Time         `json:"started_at"`
	FinishedAt    time.Time         `json:"finished_at"`
	Parameters    ReportParameters  `json:"parameters"`
	Counts        ReportCounts      `json:"counts"`
	HTTPStatuses  map[string]int64  `json:"http_statuses"`
	LatencyMS     ReportLatency     `json:"latency_ms"`
	StopReason    string            `json:"stop_reason"`
	Environment   ReportEnvironment `json:"environment"`
	Verdict       string            `json:"verdict"`

	ConfigVersion       string           `json:"-"`
	Mode                string           `json:"-"`
	Profile             string           `json:"-"`
	Planned             int64            `json:"-"`
	Sent                int64            `json:"-"`
	Dropped             int64            `json:"-"`
	Success             int64            `json:"-"`
	Failed              int64            `json:"-"`
	SuccessfulRPS       float64          `json:"-"`
	HTTPRPS             float64          `json:"-"`
	P50                 time.Duration    `json:"-"`
	P95                 time.Duration    `json:"-"`
	P99                 time.Duration    `json:"-"`
	Max                 time.Duration    `json:"-"`
	LatencyTarget       time.Duration    `json:"-"`
	LatencyTargetMet    bool             `json:"-"`
	Duration            time.Duration    `json:"-"`
	HTTPStatus          map[string]int64 `json:"-"`
	Errors              map[string]int64 `json:"-"`
	TargetRPS           float64          `json:"-"`
	DatasetSHA256       string           `json:"-"`
	IDNamespace         string           `json:"-"`
	HTTPRequests        int64            `json:"-"`
	Retries             int64            `json:"-"`
	FinalRateLimited    int64            `json:"-"`
	CompletedPairs      int64            `json:"-"`
	MaxInvalidStreak    int64            `json:"-"`
	QualityEvaluated    int64            `json:"-"`
	MaskDistanceMean    float64          `json:"-"`
	MaskDistanceMax     float64          `json:"-"`
	EvaluatedCategories map[string]int64 `json:"-"`
}

// Ticker abstracts a pacing ticker so tests can drive planning without real
// sleeps.
type Ticker interface {
	C() <-chan time.Time
	Stop()
	Due(time.Time) int64
}

type realTicker struct {
	*time.Ticker
	next     time.Time
	interval time.Duration
}

func (t *realTicker) C() <-chan time.Time { return t.Ticker.C }

// Due accounts for every elapsed slot even when time.Ticker coalesces wakeups.
func (t *realTicker) Due(now time.Time) int64 {
	if now.Before(t.next) {
		return 0
	}
	n := int64(now.Sub(t.next)/t.interval) + 1
	t.next = t.next.Add(time.Duration(n) * t.interval)
	return n
}

// metrics holds the per-run Prometheus collectors.
type metrics struct {
	requestsTotal  *prometheus.CounterVec
	duration       *prometheus.HistogramVec
	inflight       *prometheus.GaugeVec
	statusTotal    *prometheus.CounterVec
	statusClass    *prometheus.CounterVec
	errorsTotal    *prometheus.CounterVec
	completedPairs prometheus.Counter
	maskDistance   prometheus.Histogram
}

func newMetrics(reg *prometheus.Registry) *metrics {
	m := &metrics{
		requestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mock_client_requests_total",
			Help: "Mock client requests by stage and mode.",
		}, []string{"stage", "mode"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "mock_client_request_duration_seconds",
			Help:    "Mock client request duration in seconds by mode.",
			Buckets: prometheus.DefBuckets,
		}, []string{"mode"}),
		inflight: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "mock_client_inflight_requests",
			Help: "Mock client in-flight requests by mode.",
		}, []string{"mode"}),
		statusTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mock_client_http_status_total",
			Help: "Mock client responses by HTTP status and mode.",
		}, []string{"status", "mode"}),
		statusClass: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mock_client_http_status_class_total",
			Help: "Mock client responses by bounded HTTP status class and mode.",
		}, []string{"class", "mode"}),
		errorsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mock_client_errors_total",
			Help: "Mock client errors by category and mode.",
		}, []string{"category", "mode"}),
		completedPairs: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "mock_client_completed_pairs_total",
			Help: "Round-trip pairs whose mask and exact demask responses were evaluated.",
		}),
		maskDistance: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "mock_client_mask_distance",
			Help:    "Normalized span-based Levenshtein distance from the expected mask.",
			Buckets: []float64{0, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 0.75, 1},
		}),
	}
	reg.MustRegister(m.requestsTotal, m.duration, m.inflight, m.statusTotal, m.statusClass, m.errorsTotal, m.completedPairs, m.maskDistance)
	return m
}

// Runner executes a continuous paced load against a target. It is safe to
// construct once and run once; the per-run registry and reservoir are owned by
// the runner. The configuration can be updated atomically via SetConfig so a
// reloader can apply a new version to new planned requests.
type Runner struct {
	mu      sync.RWMutex
	cfg     Config
	reg     *prometheus.Registry
	met     *metrics
	res     *reservoir
	quality qualityAccumulator

	httpClient     *http.Client
	newTicker      func(time.Duration) Ticker
	wait           func(context.Context, time.Duration) error
	now            func() time.Time
	pacer          requestPacer
	outcomes       outcomeCounts
	execution      atomic.Pointer[runnerExecution]
	reloadRejected atomic.Bool
}

type runCounters struct {
	planned        atomic.Int64
	sent           atomic.Int64
	dropped        atomic.Int64
	success        atomic.Int64
	failed         atomic.Int64
	httpRequests   atomic.Int64
	retries        atomic.Int64
	final429       atomic.Int64
	completedPairs atomic.Int64
	timeouts       atomic.Int64
}

type requestDisposition uint8

const (
	dispositionSuccess requestDisposition = iota
	dispositionInvalid
	dispositionRateLimited
	dispositionCancelled
)

type requestResult struct {
	body        []byte
	disposition requestDisposition
}

// availabilityTracker implements the evaluator stop rule. Results are ordered
// by completion, which is the only deterministic global order under concurrent
// load. A 429 is neutral: it neither increments nor resets the invalid streak.
type availabilityTracker struct {
	mu          sync.Mutex
	consecutive int64
	maximum     int64
	stopped     bool
	stop        context.CancelFunc
}

func (t *availabilityTracker) record(disposition requestDisposition) {
	t.mu.Lock()
	if t.stopped {
		t.mu.Unlock()
		return
	}
	switch disposition {
	case dispositionSuccess:
		t.consecutive = 0
	case dispositionInvalid:
		t.consecutive++
		if t.consecutive > t.maximum {
			t.maximum = t.consecutive
		}
		if t.consecutive >= consecutiveInvalidLimit {
			t.stopped = true
			stop := t.stop
			t.mu.Unlock()
			stop()
			return
		}
	case dispositionRateLimited, dispositionCancelled:
		// A 429 is explicitly neutral. Cancellation is run control, not evidence
		// that the endpoint is unavailable.
	}
	t.mu.Unlock()
}

func (t *availabilityTracker) snapshot() (int64, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.maximum, t.stopped
}

// requestPacer limits actual HTTP attempts, including retries and demasking.
// Therefore target RPS is HTTP RPS rather than logical operation RPS.
type requestPacer struct {
	mu   sync.Mutex
	next time.Time
}

func (p *requestPacer) wait(ctx context.Context, rate float64, now func() time.Time, wait func(context.Context, time.Duration) error) error {
	interval := intervalFor(rate)
	p.mu.Lock()
	current := now()
	due := current
	if p.next.After(current) {
		due = p.next
	}
	p.next = due.Add(interval)
	p.mu.Unlock()
	return wait(ctx, due.Sub(current))
}

type outcomeCounts struct {
	mu         sync.Mutex
	httpStatus map[string]int64
	errors     map[string]int64
}

// NewRunner validates the configuration and prepares a runner with its own
// Prometheus registry.
func NewRunner(cfg Config) (*Runner, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	reg := prometheus.NewRegistry()
	r := &Runner{
		cfg:        cloneConfig(cfg),
		reg:        reg,
		met:        newMetrics(reg),
		res:        newReservoir(1024),
		httpClient: &http.Client{Transport: runnerTransport(cfg.MaxConnections)},
		now:        time.Now,
		wait: func(ctx context.Context, delay time.Duration) error {
			if delay <= 0 {
				return nil
			}
			timer := time.NewTimer(delay)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
				return nil
			}
		},
		newTicker: func(d time.Duration) Ticker {
			wake := d
			if wake < time.Millisecond {
				wake = time.Millisecond
			}
			return &realTicker{Ticker: time.NewTicker(wake), next: time.Now().Add(d), interval: d}
		},
		outcomes: outcomeCounts{
			httpStatus: map[string]int64{},
			errors:     map[string]int64{},
		},
	}
	return r, nil
}

func runnerTransport(maxConnections int) *http.Transport {
	return &http.Transport{
		MaxIdleConns: 1024, MaxIdleConnsPerHost: 1024,
		MaxConnsPerHost: maxConnections, IdleConnTimeout: 90 * time.Second,
	}
}

// SetConfig atomically replaces the runner configuration. The new value is
// validated before it is published; a rejected update leaves the current
// configuration unchanged.
func (r *Runner) SetConfig(cfg Config) error {
	if err := cfg.Validate(); err != nil {
		r.RecordReloadFailure()
		return err
	}
	r.mu.Lock()
	if cfg.MaxConnections != r.cfg.MaxConnections {
		r.mu.Unlock()
		r.RecordReloadFailure()
		return errors.New("max connections cannot change during a run")
	}
	r.cfg = cloneConfig(cfg)
	r.mu.Unlock()
	r.reloadRejected.Store(false)
	return nil
}

// RecordReloadFailure preserves the active configuration and marks the live
// snapshot when credentials or another document field cannot be resolved.
func (r *Runner) RecordReloadFailure() { r.reloadRejected.Store(true) }

// currentConfig returns a copy of the current configuration.
func (r *Runner) currentConfig() Config {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return cloneConfig(r.cfg)
}

func cloneConfig(cfg Config) Config {
	cfg.Payloads = append([]string(nil), cfg.Payloads...)
	cfg.OperationWeights = copyFloat64Map(cfg.OperationWeights)
	cfg.Environment.ResourceLimits = copyFloat64Map(cfg.Environment.ResourceLimits)
	if cfg.ReplayIndex != nil {
		value := *cfg.ReplayIndex
		cfg.ReplayIndex = &value
	}
	if cfg.MaskFixtures != nil {
		fixtures := make([]MaskFixture, len(cfg.MaskFixtures))
		for i, fixture := range cfg.MaskFixtures {
			fixture.Spans = append([]MaskSpan(nil), fixture.Spans...)
			fixtures[i] = fixture
		}
		cfg.MaskFixtures = fixtures
	}
	return cfg
}

// Registry returns the per-run Prometheus registry.
func (r *Runner) Registry() *prometheus.Registry { return r.reg }

// Run paces requests until the context is cancelled or the configured duration
// elapses. When Enabled is false no new requests are planned, but the runner
// remains alive so a hot reload can enable it. On completion the report is
// computed from the bounded reservoir and atomic counters. The configuration
// is read on each planned tick, so a SetConfig update applies to new requests.
func (r *Runner) Run(ctx context.Context) (Report, error) {
	cfg := r.currentConfig()
	defer r.httpClient.CloseIdleConnections()
	requestsCtx, cancelRequests := context.WithCancel(ctx)
	defer cancelRequests()
	e := runnerExecution{
		runner: r, ctx: requestsCtx, initial: cfg, start: time.Now(),
		interval: operationIntervalFor(cfg), availability: &availabilityTracker{stop: cancelRequests},
	}
	e.ticker = r.newTicker(e.interval)
	defer e.stop()
	if real, ok := e.ticker.(*realTicker); ok {
		real.next = e.start.Add(e.interval)
	}
	e.resetDurationTimer(cfg.Duration)
	r.execution.Store(&e)
	e.schedule()
	e.ticker.Stop()
	e.wg.Wait()
	e.finishedAt.Store(time.Now().UnixNano())
	return e.report(ctx), nil
}

// runnerExecution owns the planning window. Workers drain after scheduling ends.
type runnerExecution struct {
	runner                   *Runner
	ctx                      context.Context
	initial                  Config
	start                    time.Time
	counts                   runCounters
	inflight                 atomic.Int64
	finishedAt               atomic.Int64
	wg                       sync.WaitGroup
	availability             *availabilityTracker
	ticker                   Ticker
	interval, activeDuration time.Duration
	durationTimer            *time.Timer
	durationC                <-chan time.Time
}

func (e *runnerExecution) stop() {
	e.ticker.Stop()
	if e.durationTimer != nil {
		e.durationTimer.Stop()
	}
}

func (e *runnerExecution) resetDurationTimer(next time.Duration) {
	if e.durationTimer != nil && !e.durationTimer.Stop() {
		select {
		case <-e.durationTimer.C:
		default:
		}
	}
	e.activeDuration = next
	if next <= 0 {
		e.durationC = nil
		return
	}
	remaining := max(time.Duration(0), time.Until(e.start.Add(next)))
	e.durationTimer = time.NewTimer(remaining)
	e.durationC = e.durationTimer.C
}

func (e *runnerExecution) plan(cfg Config, due int64) bool {
	if !cfg.Enabled || due == 0 {
		return false
	}
	if cfg.OperationLimit > 0 {
		remaining := cfg.OperationLimit - e.counts.planned.Load()
		if remaining <= 0 {
			return true
		}
		due = min(due, remaining)
	}
	first := e.counts.planned.Add(due) - due
	e.runner.met.requestsTotal.WithLabelValues("planned", cfg.Mode).Add(float64(due))
	limit := min(cfg.MaxInFlight, concurrencyOf(cfg))
	available := max(int64(0), int64(limit)-e.inflight.Load())
	launch := min(due, available)
	e.counts.dropped.Add(due - launch)
	e.runner.met.requestsTotal.WithLabelValues("dropped", cfg.Mode).Add(float64(due - launch))
	for slot := int64(0); slot < launch; slot++ {
		e.launch(first+slot, cfg)
	}
	return cfg.OperationLimit > 0 && e.counts.planned.Load() >= cfg.OperationLimit
}

func (e *runnerExecution) launch(idx int64, cfg Config) {
	e.counts.sent.Add(1)
	e.inflight.Add(1)
	e.runner.met.requestsTotal.WithLabelValues("sent", cfg.Mode).Inc()
	e.runner.met.inflight.WithLabelValues(cfg.Mode).Set(float64(e.inflight.Load()))
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		if cfg.ReplayIndex != nil {
			idx = *cfg.ReplayIndex
		}
		e.runner.sendOne(e.ctx, idx, cfg, &e.counts, &e.inflight, e.availability)
	}()
}

func (e *runnerExecution) schedule() {
	for {
		select {
		case <-e.ctx.Done():
			return
		case <-e.durationC:
			if e.durationElapsed() {
				return
			}
		case <-e.ticker.C():
			if e.tick() {
				return
			}
		}
	}
}

func (e *runnerExecution) durationElapsed() bool {
	cfg := e.runner.currentConfig()
	duration := cfg.Duration
	if duration <= 0 || time.Now().Before(e.start.Add(duration)) {
		e.resetDurationTimer(duration)
		return false
	}
	if real, ok := e.ticker.(*realTicker); ok {
		e.plan(cfg, real.Due(e.start.Add(duration)))
	}
	return true
}

func (e *runnerExecution) tick() bool {
	cfg := e.runner.currentConfig()
	now := time.Now()
	if cfg.Duration != e.activeDuration {
		e.resetDurationTimer(cfg.Duration)
	}
	finished := cfg.Duration > 0 && !now.Before(e.start.Add(cfg.Duration))
	if finished {
		now = e.start.Add(cfg.Duration)
	}
	due := e.ticker.Due(now)
	if !cfg.Enabled {
		return false
	}
	if interval := operationIntervalFor(cfg); interval != e.interval {
		e.interval = interval
		e.ticker.Stop()
		e.ticker = e.runner.newTicker(interval)
	}
	return e.plan(cfg, due) || finished
}

func (e *runnerExecution) report(ctx context.Context) Report {
	r, start := e.runner, e.start
	counts, availability := &e.counts, e.availability
	finishedAt := time.Now()
	elapsed := finishedAt.Sub(start)
	if elapsed < 0 {
		elapsed = 0
	}
	finalCfg := r.currentConfig()
	cfg := e.initial
	report := Report{
		SchemaVersion:    "alfagen.load.v1",
		RunID:            cfg.RunID,
		CommitSHA:        cfg.CommitSHA,
		ImageTag:         cfg.ImageTag,
		StartedAt:        start.UTC(),
		FinishedAt:       finishedAt.UTC(),
		Environment:      normalizedEnvironment(cfg.Environment),
		ConfigVersion:    finalCfg.Version,
		Mode:             cfg.Mode,
		Scenario:         scenarioOf(cfg),
		Seed:             cfg.Seed,
		Profile:          cfg.PayloadProfile,
		Planned:          counts.planned.Load(),
		Sent:             counts.sent.Load(),
		Dropped:          counts.dropped.Load(),
		Success:          counts.success.Load(),
		Failed:           counts.failed.Load(),
		Duration:         elapsed,
		TargetRPS:        cfg.RatePerSecond,
		DatasetSHA256:    cfg.DatasetSHA256,
		IDNamespace:      cfg.IDNamespace,
		HTTPRequests:     counts.httpRequests.Load(),
		Retries:          counts.retries.Load(),
		FinalRateLimited: counts.final429.Load(),
		CompletedPairs:   counts.completedPairs.Load(),
	}
	var stopped bool
	report.MaxInvalidStreak, stopped = availability.snapshot()
	if stopped {
		report.StopReason = "five_consecutive_invalid"
	}
	if elapsed > 0 {
		report.SuccessfulRPS = float64(counts.success.Load()) / elapsed.Seconds()
		report.HTTPRPS = float64(counts.httpRequests.Load()) / elapsed.Seconds()
	}
	report.P50, report.P95, report.P99, report.Max = r.res.percentiles()
	report.HTTPStatus, report.Errors = r.outcomes.snapshot()
	report.QualityEvaluated, report.MaskDistanceMean, report.MaskDistanceMax, report.EvaluatedCategories = r.quality.snapshot()
	report.Parameters = ReportParameters{
		TargetRPS: cfg.RatePerSecond, DurationSeconds: cfg.Duration.Seconds(),
		Concurrency: concurrencyOf(cfg), MaxInFlight: cfg.MaxInFlight,
		MaxConnections:   cfg.MaxConnections,
		RequestTimeoutMS: cfg.RequestTimeout.Milliseconds(), PayloadProfile: cfg.PayloadProfile,
		OperationWeights: normalizedWeights(cfg),
	}
	report.Counts = ReportCounts{
		PlannedOperations: report.Planned, SentRequests: report.HTTPRequests,
		DroppedOperations: report.Dropped, SuccessfulOperations: report.Success,
		FailedOperations: report.Failed, Timeouts: counts.timeouts.Load(),
		HTTPRequests: report.HTTPRequests, CompletedPairs: report.CompletedPairs,
		Retries: report.Retries, FinalRateLimited: report.FinalRateLimited,
		MaxInvalidStreak: report.MaxInvalidStreak,
	}
	report.HTTPStatuses = copyInt64Map(report.HTTPStatus)
	target := time.Second
	if report.LatencyTarget > 0 {
		target = report.LatencyTarget
	}
	report.LatencyTarget = target
	report.LatencyTargetMet = report.P95 <= target
	report.LatencyMS = ReportLatency{
		P50: durationMilliseconds(report.P50), P95: durationMilliseconds(report.P95),
		P99: durationMilliseconds(report.P99), Max: durationMilliseconds(report.Max),
		Target: durationMilliseconds(target), TargetMet: report.LatencyTargetMet,
	}
	switch {
	case ctx.Err() != nil:
		report.Verdict = "CANCELLED"
	case report.Failed > 0 || report.Dropped > 0 || report.Success == 0:
		report.Verdict = "HARNESS_ERROR"
	default:
		report.Verdict = "PASS"
	}
	return report
}

func concurrencyOf(cfg Config) int {
	if cfg.Concurrency > 0 {
		return cfg.Concurrency
	}
	return cfg.MaxInFlight
}

func normalizedEnvironment(environment ReportEnvironment) ReportEnvironment {
	if environment.Runner == "" {
		environment.Runner = "same_vps"
	}
	if environment.Host == "" {
		environment.Host = "local"
	}
	if environment.ResourceLimits == nil {
		environment.ResourceLimits = map[string]float64{}
	}
	return environment
}

func normalizedWeights(cfg Config) map[string]float64 {
	if scenarioOf(cfg) != ScenarioMixed {
		return map[string]float64{}
	}
	weights := make(map[string]float64, len(cfg.OperationWeights))
	total := 0.0
	ordered := []string{ScenarioMaskOnly, ScenarioRoundTrip, ScenarioStableRetry, ScenarioExpectedConflict}
	for _, key := range ordered {
		total += cfg.OperationWeights[key]
	}
	for _, key := range ordered {
		weights[key] = cfg.OperationWeights[key] / total
	}
	return weights
}

func copyInt64Map(source map[string]int64) map[string]int64 {
	copy := make(map[string]int64, len(source))
	for key, value := range source {
		copy[key] = value
	}
	return copy
}

func durationMilliseconds(value time.Duration) float64 {
	return float64(value) / float64(time.Millisecond)
}

func intervalFor(rate float64) time.Duration {
	return time.Duration(float64(time.Second) / rate)
}

func operationIntervalFor(cfg Config) time.Duration {
	rate := cfg.RatePerSecond
	expectedRequests := expectedRequestsPerOperation(cfg)
	if expectedRequests > 1 {
		// Planning accounts for every request in a logical operation. Retries are
		// additionally governed by the shared request pacer.
		rate /= expectedRequests
	}
	return intervalFor(rate)
}

func expectedRequestsPerOperation(cfg Config) float64 {
	switch scenarioOf(cfg) {
	case ScenarioRoundTrip, ScenarioStableRetry:
		return 2
	case ScenarioExpectedConflict:
		return 3
	case ScenarioMixed:
		weights := normalizedWeights(cfg)
		return weights[ScenarioMaskOnly] + 2*weights[ScenarioRoundTrip] + 2*weights[ScenarioStableRetry] + 3*weights[ScenarioExpectedConflict]
	default:
		return 1
	}
}

// sendOne builds a deterministic request for the planned index, sends it and
// records the outcome. The payload, operation ID and profile are derived only
// from the seed, run namespace and ordinal planned index.
func (r *Runner) sendOne(ctx context.Context, idx int64, cfg Config, counts *runCounters, inflight *atomic.Int64, availability *availabilityTracker) {
	defer func() {
		inflight.Add(-1)
		r.met.inflight.WithLabelValues(cfg.Mode).Set(float64(inflight.Load()))
	}()
	operationOK := false
	scenario := operationScenario(idx, cfg)
	switch scenario {
	case ScenarioRoundTrip:
		operationOK = r.sendRoundTrip(ctx, idx, cfg, counts, availability)
	case ScenarioMaskOnly:
		operationOK = r.sendMaskOnly(ctx, idx, cfg, counts, availability)
	case ScenarioStableRetry:
		operationOK = r.sendStableRetry(ctx, idx, cfg, counts, availability)
	case ScenarioExpectedConflict:
		operationOK = r.sendExpectedConflict(ctx, idx, cfg, counts, availability)
	default:
		body, _ := r.buildRequest(idx, cfg)
		result := r.sendHTTP(ctx, body, cfg, counts, false)
		availability.record(result.disposition)
		operationOK = result.disposition == dispositionSuccess
	}
	stage := "failed"
	if operationOK {
		counts.success.Add(1)
		stage = "success"
	} else {
		counts.failed.Add(1)
	}
	r.met.requestsTotal.WithLabelValues(stage, cfg.Mode).Inc()
}

func operationScenario(idx int64, cfg Config) string {
	if scenarioOf(cfg) != ScenarioMixed {
		return scenarioOf(cfg)
	}
	value := rand.New(rand.NewSource(cfg.Seed + idx*7919)).Float64()
	weights := normalizedWeights(cfg)
	for _, scenario := range []string{ScenarioMaskOnly, ScenarioRoundTrip, ScenarioStableRetry, ScenarioExpectedConflict} {
		value -= weights[scenario]
		if value < 0 {
			return scenario
		}
	}
	return ScenarioExpectedConflict
}

// fixtureFor picks the payload for a stateful scenario operation
// (round_trip/mask_only/stable_retry/expected_conflict). Priority: an
// explicit -mask-dataset (cfg.MaskFixtures) always wins, since it carries
// quality-eval ExpectedMask/Spans that a raw dataset entry does not; then a
// plain -dataset (cfg.Payloads), matching the priority buildRequest already
// uses for the default/request scenarios; only with neither does it fall
// back to the short synthetic generator.
func (r *Runner) fixtureFor(idx int64, cfg Config) MaskFixture {
	if len(cfg.MaskFixtures) > 0 {
		return cfg.MaskFixtures[idx%int64(len(cfg.MaskFixtures))]
	}
	if len(cfg.Payloads) > 0 {
		return MaskFixture{Name: "dataset", Payload: cfg.Payloads[idx%int64(len(cfg.Payloads))], allowUnchanged: true}
	}
	rng := rand.New(rand.NewSource(cfg.Seed + idx))
	return MaskFixture{Name: "synthetic", Payload: payloadFor(cfg.PayloadProfile, rng)}
}

func (r *Runner) sendMaskOnly(ctx context.Context, idx int64, cfg Config, counts *runCounters, availability *availabilityTracker) bool {
	fixture := r.fixtureFor(idx, cfg)
	body, _ := json.Marshal(map[string]string{"payload": fixture.Payload, "payload_id": r.operationID(idx, cfg)})
	result := r.sendHTTP(ctx, body, cfg, counts, true)
	if result.disposition != dispositionSuccess {
		availability.record(result.disposition)
		return false
	}
	masked, err := decodeProcessResult(result.body)
	if err != nil || fixture.rejectsUnchanged(masked) {
		category := "response_json"
		if err == nil {
			category = "mask_unchanged"
		}
		r.recordError(category, cfg.Mode)
		availability.record(dispositionInvalid)
		return false
	}
	availability.record(dispositionSuccess)
	return true
}

func (r *Runner) sendStableRetry(ctx context.Context, idx int64, cfg Config, counts *runCounters, availability *availabilityTracker) bool {
	fixture := r.fixtureFor(idx, cfg)
	body, _ := json.Marshal(map[string]string{"payload": fixture.Payload, "payload_id": r.operationID(idx, cfg)})
	first := r.sendHTTP(ctx, body, cfg, counts, true)
	if first.disposition != dispositionSuccess {
		availability.record(first.disposition)
		return false
	}
	firstMask, err := decodeProcessResult(first.body)
	if err != nil || fixture.rejectsUnchanged(firstMask) {
		r.recordError("stable_retry_first", cfg.Mode)
		availability.record(dispositionInvalid)
		return false
	}
	availability.record(dispositionSuccess)
	second := r.sendHTTP(ctx, body, cfg, counts, true)
	if second.disposition != dispositionSuccess {
		availability.record(second.disposition)
		return false
	}
	secondMask, err := decodeProcessResult(second.body)
	if err != nil || secondMask != firstMask {
		r.recordError("stable_retry_mismatch", cfg.Mode)
		availability.record(dispositionInvalid)
		return false
	}
	availability.record(dispositionSuccess)
	return true
}

func (r *Runner) sendExpectedConflict(ctx context.Context, idx int64, cfg Config, counts *runCounters, availability *availabilityTracker) bool {
	fixture := r.fixtureFor(idx, cfg)
	id := r.operationID(idx, cfg)
	body, _ := json.Marshal(map[string]string{"payload": fixture.Payload, "payload_id": id})
	first := r.sendHTTP(ctx, body, cfg, counts, true)
	if first.disposition != dispositionSuccess {
		availability.record(first.disposition)
		return false
	}
	firstMask, err := decodeProcessResult(first.body)
	if err != nil || fixture.rejectsUnchanged(firstMask) {
		r.recordError("conflict_first", cfg.Mode)
		availability.record(dispositionInvalid)
		return false
	}
	availability.record(dispositionSuccess)
	second := r.sendHTTP(ctx, body, cfg, counts, true)
	if second.disposition != dispositionSuccess {
		availability.record(second.disposition)
		return false
	}
	secondMask, err := decodeProcessResult(second.body)
	if err != nil || secondMask != firstMask {
		r.recordError("conflict_stability", cfg.Mode)
		availability.record(dispositionInvalid)
		return false
	}
	availability.record(dispositionSuccess)
	conflictBody, _ := json.Marshal(map[string]string{"payload": fixture.Payload + " [synthetic conflict]", "payload_id": id})
	conflict := r.sendHTTPExpected(ctx, conflictBody, cfg, counts, false, http.StatusConflict)
	availability.record(conflict.disposition)
	if conflict.disposition != dispositionSuccess {
		r.recordError("expected_conflict", cfg.Mode)
		return false
	}
	return true
}

func (r *Runner) sendRoundTrip(ctx context.Context, idx int64, cfg Config, counts *runCounters, availability *availabilityTracker) bool {
	fixture := r.fixtureFor(idx, cfg)
	id := r.operationID(idx, cfg)
	maskBody, _ := json.Marshal(map[string]string{"payload": fixture.Payload, "payload_id": id})
	maskResult := r.sendHTTP(ctx, maskBody, cfg, counts, true)
	if maskResult.disposition != dispositionSuccess {
		availability.record(maskResult.disposition)
		return false
	}
	actualMask, err := decodeProcessResult(maskResult.body)
	if err != nil {
		r.recordError("response_json", cfg.Mode)
		availability.record(dispositionInvalid)
		return false
	}
	if fixture.ExpectedMask == "" && fixture.rejectsUnchanged(actualMask) {
		r.recordError("mask_unchanged", cfg.Mode)
		availability.record(dispositionInvalid)
		return false
	}
	if fixture.ExpectedMask != "" {
		distance, err := NormalizedSpanLevenshtein(fixture, actualMask)
		if err != nil {
			r.recordError("quality", cfg.Mode)
			availability.record(dispositionInvalid)
			return false
		}
		r.quality.record(distance, fixture.Spans)
		r.met.maskDistance.Observe(distance)
	} else {
		r.quality.recordCategories(fixture.Spans)
	}
	availability.record(dispositionSuccess)

	demaskBody, _ := json.Marshal(map[string]string{"payload": actualMask, "payload_id": id})
	demaskResult := r.sendHTTP(ctx, demaskBody, cfg, counts, true)
	if demaskResult.disposition != dispositionSuccess {
		availability.record(demaskResult.disposition)
		return false
	}
	restored, err := decodeProcessResult(demaskResult.body)
	if err != nil {
		r.recordError("response_json", cfg.Mode)
		availability.record(dispositionInvalid)
		return false
	}
	if restored != fixture.Payload {
		r.recordError("demask_mismatch", cfg.Mode)
		availability.record(dispositionInvalid)
		return false
	}
	availability.record(dispositionSuccess)
	counts.completedPairs.Add(1)
	r.met.completedPairs.Inc()
	return true
}

func decodeProcessResult(raw []byte) (string, error) {
	var response struct {
		Result *string `json:"result"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&response); err != nil || response.Result == nil {
		return "", errors.New("invalid process response")
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return "", errors.New("invalid process response")
	}
	return *response.Result, nil
}

func (r *Runner) sendHTTP(ctx context.Context, body []byte, cfg Config, counts *runCounters, captureResponse bool) requestResult {
	return r.sendHTTPExpected(ctx, body, cfg, counts, captureResponse, http.StatusOK)
}

func (r *Runner) sendHTTPExpected(ctx context.Context, body []byte, cfg Config, counts *runCounters, captureResponse bool, expectedStatus int) requestResult {
	for attempt := 1; attempt <= requestAttemptsLimit; attempt++ {
		if err := r.pacer.wait(ctx, cfg.RatePerSecond, r.now, r.wait); err != nil {
			return requestResult{disposition: dispositionCancelled}
		}
		result, retryable, retryAfter := r.sendAttempt(ctx, body, cfg, counts, captureResponse, expectedStatus)
		if !retryable || attempt == requestAttemptsLimit {
			if result.disposition == dispositionRateLimited {
				counts.final429.Add(1)
				r.recordError("final_rate_limited", cfg.Mode)
			}
			return result
		}
		if result.disposition != dispositionRateLimited && retryAfter <= 0 {
			retryAfter = time.Duration(attempt) * firstTransientRetryBackoff
		}
		if err := r.wait(ctx, retryAfter); err != nil {
			return requestResult{disposition: dispositionCancelled}
		}
		counts.retries.Add(1)
		r.met.requestsTotal.WithLabelValues("retry", cfg.Mode).Inc()
	}
	return requestResult{disposition: dispositionInvalid}
}

func (r *Runner) sendAttempt(ctx context.Context, body []byte, cfg Config, counts *runCounters, captureResponse bool, expectedStatus int) (requestResult, bool, time.Duration) {
	requestCtx, cancel := context.WithTimeout(ctx, cfg.RequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, cfg.TargetURL, bytes.NewReader(body))
	if err != nil {
		r.recordError("build", cfg.Mode)
		return requestResult{disposition: dispositionInvalid}, false, 0
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-System-ID", cfg.SystemID)
	if cfg.APIKey != "" {
		req.Header.Set("X-API-Key", cfg.APIKey)
	}
	counts.httpRequests.Add(1)
	r.met.requestsTotal.WithLabelValues("http", cfg.Mode).Inc()
	start := r.now()
	resp, err := r.httpClient.Do(req)
	dur := r.now().Sub(start)
	if err != nil {
		return r.attemptTransportError(ctx, err, cfg.Mode, counts, dur)
	}
	var raw []byte
	var readBytes int64
	var readErr error
	if captureResponse {
		raw, readErr = io.ReadAll(io.LimitReader(resp.Body, (4<<20)+1))
		readBytes = int64(len(raw))
	} else {
		readBytes, readErr = io.Copy(io.Discard, io.LimitReader(resp.Body, (4<<20)+1))
	}
	_ = resp.Body.Close()
	dur = r.now().Sub(start)
	r.met.duration.WithLabelValues(cfg.Mode).Observe(dur.Seconds())
	status := strconv.Itoa(resp.StatusCode)
	r.met.statusTotal.WithLabelValues(status, cfg.Mode).Inc()
	r.met.statusClass.WithLabelValues(fmt.Sprintf("%dxx", resp.StatusCode/100), cfg.Mode).Inc()
	r.outcomes.recordStatus(status)
	r.res.record(dur)
	if resp.StatusCode == http.StatusTooManyRequests {
		if readErr != nil || readBytes > 4<<20 {
			r.recordError("response_body", cfg.Mode)
		}
		r.recordError("http_status", cfg.Mode)
		return requestResult{body: raw, disposition: dispositionRateLimited}, true, parseRetryAfter(resp.Header.Get("Retry-After"), r.now())
	}
	if readErr != nil || readBytes > 4<<20 {
		r.recordError("response_body", cfg.Mode)
		return requestResult{disposition: dispositionInvalid}, true, 0
	}
	if resp.StatusCode == expectedStatus {
		return requestResult{body: raw, disposition: dispositionSuccess}, false, 0
	}
	r.recordError("http_status", cfg.Mode)
	if resp.StatusCode >= 500 {
		return requestResult{body: raw, disposition: dispositionInvalid}, true, 0
	}
	return requestResult{body: raw, disposition: dispositionInvalid}, false, 0
}

func parseRetryAfter(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil && seconds >= 0 {
		return time.Duration(seconds) * time.Second
	}
	if at, err := http.ParseTime(value); err == nil {
		if delay := at.Sub(now); delay > 0 {
			return delay
		}
		return 0
	}
	return defaultRetryAfter
}

func (r *Runner) recordError(category, mode string) {
	r.outcomes.recordError(category)
	r.met.errorsTotal.WithLabelValues(category, mode).Inc()
}

func (o *outcomeCounts) recordStatus(status string) {
	o.mu.Lock()
	o.httpStatus[status]++
	o.mu.Unlock()
}

func (o *outcomeCounts) recordError(category string) {
	o.mu.Lock()
	o.errors[category]++
	o.mu.Unlock()
}

func (o *outcomeCounts) snapshot() (map[string]int64, map[string]int64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	statuses := make(map[string]int64, len(o.httpStatus))
	for key, value := range o.httpStatus {
		statuses[key] = value
	}
	errorsByCategory := make(map[string]int64, len(o.errors))
	for key, value := range o.errors {
		errorsByCategory[key] = value
	}
	return statuses, errorsByCategory
}

// buildRequest returns the JSON body and the deterministic operation ID for a
// planned index. The generator is seeded by seed+index so the same seed and
// index and namespace always produce the same payload and ID.
func (r *Runner) buildRequest(idx int64, cfg Config) ([]byte, string) {
	opID := r.operationID(idx, cfg)
	var payload string
	if len(cfg.Payloads) > 0 {
		payload = cfg.Payloads[idx%int64(len(cfg.Payloads))]
	} else {
		payload = payloadFor(cfg.PayloadProfile, rand.New(rand.NewSource(cfg.Seed+idx)))
	}
	switch cfg.Mode {
	case ModeGenerate:
		body, _ := json.Marshal(map[string]string{
			"request_id": opID,
			"model":      "mock",
			"text":       payload,
		})
		return body, opID
	default:
		body, _ := json.Marshal(map[string]string{
			"payload":    payload,
			"payload_id": opID,
		})
		return body, opID
	}
}

func (r *Runner) operationID(idx int64, cfg Config) string {
	id := fmt.Sprintf("op-%s-%s-%s-%d-%d", cfg.Mode, scenarioOf(cfg), cfg.PayloadProfile, cfg.Seed, idx)
	if cfg.IDNamespace != "" {
		id = cfg.IDNamespace + "-" + id
	}
	if cfg.DatasetSHA256 != "" {
		id += "-" + cfg.DatasetSHA256
	}
	return id
}

// payloadFor returns a deterministic synthetic payload for a profile. Only
// synthetic values are used; no real personal data is ever generated.
func payloadFor(profile string, rng *rand.Rand) string {
	switch profile {
	case "large", "long", "long-100k":
		return longPayload(rng)
	case "medium":
		var b strings.Builder
		for i := 0; i < 24; i++ {
			b.WriteString(shortPayload(rng))
			b.WriteByte(' ')
		}
		return b.String()
	default:
		return shortPayload(rng)
	}
}

func shortPayload(rng *rand.Rand) string {
	names := []string{"Иванов Иван Иванович", "Петрова Анна Сергеевна", "Сидоров Пётр Алексеевич"}
	emails := []string{"demo@example.test", "user@example.test", "test@example.test"}
	phones := []string{"+7 (999) 123-45-67", "+7 (495) 000-11-22", "+7 (812) 333-44-55"}
	n := names[rng.Intn(len(names))]
	e := emails[rng.Intn(len(emails))]
	p := phones[rng.Intn(len(phones))]
	return fmt.Sprintf("Клиент %s, телефон %s, email %s", n, p, e)
}

func longPayload(rng *rand.Rand) string {
	var b bytes.Buffer
	// Approximately 450 KiB UTF-8 is the agreed synthetic 100k-token-
	// equivalent profile. It is deliberately not claimed to equal the token
	// count of any production model tokenizer.
	for b.Len() < 450*1024 {
		b.WriteString(shortPayload(rng))
		b.WriteByte(' ')
	}
	return b.String()
}

// reservoir is a bounded latency sample with random replacement. It never
// grows beyond its capacity, so a continuous process does not accumulate every
// request latency indefinitely.
type reservoir struct {
	mu      sync.Mutex
	size    int
	count   int
	max     time.Duration
	samples []time.Duration
	rng     *rand.Rand
}

func newReservoir(size int) *reservoir {
	return &reservoir{size: size, rng: rand.New(rand.NewSource(1))}
}

func (r *reservoir) record(d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.count++
	if d > r.max {
		r.max = d
	}
	if len(r.samples) < r.size {
		r.samples = append(r.samples, d)
		return
	}
	if j := r.rng.Intn(r.count); j < r.size {
		r.samples[j] = d
	}
}

func (r *reservoir) percentiles() (p50, p95, p99, max time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.samples) == 0 {
		return 0, 0, 0, 0
	}
	sorted := append([]time.Duration(nil), r.samples...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	max = r.max
	p50 = sorted[quantileIndex(len(sorted), 0.50)]
	p95 = sorted[quantileIndex(len(sorted), 0.95)]
	p99 = sorted[quantileIndex(len(sorted), 0.99)]
	return p50, p95, p99, max
}

func quantileIndex(n int, q float64) int {
	i := int(float64(n) * q)
	if i >= n {
		return n - 1
	}
	return i
}

func (r *Runner) attemptTransportError(ctx context.Context, err error, mode string, counts *runCounters, dur time.Duration) (requestResult, bool, time.Duration) {
	r.res.record(dur)
	category := "transport"
	disposition := dispositionInvalid
	retryable := true
	if errors.Is(err, context.DeadlineExceeded) {
		category = "timeout"
		counts.timeouts.Add(1)
	} else if errors.Is(err, context.Canceled) || ctx.Err() != nil {
		category = "cancelled"
		disposition = dispositionCancelled
		retryable = false
	}
	r.recordError(category, mode)
	return requestResult{disposition: disposition}, retryable, 0
}
