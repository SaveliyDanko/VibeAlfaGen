// Package client contains the finite smoke/load client. Continuous pacing and
// configuration reload are separate workflow tasks; this is not an SLA harness.
package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

type Options struct {
	URL, Payload, SystemID, APIKey string
	Concurrency, Total             int

	Version          string
	Mode             string
	Scenario         string
	Seed             int64
	TargetRPS        float64
	Duration         time.Duration
	MaxInFlight      int
	RequestTimeout   time.Duration
	PayloadProfile   string
	OperationWeights map[string]float64
	CommitSHA        string
	ImageTag         string
	RunID            string
	ReplayIndex      *int64
	Environment      ReportEnvironment
	MaskFixtures     []MaskFixture
	Payloads         []string
	DatasetSHA256    string
}

// RunReport executes the paced runner and returns a canonical alfagen.load.v1
// report. Run remains the finite compatibility entry point.
func RunReport(ctx context.Context, opts Options) (Report, error) {
	mode := opts.Mode
	if mode == "" {
		mode = ModeProcess
	}
	scenario := opts.Scenario
	if scenario == "" {
		scenario = ScenarioMaskOnly
	}
	rate := opts.TargetRPS
	if rate == 0 {
		rate = 1000
	}
	concurrency := opts.Concurrency
	if concurrency == 0 {
		concurrency = 256
	}
	maxInFlight := opts.MaxInFlight
	if maxInFlight == 0 {
		maxInFlight = concurrency
	}
	timeout := opts.RequestTimeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	profile := opts.PayloadProfile
	if profile == "" {
		profile = "small"
	}
	runID := opts.RunID
	if runID == "" {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return Report{}, fmt.Errorf("create run ID: %w", err)
		}
		runID = fmt.Sprintf("synthetic-%x", nonce[:])
	}
	fixtures := append([]MaskFixture(nil), opts.MaskFixtures...)
	if len(fixtures) == 0 && opts.Payload != "" && mode == ModeProcess && scenario != ScenarioRequest {
		fixtures = []MaskFixture{{Name: "synthetic", Payload: opts.Payload}}
	}
	operationLimit := int64(opts.Total)
	if opts.ReplayIndex != nil {
		operationLimit = 1
	}
	runner, err := NewRunner(Config{
		Version: opts.Version, Mode: mode, Scenario: scenario, TargetURL: opts.URL,
		Seed: opts.Seed, RatePerSecond: rate, Concurrency: concurrency,
		MaxInFlight: maxInFlight, RequestTimeout: timeout, Duration: opts.Duration,
		OperationLimit: operationLimit, PayloadProfile: profile, SystemID: opts.SystemID,
		APIKey: opts.APIKey, Enabled: true, OperationWeights: opts.OperationWeights,
		CommitSHA: opts.CommitSHA, ImageTag: opts.ImageTag, RunID: runID,
		ReplayIndex: opts.ReplayIndex, Environment: opts.Environment,
		MaskFixtures: fixtures, Payloads: append([]string(nil), opts.Payloads...),
		DatasetSHA256: opts.DatasetSHA256, IDNamespace: runID,
	})
	if err != nil {
		return Report{}, err
	}
	return runner.Run(ctx)
}

// WriteJSON writes one strictly validated alfagen.load.v1 document.
func WriteJSON(w io.Writer, report Report) error {
	if err := validateReport(report); err != nil {
		return err
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	return enc.Encode(report)
}

func validateReport(report Report) error {
	if report.SchemaVersion != "alfagen.load.v1" {
		return errors.New("load report: unsupported schema_version")
	}
	if report.RunID == "" || report.Scenario == "" || report.StartedAt.IsZero() || report.FinishedAt.IsZero() || report.FinishedAt.Before(report.StartedAt) {
		return errors.New("load report: invalid identity or timestamps")
	}
	switch report.Verdict {
	case "PASS", "SLO_MISSED", "HARNESS_ERROR", "CANCELLED":
	default:
		return errors.New("load report: invalid verdict")
	}
	if err := validateReportMeasures(report); err != nil {
		return err
	}
	if report.Environment.Runner != "external" && report.Environment.Runner != "same_vps" {
		return errors.New("load report: environment.runner must be external or same_vps")
	}
	for _, value := range report.Environment.ResourceLimits {
		if value < 0 || math.IsNaN(value) || math.IsInf(value, 0) {
			return errors.New("load report: invalid resource limit")
		}
	}
	return nil
}

func Run(ctx context.Context, opts Options, out io.Writer) error {
	if opts.Concurrency <= 0 || opts.Total <= 0 {
		return fmt.Errorf("positive concurrency and request count required")
	}
	client := &http.Client{}
	defer client.CloseIdleConnections()
	var wg sync.WaitGroup
	var counts finiteCounts
	jobs := make(chan int)
	start := time.Now()
	runID := fmt.Sprintf("load-%d", start.UnixNano())
	runCtx, stop := context.WithCancel(ctx)
	defer stop()
	availability := &availabilityTracker{stop: stop}
	for worker := 0; worker < opts.Concurrency; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				counts.request(runCtx, client, opts, runID, i, availability)
			}
		}()
	}
feed:
	for i := 0; i < opts.Total; i++ {
		select {
		case jobs <- i:
		case <-runCtx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()
	elapsed := time.Since(start)
	fmt.Fprintf(out, "sent=%d attempts=%d retries=%d final_429=%d successful=%d failed=%d elapsed=%s successful_rps=%.2f\n", counts.success.Load()+counts.failed.Load(), counts.attempts.Load(), counts.retries.Load(), counts.final429.Load(), counts.success.Load(), counts.failed.Load(), elapsed, float64(counts.success.Load())/elapsed.Seconds())
	if counts.success.Load() > 0 {
		fmt.Fprintf(out, "successful_avg_latency_ms=%.2f\n", float64(counts.totalLatency.Load())/float64(counts.success.Load())/1e6)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if _, stopped := availability.snapshot(); stopped {
		return fmt.Errorf("load stopped after five consecutive invalid requests")
	}
	if counts.failed.Load() > 0 {
		return fmt.Errorf("load run had failed requests")
	}
	return nil
}

func finiteRequest(ctx context.Context, client *http.Client, opts Options, body []byte) (requestDisposition, int, int, bool, time.Duration) {
	var totalLatency time.Duration
	retries := 0
	for attempt := 1; attempt <= requestAttemptsLimit; attempt++ {
		result := finiteAttempt(ctx, client, opts, body)
		totalLatency += result.latency
		if !result.sent {
			return result.disposition, attempt - 1, retries, false, totalLatency
		}
		if !result.retryable || attempt == requestAttemptsLimit {
			return result.disposition, attempt, retries, result.disposition == dispositionRateLimited, totalLatency
		}
		delay := time.Duration(attempt) * firstTransientRetryBackoff
		if result.disposition == dispositionRateLimited {
			delay = result.retryAfter
		}
		if waitFiniteRetry(ctx, delay) != nil {
			return dispositionCancelled, attempt, retries, false, totalLatency
		}
		retries++
	}
	return dispositionInvalid, requestAttemptsLimit, retries, false, totalLatency
}

type finiteAttemptResult struct {
	disposition         requestDisposition
	sent, retryable     bool
	latency, retryAfter time.Duration
}

func finiteAttempt(ctx context.Context, client *http.Client, opts Options, body []byte) finiteAttemptResult {
	attemptCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(attemptCtx, http.MethodPost, opts.URL, bytes.NewReader(body))
	if err != nil {
		return finiteAttemptResult{disposition: dispositionInvalid}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-System-ID", opts.SystemID)
	req.Header.Set("X-API-Key", opts.APIKey)
	started := time.Now()
	resp, err := client.Do(req)
	result := finiteAttemptResult{sent: true, latency: time.Since(started), disposition: dispositionInvalid}
	if err != nil {
		result.retryable = true
		if errors.Is(err, context.Canceled) || ctx.Err() != nil {
			result.disposition, result.retryable = dispositionCancelled, false
		}
		return result
	}
	readBytes, readErr := io.Copy(io.Discard, io.LimitReader(resp.Body, (4<<20)+1))
	// The body has been consumed or rejected; closing only releases the transport.
	_ = resp.Body.Close()
	return classifyFiniteResponse(result, resp, readBytes, readErr)
}

func classifyFiniteResponse(result finiteAttemptResult, resp *http.Response, readBytes int64, readErr error) finiteAttemptResult {
	bodyOK := readErr == nil && readBytes <= 4<<20
	if bodyOK && resp.StatusCode == http.StatusOK {
		result.disposition = dispositionSuccess
		return result
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		result.disposition, result.retryable = dispositionRateLimited, true
		result.retryAfter = parseRetryAfter(resp.Header.Get("Retry-After"), time.Now())
		return result
	}
	result.retryable = !bodyOK || resp.StatusCode >= 500
	return result
}

func waitFiniteRetry(ctx context.Context, delay time.Duration) error {
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
}

func validateReportMeasures(report Report) error {
	numbers := []float64{
		report.Parameters.TargetRPS, report.Parameters.DurationSeconds,
		report.LatencyMS.P50, report.LatencyMS.P95, report.LatencyMS.P99,
		report.LatencyMS.Max, report.LatencyMS.Target,
	}
	for _, value := range numbers {
		if value < 0 || math.IsNaN(value) || math.IsInf(value, 0) {
			return errors.New("load report: numeric values must be finite and non-negative")
		}
	}
	if report.Parameters.Concurrency <= 0 || report.Parameters.MaxInFlight <= 0 || report.Parameters.MaxConnections < 0 || report.Parameters.RequestTimeoutMS <= 0 || report.Parameters.PayloadProfile == "" {
		return errors.New("load report: invalid parameters")
	}
	counts := report.Counts
	if counts.PlannedOperations < 0 || counts.SentRequests < 0 || counts.DroppedOperations < 0 || counts.SuccessfulOperations < 0 || counts.FailedOperations < 0 || counts.Timeouts < 0 || counts.HTTPRequests < 0 || counts.CompletedPairs < 0 || counts.Retries < 0 || counts.FinalRateLimited < 0 || counts.MaxInvalidStreak < 0 {
		return errors.New("load report: counts must not be negative")
	}
	for key, value := range report.HTTPStatuses {
		if key == "" || value < 0 {
			return errors.New("load report: invalid status counts")
		}
	}
	return nil
}

type finiteCounts struct{ success, failed, attempts, retries, final429, totalLatency atomic.Int64 }

func (c *finiteCounts) request(runCtx context.Context, client *http.Client, opts Options, runID string, i int, availability *availabilityTracker) {
	body, _ := json.Marshal(map[string]string{"payload": opts.Payload, "payload_id": fmt.Sprintf("%s-%d", runID, i)})
	disposition, usedAttempts, usedRetries, wasFinal429, latency := finiteRequest(runCtx, client, opts, body)
	c.attempts.Add(int64(usedAttempts))
	c.retries.Add(int64(usedRetries))
	if wasFinal429 {
		c.final429.Add(1)
	}
	availability.record(disposition)
	if disposition == dispositionSuccess {
		c.success.Add(1)
		c.totalLatency.Add(latency.Nanoseconds())
	} else if disposition != dispositionCancelled {
		c.failed.Add(1)
	}
}
