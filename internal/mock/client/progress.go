package client

import "time"

// RunProgress is a bounded, payload-free live snapshot, separate from the final
// alfagen.load.v1 report. Counters may advance while a snapshot is being read.
type RunProgress struct {
	RunID           string           `json:"run_id"`
	ConfigVersion   string           `json:"config_version"`
	ReloadRejected  bool             `json:"reload_rejected"`
	StartedAt       time.Time        `json:"started_at"`
	ElapsedSeconds  float64          `json:"elapsed_seconds"`
	DurationSeconds float64          `json:"duration_seconds"`
	OperationLimit  int64            `json:"operation_limit"`
	TargetRPS       float64          `json:"target_rps"`
	HTTPRPS         float64          `json:"http_rps"`
	SuccessfulRPS   float64          `json:"successful_rps"`
	InFlight        int64            `json:"in_flight"`
	Counts          ReportCounts     `json:"counts"`
	LatencyMS       ReportLatency    `json:"latency_ms"`
	HTTPStatuses    map[string]int64 `json:"http_statuses"`
}

// Progress is safe to read concurrently with Run and SetConfig.
func (r *Runner) Progress() *RunProgress {
	e := r.execution.Load()
	if e == nil {
		return nil
	}
	end := time.Now()
	if finished := e.finishedAt.Load(); finished != 0 {
		end = time.Unix(0, finished)
	}
	cfg, c := r.currentConfig(), &e.counts
	p := &RunProgress{
		RunID: e.initial.RunID, StartedAt: e.start.UTC(),
		ConfigVersion: cfg.Version, ReloadRejected: r.reloadRejected.Load(),
		ElapsedSeconds:  max(0, end.Sub(e.start).Seconds()),
		DurationSeconds: cfg.Duration.Seconds(), OperationLimit: cfg.OperationLimit,
		TargetRPS: cfg.RatePerSecond, InFlight: e.inflight.Load(),
		Counts: ReportCounts{
			PlannedOperations: c.planned.Load(), SentRequests: c.httpRequests.Load(),
			HTTPRequests: c.httpRequests.Load(), DroppedOperations: c.dropped.Load(),
			SuccessfulOperations: c.success.Load(), FailedOperations: c.failed.Load(),
			Timeouts: c.timeouts.Load(), CompletedPairs: c.completedPairs.Load(),
			Retries: c.retries.Load(), FinalRateLimited: c.final429.Load(),
		},
	}
	if p.ElapsedSeconds > 0 {
		p.HTTPRPS = float64(p.Counts.HTTPRequests) / p.ElapsedSeconds
		p.SuccessfulRPS = float64(p.Counts.SuccessfulOperations) / p.ElapsedSeconds
	}
	p50, p95, p99, maximum := r.res.percentiles()
	p.LatencyMS = ReportLatency{P50: durationMilliseconds(p50), P95: durationMilliseconds(p95), P99: durationMilliseconds(p99), Max: durationMilliseconds(maximum)}
	p.HTTPStatuses, _ = r.outcomes.snapshot()
	return p
}
