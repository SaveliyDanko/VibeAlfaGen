package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/alfagen/pii-service/internal/mock/client"
	"github.com/alfagen/pii-service/internal/platform/config"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	exitOK        = 0
	exitRunError  = 2
	exitSLOMissed = 3
)

type cliOverrides struct {
	set            map[string]bool
	mode           string
	targetURL      string
	seed           int64
	rate           float64
	concurrency    int
	maxInFlight    int
	maxConnections int
	timeout        time.Duration
	duration       time.Duration
	operationLimit int64
	profile        string
	systemID       string
	apiKey         string
	payloads       []string
	datasetSHA256  string
	idNamespace    string
	scenario       string
	maskFixtures   []client.MaskFixture
	weights        map[string]float64
	commitSHA      string
	imageTag       string
	replayIndex    *int64
}

type commandOptions struct {
	opts                client.Options
	continuous          bool
	managedStatus       string
	mode                string
	scenario            string
	seed                int64
	rate                float64
	concurrency         int
	maxInFlight         int
	maxConnections      int
	timeout             time.Duration
	duration            time.Duration
	operationLimit      int64
	profile             string
	weightsText         string
	commitSHA           string
	imageTag            string
	replayIndex         int64
	dataset             string
	maskDataset         string
	reliabilityDataset  string
	metricsAddr         string
	reportJSON          string
	canonicalReport     string
	reportMarkdown      string
	minimumRPS          float64
	maximumP95          time.Duration
	latencyTarget       time.Duration
	maximumMaskDistance float64
}

func parseCLI() commandOptions {
	var args commandOptions
	opts := &args.opts
	flag.StringVar(&opts.URL, "url", "http://127.0.0.1:8080/process", "endpoint URL")
	flag.IntVar(&opts.Concurrency, "c", 20, "concurrency")
	flag.IntVar(&opts.Total, "n", 1000, "finite number of requests")
	flag.StringVar(&opts.Payload, "payload", "Клиент Иванов Иван Иванович, телефон +7 (999) 123-45-67, email demo@example.test", "synthetic payload")
	flag.StringVar(&opts.SystemID, "system", "benchmark", "consumer ID")

	flag.StringVar(&args.managedStatus, "managed-status", "", "keep alive for admin-managed runs; write status to this file")
	flag.BoolVar(&args.continuous, "continuous", false, "run continuous paced load instead of the finite run")
	flag.StringVar(&args.mode, "mode", client.ModeProcess, "continuous mode: process|generate")
	flag.StringVar(&args.scenario, "scenario", client.ScenarioRequest, "continuous scenario: mask_only|round_trip|stable_retry|expected_conflict|mixed (request is legacy)")
	flag.Int64Var(&args.seed, "seed", 1, "continuous deterministic seed")
	flag.Float64Var(&args.rate, "rate", 1000, "continuous target HTTP requests per second, including retries and demasking")
	flag.Float64Var(&args.rate, "target-rps", 1000, "continuous target HTTP requests per second, including retries and demasking")
	flag.IntVar(&args.concurrency, "concurrency", 256, "continuous worker concurrency")
	flag.IntVar(&args.maxInFlight, "max-inflight", 256, "continuous max in-flight operations")
	flag.IntVar(&args.maxInFlight, "max-in-flight", 256, "continuous max in-flight operations")
	flag.IntVar(&args.maxConnections, "http-connections", 0, "maximum connections per target host (0 = unlimited); fixed for a run")
	flag.DurationVar(&args.timeout, "timeout", 10*time.Second, "per-attempt request timeout")
	flag.DurationVar(&args.timeout, "request-timeout", 10*time.Second, "per-attempt request timeout")
	flag.DurationVar(&args.duration, "duration", 0, "continuous run duration (0 = until interrupted)")
	flag.Int64Var(&args.operationLimit, "operations", 0, "stop after this many planned operations (0 = duration/context only)")
	flag.StringVar(&args.profile, "profile", "short", "continuous payload profile: short|long")
	flag.StringVar(&args.profile, "payload-profile", "small", "continuous payload profile: small|medium|large")
	flag.StringVar(&args.weightsText, "weights", "", "mixed weights as mask_only=20,round_trip=40,stable_retry=20,expected_conflict=20")
	flag.StringVar(&args.commitSHA, "commit-sha", "", "full Git SHA recorded in alfagen.load.v1")
	flag.StringVar(&args.imageTag, "image-tag", "", "immutable image tag or digest recorded in alfagen.load.v1")
	flag.Int64Var(&args.replayIndex, "replay-index", -1, "replay one planned index")
	flag.StringVar(&args.dataset, "dataset", "", "manifest of verified 100000-token payloads")
	flag.StringVar(&args.maskDataset, "mask-dataset", "", "annotated alfagen.mask-eval.v1 dataset for round_trip quality evaluation")
	flag.StringVar(&args.reliabilityDataset, "reliability-dataset", "", "synthetic JSONL corpus covering all 17 categories for repeated round_trip load")
	flag.StringVar(&args.metricsAddr, "metrics-addr", ":9091", "continuous health and metrics listen address")
	flag.StringVar(&args.canonicalReport, "report", "", "write canonical alfagen.load.v1 JSON to this path")
	flag.StringVar(&args.reportJSON, "report-json", "", "write a safe JSON report to this path")
	flag.StringVar(&args.reportMarkdown, "report-md", "", "write a human-readable report to this path")
	flag.Float64Var(&args.minimumRPS, "min-success-rps", 0, "minimum successful operation RPS; 0 disables this SLO")
	flag.DurationVar(&args.maximumP95, "max-p95", 0, "optional hard maximum p95 latency; 0 disables this SLO")
	flag.DurationVar(&args.latencyTarget, "latency-target", time.Second, "advisory p95 latency target; does not fail the run")
	flag.Float64Var(&args.maximumMaskDistance, "max-mask-distance", -1, "maximum per-item normalized mask distance [0..1]; -1 disables this SLO")
	flag.Parse()
	return args
}

func main() {
	args := parseCLI()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	code := runCLI(ctx, args)
	stop()
	os.Exit(code)
}

func runCLI(ctx context.Context, args commandOptions) int {
	opts := args.opts

	opts.APIKey = os.Getenv("MOCK_CLIENT_API_KEY")

	if !args.continuous {
		return runFinite(ctx, args, opts)
	}

	set := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { set[f.Name] = true })
	overrides := cliOverrides{
		set: set, mode: args.mode, targetURL: opts.URL, seed: args.seed, rate: args.rate,
		concurrency: args.concurrency, maxInFlight: args.maxInFlight, timeout: args.timeout, duration: args.duration,
		maxConnections: args.maxConnections,
		operationLimit: args.operationLimit, profile: args.profile, systemID: opts.SystemID, apiKey: opts.APIKey, scenario: args.scenario,
		commitSHA: args.commitSHA, imageTag: args.imageTag,
	}
	if args.weightsText != "" {
		var err error
		overrides.weights, err = parseWeights(args.weightsText)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return exitRunError
		}
	}
	if args.replayIndex >= 0 {
		overrides.replayIndex = &args.replayIndex
	}
	if args.canonicalReport != "" && args.reportJSON != "" && args.canonicalReport != args.reportJSON {
		fmt.Fprintln(os.Stderr, "-report and -report-json must not select different files")
		return exitRunError
	}
	if args.canonicalReport == "" {
		args.canonicalReport = args.reportJSON
	}
	if err := args.loadDatasets(&overrides); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitRunError
	}
	if !validMaskDistanceLimit(args.maximumMaskDistance) {
		fmt.Fprintln(os.Stderr, "-max-mask-distance must be between 0 and 1, or -1 to disable")
		return exitRunError
	}
	if args.latencyTarget <= 0 {
		fmt.Fprintln(os.Stderr, "-latency-target must be positive")
		return exitRunError
	}
	if args.managedStatus != "" {
		return runManaged(ctx, overrides, args.reportOptions(), args.managedStatus)
	}
	return runContinuous(ctx, overrides, args.reportOptions())
}

func (args commandOptions) loadDatasets(overrides *cliOverrides) error {
	if boolCount(args.dataset != "", args.maskDataset != "", args.reliabilityDataset != "") > 1 {
		return fmt.Errorf("-dataset, -mask-dataset, and -reliability-dataset are mutually exclusive")
	}
	if args.dataset != "" {
		var err error
		overrides.payloads, overrides.datasetSHA256, err = client.LoadDataset(args.dataset)
		if err != nil {
			return err
		}
		overrides.profile = "cl100k-100000"
		overrides.set["profile"] = true
	}
	if err := args.loadMaskDataset(overrides); err != nil {
		return err
	}
	if args.reliabilityDataset != "" {
		var err error
		overrides.maskFixtures, overrides.datasetSHA256, err = client.LoadReliabilityDataset(args.reliabilityDataset)
		if err != nil {
			return err
		}
		if overrides.set["scenario"] && args.scenario != client.ScenarioRoundTrip {
			return fmt.Errorf("-reliability-dataset requires -scenario round_trip")
		}
		overrides.scenario = client.ScenarioRoundTrip
		overrides.profile = "all-categories"
		overrides.set["scenario"] = true
		overrides.set["profile"] = true
	}
	return nil
}

type reportOptions struct {
	metricsAddr, jsonPath, markdownPath string
	minimumRPS, maximumMaskDistance     float64
	maximumP95, latencyTarget           time.Duration
}

func (args commandOptions) reportOptions() reportOptions {
	return reportOptions{
		metricsAddr: args.metricsAddr, jsonPath: args.canonicalReport, markdownPath: args.reportMarkdown,
		minimumRPS: args.minimumRPS, maximumMaskDistance: args.maximumMaskDistance,
		maximumP95: args.maximumP95, latencyTarget: args.latencyTarget,
	}
}

func parseWeights(raw string) (map[string]float64, error) {
	weights := map[string]float64{}
	for _, item := range strings.Split(raw, ",") {
		name, valueText, ok := strings.Cut(strings.TrimSpace(item), "=")
		if !ok || name == "" || valueText == "" {
			return nil, fmt.Errorf("invalid -weights item %q", item)
		}
		value, err := strconv.ParseFloat(valueText, 64)
		if err != nil || value < 0 || math.IsNaN(value) || math.IsInf(value, 0) {
			return nil, fmt.Errorf("invalid -weights value for %q", name)
		}
		if _, exists := weights[name]; exists {
			return nil, fmt.Errorf("duplicate -weights key %q", name)
		}
		weights[name] = value
	}
	return weights, nil
}

func boolCount(values ...bool) int {
	total := 0
	for _, value := range values {
		if value {
			total++
		}
	}
	return total
}

func validMaskDistanceLimit(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && (value == -1 || (value >= 0 && value <= 1))
}

func runContinuous(ctx context.Context, overrides cliOverrides, options reportOptions) int {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// A new run must exercise new contexts, not warm idempotent retries. An
	// explicit run ID retains deterministic replay when that is desired.
	overrides.idNamespace = env("ALFAGEN_RUN_ID", "")
	if overrides.idNamespace == "" {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return exitRunError
		}
		overrides.idNamespace = fmt.Sprintf("load-%x", nonce)
	}
	src, err := buildSource()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitRunError
	}
	poll := envDuration("ALFAGEN_CONFIG_POLL", 5*time.Second)
	reloader, err := client.NewReloader(ctx, src, poll)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitRunError
	}

	runnerConfig, err := documentRunnerConfig(reloader.Current(), overrides)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitRunError
	}
	runnerConfig.CommitSHA = firstNonEmpty(overrides.commitSHA, env("ALFAGEN_COMMIT_SHA", "unknown"))
	runnerConfig.ImageTag = firstNonEmpty(overrides.imageTag, env("ALFAGEN_IMAGE_TAG", "unknown"))
	runnerConfig.RunID = overrides.idNamespace
	runnerConfig.ReplayIndex = overrides.replayIndex
	runnerConfig.Environment = client.ReportEnvironment{
		Runner:         env("ALFAGEN_RUNNER", "same_vps"),
		Host:           env("ALFAGEN_SAFE_HOST_LABEL", runtime.GOOS+"/"+runtime.GOARCH),
		ResourceLimits: map[string]float64{},
	}
	runner, err := client.NewRunner(runnerConfig)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitRunError
	}
	if err := configureMTLS(runner); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitRunError
	}

	metricsServer, err := startMetricsServer(options.metricsAddr, runner)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitRunError
	}
	defer stopMetricsServer(metricsServer)
	go reloadRunner(ctx, reloader, runner, overrides)

	report, err := runner.Run(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitRunError
	}
	return finishReport(report, options)
}

func finishReport(report client.Report, options reportOptions) int {
	report.LatencyTarget = options.latencyTarget
	report.LatencyTargetMet = report.P95 <= options.latencyTarget
	status := loadStatus(report, options.minimumRPS, options.maximumP95, options.maximumMaskDistance)
	report.LatencyMS.Target = float64(options.latencyTarget) / float64(time.Millisecond)
	report.LatencyMS.TargetMet = report.LatencyTargetMet
	report.Verdict = status
	if err := writeReports(report, options.jsonPath, options.markdownPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitRunError
	}
	printReport(report, status)
	if status == "SLO_MISSED" {
		return exitSLOMissed
	}
	if status == "HARNESS_ERROR" || status == "CANCELLED" {
		return exitRunError
	}
	return exitOK
}

func configureMTLS(runner *client.Runner) error {
	caFile := os.Getenv("ALFAGEN_MTLS_CA_FILE")
	certFile := os.Getenv("ALFAGEN_MTLS_CERT_FILE")
	keyFile := os.Getenv("ALFAGEN_MTLS_KEY_FILE")
	if caFile == "" && certFile == "" && keyFile == "" {
		return nil
	}
	return runner.ConfigureMTLS(caFile, certFile, keyFile)
}

func applyOverrides(cfg client.Config, overrides cliOverrides) client.Config {
	cfg.IDNamespace = overrides.idNamespace
	if len(overrides.maskFixtures) > 0 {
		cfg.MaskFixtures = overrides.maskFixtures
		cfg.DatasetSHA256 = overrides.datasetSHA256
	}
	if len(overrides.payloads) > 0 {
		cfg.Payloads = overrides.payloads
		cfg.DatasetSHA256 = overrides.datasetSHA256
	}
	if overrides.set["mode"] {
		cfg.Mode = overrides.mode
	}
	if overrides.set["scenario"] {
		cfg.Scenario = overrides.scenario
	}
	if overrides.set["url"] {
		cfg.TargetURL = overrides.targetURL
	}
	if overrides.set["seed"] {
		cfg.Seed = overrides.seed
	}
	applyLoadOverrides(&cfg, overrides)
	if overrides.set["profile"] {
		cfg.PayloadProfile = overrides.profile
	}
	if overrides.set["payload-profile"] {
		cfg.PayloadProfile = overrides.profile
	}
	if overrides.set["system"] {
		cfg.SystemID = overrides.systemID
	}
	if overrides.apiKey != "" {
		cfg.APIKey = overrides.apiKey
	}
	if len(overrides.weights) > 0 {
		cfg.OperationWeights = overrides.weights
	}
	return cfg
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func startMetricsServer(addr string, runner *client.Runner) (*http.Server, error) {
	return startMetricsHandler(addr, promhttp.HandlerFor(runner.Registry(), promhttp.HandlerOpts{}))
}

func startMetricsHandler(addr string, handler http.Handler) (*http.Server, error) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("mock-client metrics: %w", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/live", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/ready", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.Handle("/metrics", handler)
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second}
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			fmt.Fprintln(os.Stderr, "mock-client metrics: server failed")
		}
	}()
	return server, nil
}

func loadStatus(report client.Report, minimumRPS float64, maximumP95 time.Duration, maximumMaskDistance float64) string {
	if report.Verdict == "CANCELLED" {
		return "CANCELLED"
	}
	if report.Failed > 0 || report.StopReason == "five_consecutive_invalid" {
		return "HARNESS_ERROR"
	}
	if report.Dropped > 0 || report.Success == 0 {
		return "SLO_MISSED"
	}
	if minimumRPS > 0 && report.SuccessfulRPS < minimumRPS {
		return "SLO_MISSED"
	}
	if maximumP95 > 0 && report.P95 > maximumP95 {
		return "SLO_MISSED"
	}
	if maximumMaskDistance >= 0 && (report.QualityEvaluated == 0 || report.MaskDistanceMax > maximumMaskDistance) {
		return "SLO_MISSED"
	}
	return "PASS"
}

func writeReports(report client.Report, jsonPath, markdownPath string) error {
	if jsonPath != "" {
		var buffer bytes.Buffer
		if err := client.WriteJSON(&buffer, report); err != nil {
			return err
		}
		if err := writeFile(jsonPath, buffer.Bytes()); err != nil {
			return err
		}
	}
	if markdownPath != "" {
		if err := writeFile(markdownPath, []byte(markdownReport(report))); err != nil {
			return err
		}
	}
	return nil
}

func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".report-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func markdownReport(r client.Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# AlfaGen load report\n\n- Schema: `%s`\n- Verdict: **%s**\n- Run ID: `%s`\n- Commit: `%s`\n- Image: `%s`\n- Mode/scenario/profile: `%s` / `%s` / `%s`\n- Seed: `%d`\n- Duration: `%s`\n- Runner/host: `%s` / `%s`\n\n", r.SchemaVersion, r.Verdict, r.RunID, r.CommitSHA, r.ImageTag, r.Mode, r.Scenario, r.Profile, r.Seed, r.Duration, r.Environment.Runner, r.Environment.Host)
	b.WriteString("| planned operations | sent operations | dropped | success | failed | successful operation RPS | HTTP RPS | p50 | p95 | p99 | max |\n|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n")
	fmt.Fprintf(&b, "| %d | %d | %d | %d | %d | %.2f | %.2f | %s | %s | %s | %s |\n\n", r.Planned, r.Sent, r.Dropped, r.Success, r.Failed, r.SuccessfulRPS, r.HTTPRPS, r.P50, r.P95, r.P99, r.Max)
	fmt.Fprintf(&b, "- HTTP requests: %d\n- Retries: %d\n- Final 429 responses: %d\n- Completed pairs: %d\n- Maximum invalid streak: %d\n- Stop reason: `%s`\n- Advisory p95 target: %s (met: %t)\n- Quality evaluated: %d\n- Mask distance mean/max: %.6f / %.6f\n\n", r.HTTPRequests, r.Retries, r.FinalRateLimited, r.CompletedPairs, r.MaxInvalidStreak, r.StopReason, r.LatencyTarget, r.LatencyTargetMet, r.QualityEvaluated, r.MaskDistanceMean, r.MaskDistanceMax)
	writeBreakdown(&b, "HTTP status", r.HTTPStatus)
	writeBreakdown(&b, "Errors", r.Errors)
	writeBreakdown(&b, "Evaluated categories", r.EvaluatedCategories)
	return b.String()
}

func writeBreakdown(b *strings.Builder, title string, values map[string]int64) {
	fmt.Fprintf(b, "## %s\n\n", title)
	if len(values) == 0 {
		b.WriteString("None.\n\n")
		return
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Fprintf(b, "- `%s`: %d\n", key, values[key])
	}
	b.WriteByte('\n')
}

func printReport(report client.Report, status string) {
	fmt.Printf("status=%s scenario=%s planned=%d sent=%d http_requests=%d retries=%d final_429=%d completed_pairs=%d dropped=%d success=%d failed=%d invalid_streak_max=%d stop_reason=%s quality=%d mask_distance_mean=%.6f mask_distance_max=%.6f duration=%s successful_rps=%.2f http_rps=%.2f p50=%s p95=%s p99=%s max=%s latency_target=%s latency_target_met=%t\n",
		status, report.Scenario, report.Planned, report.Sent, report.HTTPRequests, report.Retries, report.FinalRateLimited, report.CompletedPairs, report.Dropped, report.Success, report.Failed, report.MaxInvalidStreak, report.StopReason, report.QualityEvaluated, report.MaskDistanceMean, report.MaskDistanceMax,
		report.Duration, report.SuccessfulRPS, report.HTTPRPS, report.P50, report.P95, report.P99, report.Max, report.LatencyTarget, report.LatencyTargetMet)
}

func buildSource() (config.Source, error) {
	source := env("ALFAGEN_CONFIG_SOURCE", "file")
	switch source {
	case "file":
		return config.NewFileSource(env("ALFAGEN_CONFIG_FILE", "mock-client-config/config.json")), nil
	case "kubernetes":
		return config.NewInClusterSecretSource(env("ALFAGEN_CONFIG_NAMESPACE", ""), env("ALFAGEN_CONFIG_SECRET", "mock-client-config"), env("ALFAGEN_CONFIG_KEY", "config.json"))
	default:
		return nil, fmt.Errorf("unknown ALFAGEN_CONFIG_SOURCE %q", source)
	}
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func envDuration(name string, fallback time.Duration) time.Duration {
	if value := os.Getenv(name); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return fallback
}

func applyLoadOverrides(cfg *client.Config, overrides cliOverrides) {
	if overrides.set["http-connections"] {
		cfg.MaxConnections = overrides.maxConnections
	}
	if overrides.set["rate"] {
		cfg.RatePerSecond = overrides.rate
	}
	if overrides.set["target-rps"] {
		cfg.RatePerSecond = overrides.rate
	}
	if overrides.set["concurrency"] {
		cfg.Concurrency = overrides.concurrency
	}
	if overrides.set["max-inflight"] {
		cfg.MaxInFlight = overrides.maxInFlight
	}
	if overrides.set["max-in-flight"] {
		cfg.MaxInFlight = overrides.maxInFlight
	}
	if overrides.set["timeout"] {
		cfg.RequestTimeout = overrides.timeout
	}
	if overrides.set["request-timeout"] {
		cfg.RequestTimeout = overrides.timeout
	}
	if overrides.set["duration"] {
		cfg.Duration = overrides.duration
	}
	if overrides.set["operations"] {
		cfg.OperationLimit = overrides.operationLimit
	}

}

func stopMetricsServer(server *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "mock-client metrics: graceful shutdown failed")
		if err := server.Close(); err != nil {
			fmt.Fprintln(os.Stderr, "mock-client metrics: close failed")
		}
	}
}

func reloadRunner(ctx context.Context, reloader *client.Reloader, runner *client.Runner, overrides cliOverrides) {
	for next := range reloader.Watch(ctx) {
		nextConfig, err := documentRunnerConfig(next, overrides)
		if err != nil {
			fmt.Fprintln(os.Stderr, "mock-client: rejected invalid runner configuration")
			continue
		}
		if err := runner.SetConfig(nextConfig); err != nil {
			fmt.Fprintln(os.Stderr, "mock-client: rejected runner configuration update")
		}
	}
}

func runFinite(ctx context.Context, args commandOptions, opts client.Options) int {
	if args.dataset != "" || args.maskDataset != "" || args.reliabilityDataset != "" {
		fmt.Fprintln(os.Stderr, "dataset flags require -continuous")
		return exitRunError
	}
	if err := client.Run(ctx, opts, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return exitOK
}

func (args commandOptions) loadMaskDataset(overrides *cliOverrides) error {
	if args.maskDataset != "" {
		var err error
		overrides.maskFixtures, overrides.datasetSHA256, err = client.LoadMaskDataset(args.maskDataset)
		if err != nil {
			return err
		}
		if overrides.set["scenario"] && args.scenario != client.ScenarioRoundTrip {
			return fmt.Errorf("-mask-dataset requires -scenario round_trip")
		}
		overrides.scenario = client.ScenarioRoundTrip
		overrides.profile = "mask-eval"
		overrides.set["scenario"] = true
		overrides.set["profile"] = true
		if !overrides.set["operations"] {
			overrides.operationLimit = int64(len(overrides.maskFixtures))
			overrides.set["operations"] = true
		}
	}
	return nil
}

// A configured file is the rotating credential. The bootstrap environment
// fallback must not overwrite it, on either startup or a later reload.
func documentRunnerConfig(doc *client.DocConfig, overrides cliOverrides) (client.Config, error) {
	cfg, err := doc.RunnerConfig()
	if err != nil {
		return client.Config{}, err
	}
	// The document owns credentials, including an explicitly anonymous system.
	overrides.apiKey = ""
	return applyOverrides(cfg, overrides), nil
}
