package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/alfagen/pii-service/internal/mock/client"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func runManaged(ctx context.Context, overrides cliOverrides, options reportOptions, statusPath string) int {
	src, err := buildSource()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitRunError
	}
	reloader, err := client.NewReloader(ctx, src, envDuration("ALFAGEN_CONFIG_POLL", 2*time.Second))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitRunError
	}
	go func() {
		for range reloader.Watch(ctx) {
			// Drain update notifications; the supervisor reads Current on each poll.
		}
	}()
	var active atomic.Pointer[client.Runner]
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		runner := active.Load()
		if runner == nil {
			w.WriteHeader(http.StatusOK)
			return
		}
		promhttp.HandlerFor(runner.Registry(), promhttp.HandlerOpts{}).ServeHTTP(w, r)
	})
	server, err := startMetricsHandler(options.metricsAddr, handler)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitRunError
	}
	defer stopMetricsServer(server)
	run := managedRunCallback(overrides, options, &active, reloader)

	progress := func() *client.RunProgress {
		if runner := active.Load(); runner != nil {
			return runner.Progress()
		}
		return nil
	}
	if err := client.SuperviseWithProgress(ctx, reloader.Current, statusPath, time.Second, run, progress); err != nil && ctx.Err() == nil {
		fmt.Fprintln(os.Stderr, "mock-client supervisor:", err)
		return exitRunError
	}
	return exitOK
}

func managedRunCallback(overrides cliOverrides, options reportOptions, active *atomic.Pointer[client.Runner], reloader *client.Reloader) func(context.Context, *client.DocConfig) error {
	return func(runCtx context.Context, doc *client.DocConfig) error {
		cfg, err := documentRunnerConfig(doc, overrides)
		if err != nil {
			return &client.RunFailure{Code: "configuration", Err: err}
		}
		runOverrides := overrides
		runOverrides.idNamespace = doc.RunID
		cfg.IDNamespace = doc.RunID
		cfg.RunID = doc.RunID
		cfg = managedMetadata(cfg, overrides)
		runner, err := client.NewRunner(cfg)
		if err != nil {
			return &client.RunFailure{Code: "configuration", Err: err}
		}
		if err := configureMTLS(runner); err != nil {
			return &client.RunFailure{Code: "tls", Err: err}
		}
		active.Store(runner)
		reloadCtx, stopReload := context.WithCancel(runCtx)
		defer stopReload()
		go reloadManaged(reloadCtx, reloader, runner, runOverrides, doc.RunID)
		report, err := runner.Run(runCtx)
		if err != nil {
			return err
		}
		if code := finishReport(report, options); code != exitOK {
			if code == exitSLOMissed {
				return nil // A measured SLO miss is a completed run, not a worker failure.
			}
			return &client.RunFailure{Code: "report_or_requests", Err: fmt.Errorf("load run exited with status %d", code)}
		}
		return nil
	}
}

func reloadManaged(ctx context.Context, reloader *client.Reloader, runner *client.Runner, overrides cliOverrides, id string) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			doc := reloader.Current()
			if doc.RunID != id || !doc.Enabled {
				continue
			}
			cfg, err := documentRunnerConfig(doc, overrides)
			if err != nil {
				runner.RecordReloadFailure()
				continue
			}
			cfg.RunID = id
			cfg = managedMetadata(cfg, overrides)
			if err := runner.SetConfig(cfg); err != nil {
				fmt.Fprintln(os.Stderr, "mock-client: rejected managed config update")
			}
		}
	}
}

func managedMetadata(cfg client.Config, overrides cliOverrides) client.Config {
	cfg.CommitSHA = firstNonEmpty(overrides.commitSHA, env("ALFAGEN_COMMIT_SHA", "unknown"))
	cfg.ImageTag = firstNonEmpty(overrides.imageTag, env("ALFAGEN_IMAGE_TAG", "unknown"))
	cfg.Environment = client.ReportEnvironment{Runner: env("ALFAGEN_RUNNER", "same_vps"), Host: env("ALFAGEN_SAFE_HOST_LABEL", runtime.GOOS+"/"+runtime.GOARCH), ResourceLimits: map[string]float64{}}
	return cfg
}
