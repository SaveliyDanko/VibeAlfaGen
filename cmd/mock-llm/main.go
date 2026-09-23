// Command mock-llm is an internal deterministic provider used by smoke and
// integration tests. It must never be exposed by the external ingress.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	mockllm "github.com/alfagen/pii-service/internal/mock/llm"
	"github.com/alfagen/pii-service/internal/platform/config"
)

const invalidConfigMessage = "invalid mock LLM configuration"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	src, err := buildSource()
	if err != nil {
		logger.Error(invalidConfigMessage, "error", err)
		os.Exit(1)
	}
	poll := envDuration("ALFAGEN_CONFIG_POLL", 5*time.Second)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	reloader, err := mockllm.NewReloader(ctx, src, poll)
	if err != nil {
		logger.Error(invalidConfigMessage, "error", err)
		os.Exit(1)
	}
	doc := reloader.Current()
	hc, err := doc.HandlerConfig()
	if err != nil {
		logger.Error(invalidConfigMessage, "error", err)
		os.Exit(1)
	}
	addr := reloader.Addr()

	handler := mockllm.NewDynamicHandler(hc)
	go func() {
		for next := range reloader.Watch(ctx) {
			nhc, err := next.HandlerConfig()
			if err != nil {
				continue
			}
			handler.SetConfig(nhc)
		}
	}()

	server := &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}
	errCh := make(chan error, 1)
	go func() {
		logger.Info("mock LLM starting", "addr", addr, "mode", hc.Mode, "seed", hc.Seed)
		errCh <- server.ListenAndServe()
	}()
	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("mock LLM failed")
			os.Exit(1)
		}
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdownCtx)
}

// buildSource selects a config.Source from the environment.
func buildSource() (config.Source, error) {
	source := env("ALFAGEN_CONFIG_SOURCE", "file")
	switch source {
	case "file":
		path := env("ALFAGEN_CONFIG_FILE", "mock-llm-config/config.json")
		return config.NewFileSource(path), nil
	case "kubernetes":
		namespace := env("ALFAGEN_CONFIG_NAMESPACE", "")
		name := env("ALFAGEN_CONFIG_SECRET", "mock-llm-config")
		key := env("ALFAGEN_CONFIG_KEY", "config.json")
		return config.NewInClusterSecretSource(namespace, name, key)
	default:
		return nil, fmt.Errorf("unknown ALFAGEN_CONFIG_SOURCE %q", source)
	}
}

func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func envDuration(name string, fallback time.Duration) time.Duration {
	if v := os.Getenv(name); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}
