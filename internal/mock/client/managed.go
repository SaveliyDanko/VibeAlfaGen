package client

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// RunStatus is a heartbeat from the load process, independent of desired config.
type RunStatus struct {
	RunID         string       `json:"run_id"`
	State         string       `json:"state"`
	UpdatedAt     time.Time    `json:"updated_at"`
	ConfigVersion string       `json:"config_version,omitempty"`
	FailureCode   string       `json:"failure_code,omitempty"`
	Progress      *RunProgress `json:"progress,omitempty"`
}

// RunFailure exposes only a bounded stage code, never raw errors or credentials.
type RunFailure struct {
	Code string
	Err  error
}

func (e *RunFailure) Error() string { return e.Err.Error() }
func (e *RunFailure) Unwrap() error { return e.Err }

func ReadRunStatus(path string) (RunStatus, error) {
	var status RunStatus
	raw, err := os.ReadFile(path)
	if err != nil {
		return status, err
	}
	err = json.Unmarshal(raw, &status)
	return status, err
}

func WriteRunStatus(path string, status RunStatus) error {
	raw, err := json.Marshal(status)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".run-status-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(raw); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

type managedRun struct {
	cancel   context.CancelFunc
	done     chan error
	stopping bool
}

type runSupervisor struct {
	status RunStatus
	active *managedRun
	run    func(context.Context, *DocConfig) error
}

// Supervise keeps the worker alive while idle and starts one fresh run per ID.
// A completed ID is persisted so restarting the process cannot replay a run.
func Supervise(ctx context.Context, current func() *DocConfig, path string, interval time.Duration, run func(context.Context, *DocConfig) error) error {
	return SuperviseWithProgress(ctx, current, path, interval, run, nil)
}

func SuperviseWithProgress(ctx context.Context, current func() *DocConfig, path string, interval time.Duration, run func(context.Context, *DocConfig) error, progress func() *RunProgress) error {
	if interval <= 0 {
		return errors.New("mock-client supervisor: interval must be positive")
	}
	status, err := ReadRunStatus(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	status.State = "idle"
	if status.RunID != "" {
		status.State = "interrupted"
	}
	s := runSupervisor{status: status, run: run}
	defer s.stop()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		doc := current()
		if doc == nil {
			return errors.New("mock-client supervisor: configuration unavailable")
		}
		s.advance(ctx, doc)
		s.status.ConfigVersion = doc.Version
		s.refreshProgress(progress)
		s.status.UpdatedAt = time.Now().UTC()
		if err := WriteRunStatus(path, s.status); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (s *runSupervisor) refreshProgress(progress func() *RunProgress) {
	if progress == nil {
		return
	}
	if p := progress(); p != nil && p.RunID == s.status.RunID {
		s.status.Progress = p
	}
}

func (s *runSupervisor) advance(ctx context.Context, doc *DocConfig) {
	s.collect()
	if s.active != nil {
		if !doc.Enabled || doc.RunID != s.status.RunID {
			s.active.stopping = true
			s.active.cancel()
			s.status.State = "stopping"
		}
		return
	}
	if !doc.Enabled || doc.RunID == "" || doc.RunID == s.status.RunID {
		return
	}
	runCtx, cancel := context.WithCancel(ctx)
	active := &managedRun{cancel: cancel, done: make(chan error, 1)}
	s.active = active
	s.status.RunID, s.status.State = doc.RunID, "running"
	s.status.FailureCode, s.status.Progress = "", nil
	go func() { active.done <- s.run(runCtx, doc) }()
}

func (s *runSupervisor) collect() {
	if s.active == nil {
		return
	}
	select {
	case err := <-s.active.done:
		s.status.State = "completed"
		if err != nil {
			s.status.State = "failed"
			s.status.FailureCode = "run_failed"
			var failure *RunFailure
			if errors.As(err, &failure) {
				s.status.FailureCode = failure.Code
			}
		}
		if s.active.stopping {
			s.status.State = "stopped"
			s.status.FailureCode = ""
		}
		s.active.cancel()
		s.active = nil
	default:
	}
}

func (s *runSupervisor) stop() {
	if s.active == nil {
		return
	}
	s.active.cancel()
	<-s.active.done
}
