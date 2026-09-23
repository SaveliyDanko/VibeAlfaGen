package admin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Keep this expression aligned with the provisioned Grafana TPS panels.
// Rate before sum handles each replica's counter resets independently. A failed
// scrape must not turn a missing backend into an apparently healthy idle one.
const tokensPerSecondQuery = `sum(rate(tokens_processed_total{job="alfagen-production-backend"}[1m]) and on(job,instance) (up{job="alfagen-production-backend"} == 1))`

type throughputSource struct {
	endpoint string
	client   *http.Client
}

type throughputSnapshot struct {
	Status          string     `json:"status"`
	TokensPerSecond *float64   `json:"tokens_per_second"`
	Estimated       bool       `json:"estimated"`
	WindowSeconds   int        `json:"window_seconds"`
	EvaluatedAt     *time.Time `json:"evaluated_at,omitempty"`
}

func newThroughputSource(address string) (*throughputSource, error) {
	if address == "" {
		return nil, nil
	}
	u, err := url.Parse(address)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("admin: invalid Prometheus URL")
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/api/v1/query"
	u.RawPath = ""
	u.RawQuery = url.Values{"query": {tokensPerSecondQuery}, "timeout": {"2s"}}.Encode()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &throughputSource{endpoint: u.String(), client: &http.Client{
		Timeout: 3 * time.Second, Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

func (s *Server) throughput(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.throughputSource.read(r.Context()))
}

func (s *throughputSource) read(ctx context.Context) throughputSnapshot {
	result := throughputSnapshot{Status: "unavailable", Estimated: true, WindowSeconds: 60}
	if s == nil {
		result.Status = "not_configured"
		return result
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.endpoint, nil)
	if err != nil {
		return result
	}
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return result
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return result
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024+1))
	if err != nil || len(raw) > 64*1024 {
		return result
	}
	return decodeThroughput(raw, result)
}

func decodeThroughput(raw []byte, result throughputSnapshot) throughputSnapshot {
	var envelope struct {
		Status   string   `json:"status"`
		Warnings []string `json:"warnings"`
		Data     struct {
			ResultType string `json:"resultType"`
			Result     []struct {
				Value []json.RawMessage `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if json.Unmarshal(raw, &envelope) != nil || envelope.Status != "success" || envelope.Data.ResultType != "vector" || len(envelope.Warnings) > 0 {
		return result
	}
	if len(envelope.Data.Result) == 0 {
		result.Status = "no_data"
		return result
	}
	if len(envelope.Data.Result) != 1 {
		return result
	}
	value, at, ok := decodeThroughputSample(envelope.Data.Result[0].Value)
	if !ok {
		return result
	}
	result.Status = "available"
	result.TokensPerSecond = &value
	result.EvaluatedAt = &at
	return result
}

func decodeThroughputSample(sample []json.RawMessage) (float64, time.Time, bool) {
	if len(sample) != 2 {
		return 0, time.Time{}, false
	}
	var timestamp float64
	var text string
	if json.Unmarshal(sample[0], &timestamp) != nil || json.Unmarshal(sample[1], &text) != nil {
		return 0, time.Time{}, false
	}
	value, err := strconv.ParseFloat(text, 64)
	// Instant query timestamps are evaluation times, not scrape times.
	now := float64(time.Now().Unix())
	if err != nil || math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || timestamp < now-60 || timestamp > now+30 {
		return 0, time.Time{}, false
	}
	return value, time.UnixMilli(int64(timestamp * 1000)).UTC(), true
}
