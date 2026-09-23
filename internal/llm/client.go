// Package llm contains provider adapters used by the proxy route.
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/alfagen/pii-service/internal/contracts"
)

type HTTPProvider struct {
	endpoint string
	client   *http.Client
	models   map[string]bool
}

func NewHTTPProvider(baseURL string, client *http.Client, models []string) (*HTTPProvider, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("provider: invalid base URL")
	}
	if client == nil {
		return nil, errors.New("provider: HTTP client is required")
	}
	allowed := make(map[string]bool, len(models))
	for _, model := range models {
		allowed[model] = true
	}
	copyClient := *client
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &HTTPProvider{
		endpoint: strings.TrimRight(baseURL, "/") + "/v1/generate",
		client:   &copyClient,
		models:   allowed,
	}, nil
}

func (p *HTTPProvider) Generate(ctx context.Context, request contracts.ProviderRequest) (string, error) {
	if !p.models[request.Model] {
		return "", contracts.ErrInvalidModel
	}
	body, err := json.Marshal(request)
	if err != nil {
		return "", errors.New("provider: encode request")
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, bytes.NewReader(body))
	if err != nil {
		return "", errors.New("provider: build request")
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	response, err := p.client.Do(httpRequest)
	if err != nil {
		return "", fmt.Errorf("provider: request failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return "", fmt.Errorf("provider: unexpected status %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, (4<<20)+1))
	if err != nil || len(data) > 4<<20 {
		return "", errors.New("provider: oversized or unreadable response")
	}
	var decoded struct {
		RequestID *string `json:"request_id"`
		Text      *string `json:"text"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return "", errors.New("provider: invalid response")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return "", errors.New("provider: trailing response data")
	}
	if decoded.RequestID == nil || decoded.Text == nil || *decoded.RequestID != request.RequestID {
		return "", errors.New("provider: request ID mismatch")
	}
	return *decoded.Text, nil
}
