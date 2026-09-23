package admin

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"time"
)

// The destination is deployment configuration, never a URL from the browser
// or the mutable load-test form. Redirects must not forward system credentials.
func newProcessClient(target string) (*http.Client, error) {
	if target == "" {
		return nil, nil
	}
	u, err := url.Parse(target)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Path != "/process" || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("admin: process URL must be an HTTP(S) /process endpoint without credentials, query or fragment")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.MaxConnsPerHost = 8
	return &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}}, nil
}

type manualInput struct {
	SystemID  string  `json:"system_id"`
	PayloadID string  `json:"payload_id"`
	Payload   *string `json:"payload"`
}

type manualResponse struct {
	UpstreamStatus int          `json:"upstream_status"`
	ElapsedMS      float64      `json:"elapsed_ms"`
	Result         *string      `json:"result,omitempty"`
	Error          *manualError `json:"error,omitempty"`
}

type manualError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (s *Server) manualProcess(w http.ResponseWriter, r *http.Request) {
	var input manualInput
	if err := decodeJSON(r, &input); err != nil || input.Payload == nil || input.PayloadID == "" || len(input.PayloadID) > 256 || !managedIDPattern.MatchString(input.SystemID) {
		// Decoder errors may contain user input. Never return or log them here.
		writeError(w, 400, "invalid_manual_input", "Укажите систему, payload ID (до 256 байт) и строку payload. JSON-запрос должен быть не больше 1 МиБ.")
		return
	}
	if s.processClient == nil {
		writeError(w, 503, "manual_unavailable", "Ручная проверка не настроена: задайте ALFAGEN_ADMIN_PROCESS_URL на сервере.")
		return
	}
	key, err := s.store.manualCredential(input.SystemID)
	if err != nil {
		writeError(w, 400, "manual_credentials", err.Error())
		return
	}
	body, _ := json.Marshal(struct {
		PayloadID string `json:"payload_id"`
		Payload   string `json:"payload"`
	}{input.PayloadID, *input.Payload})
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, s.opts.ProcessURL, bytes.NewReader(body))
	if err != nil {
		writeError(w, 503, "manual_unavailable", "Не удалось создать запрос к backend.")
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-System-ID", input.SystemID)
	if key != "" {
		req.Header.Set("X-API-Key", key)
	}
	started := time.Now()
	response, err := s.processClient.Do(req)
	if err != nil {
		// Neither the payload nor transport errors (which can contain URLs) are logged.
		writeError(w, 502, "backend_unavailable", "Backend недоступен или не ответил за 10 секунд. Проверьте соединение; запрос мог быть обработан, повтор с тем же ID безопасен.")
		return
	}
	defer response.Body.Close()
	result, err := readManualResponse(response)
	if err != nil {
		writeError(w, 502, "backend_response", "Backend вернул некорректный или слишком большой ответ.")
		return
	}
	result.ElapsedMS = float64(time.Since(started).Microseconds()) / 1000
	// Upstream 401 is data, not an expired administrator session.
	writeJSON(w, 200, result)
}

func (s *Store) manualCredential(systemID string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg, _, err := s.loadBackendLocked()
	if err != nil {
		return "", errors.New("не удалось прочитать настройки систем")
	}
	index := systemIndex(cfg, systemID)
	if index < 0 {
		return "", errors.New("выберите существующую систему из раздела «Доступ»")
	}
	system := &cfg.Systems[index]
	if system.Enabled != nil && !*system.Enabled {
		return "", errors.New("система отключена. Включите её в разделе «Доступ»")
	}
	if system.APIKeyFile != "" && filepath.Dir(system.APIKeyFile) == filepath.Clean(s.opts.RuntimeAPIKeyDir) {
		system.APIKeyFile = filepath.Join(s.opts.APIKeyDir, filepath.Base(system.APIKeyFile))
	}
	consumer, ok := cfg.ResolveSystem(systemID)
	if !ok {
		return "", errors.New("не удалось прочитать ключ или политику системы. Проверьте настройки доступа")
	}
	return consumer.APIKey, nil
}

func readManualResponse(response *http.Response) (manualResponse, error) {
	result := manualResponse{UpstreamStatus: response.StatusCode}
	if response.StatusCode != http.StatusOK {
		// Do not proxy arbitrary error pages or reflected user text from upstream.
		result.Error = &manualError{Code: "backend_rejected", Message: manualStatusMessage(response.StatusCode)}
		return result, nil
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, (4<<20)+1))
	if err != nil || len(raw) > 4<<20 {
		return result, errors.New("invalid response size")
	}
	var body struct {
		Result *string `json:"result"`
	}
	if err := json.Unmarshal(raw, &body); err != nil || body.Result == nil {
		return result, errors.New("invalid process response")
	}
	result.Result = body.Result
	return result, nil
}

func manualStatusMessage(status int) string {
	switch status {
	case 400:
		return "Backend отклонил payload или payload ID."
	case 401:
		return "Backend не принял API-ключ системы. После ротации дождитесь применения настроек."
	case 403:
		return "Доступ запрещён. Проверьте активность системы и разрешение демаскирования."
	case 409:
		return "Этот payload ID уже связан с другим текстом. Отправьте исходник, точную маску или используйте новый ID."
	case 410:
		return "Контекст восстановления больше недоступен. Создайте новый ID и повторите маскирование исходника."
	case 413:
		return "Текст превышает допустимый размер запроса backend."
	case 429:
		return "Превышен лимит запросов. Повторите позже."
	case 503, 504:
		return "Сервис обработки временно недоступен или не успел ответить. Повторите позже с тем же ID."
	default:
		return "Backend отклонил запрос. Код HTTP указан рядом с результатом."
	}
}
