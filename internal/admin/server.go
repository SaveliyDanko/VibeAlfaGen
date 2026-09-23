package admin

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/alfagen/pii-service/internal/mock/client"
)

//go:embed web/*
var webFiles embed.FS

type ServerOptions struct {
	PrometheusURL       string
	ProcessURL          string
	DisableCertificates bool
	AdminTokenFile      string
	SecureCookies       bool
	SessionTTL          time.Duration
	Logger              *slog.Logger
}

type Server struct {
	throughputSource *throughputSource
	processClient    *http.Client
	store            *Store
	opts             ServerOptions
	token            []byte
	mux              *http.ServeMux
	mu               sync.Mutex
	sessions         map[string]time.Time
}

func NewServer(store *Store, opts ServerOptions) (*Server, error) {
	if store == nil || opts.AdminTokenFile == "" {
		return nil, errors.New("admin: store and admin token file are required")
	}
	raw, err := os.ReadFile(opts.AdminTokenFile)
	if err != nil {
		return nil, errors.New("admin: cannot read admin token file")
	}
	if len(raw) > 4096 {
		return nil, errors.New("admin: admin token file is too large")
	}
	token := []byte(strings.TrimSpace(string(raw)))
	if len(token) < 24 {
		return nil, errors.New("admin: admin token must contain at least 24 characters")
	}
	if opts.SessionTTL <= 0 {
		opts.SessionTTL = 8 * time.Hour
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	s := &Server{store: store, opts: opts, token: token, mux: http.NewServeMux(), sessions: make(map[string]time.Time)}
	s.processClient, err = newProcessClient(opts.ProcessURL)
	if err != nil {
		return nil, err
	}
	s.throughputSource, err = newThroughputSource(opts.PrometheusURL)
	if err != nil {
		return nil, err
	}
	s.routes()
	return s, nil
}

func (s *Server) Handler() http.Handler { return s.securityHeaders(s.mux) }

func (s *Server) routes() {
	s.mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	s.mux.HandleFunc("POST /api/v1/session", s.login)
	s.mux.HandleFunc("DELETE /api/v1/session", s.auth(s.logout))
	s.mux.HandleFunc("GET /api/v1/dashboard", s.auth(s.dashboard))
	s.mux.HandleFunc("GET /api/v1/metrics/throughput", s.auth(s.throughput))
	s.mux.HandleFunc("GET /api/v1/systems", s.auth(s.systems))
	s.mux.HandleFunc("PUT /api/v1/systems/{id}", s.auth(s.mutate(s.putSystem)))
	s.mux.HandleFunc("DELETE /api/v1/systems/{id}", s.auth(s.mutate(s.deleteSystem)))
	s.mux.HandleFunc("POST /api/v1/systems/{id}/rotate-key", s.auth(s.mutate(s.rotateKey)))
	s.mux.HandleFunc("GET /api/v1/certificates", s.auth(s.certificates))
	s.mux.HandleFunc("POST /api/v1/certificates/{id}", s.auth(s.mutate(s.issueCertificate)))
	s.mux.HandleFunc("DELETE /api/v1/certificates/{id}/{serial}", s.auth(s.mutate(s.revokeCertificate)))
	s.mux.HandleFunc("GET /api/v1/tests/config", s.auth(s.testConfig))
	s.mux.HandleFunc("PUT /api/v1/tests/config", s.auth(s.mutate(s.putTestConfig)))
	s.mux.HandleFunc("POST /api/v1/tests/start", s.auth(s.mutate(s.startTest)))
	s.mux.HandleFunc("POST /api/v1/tests/stop", s.auth(s.mutate(s.stopTest)))
	s.mux.HandleFunc("GET /api/v1/tests/report", s.auth(s.testReport))
	s.mux.HandleFunc("GET /api/v1/audit", s.auth(s.audit))
	s.mux.HandleFunc("POST /api/v1/playground/process", s.auth(s.mutate(s.manualProcess)))
	content, _ := fs.Sub(webFiles, "web")
	s.mux.Handle("GET /assets/", http.StripPrefix("/assets/", http.FileServer(http.FS(content))))
	s.mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		raw, err := webFiles.ReadFile("web/index.html")
		if err != nil {
			http.Error(w, "UI unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(raw)
	})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Token string `json:"token"`
	}
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	provided := []byte(input.Token)
	if len(provided) != len(s.token) || subtle.ConstantTimeCompare(provided, s.token) != 1 {
		time.Sleep(150 * time.Millisecond)
		writeError(w, http.StatusUnauthorized, "unauthorized", "invalid credentials")
		return
	}
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		writeError(w, 500, "internal", "could not create session")
		return
	}
	id := base64.RawURLEncoding.EncodeToString(value[:])
	expires := time.Now().Add(s.opts.SessionTTL)
	s.mu.Lock()
	for key, deadline := range s.sessions {
		if time.Now().After(deadline) {
			delete(s.sessions, key)
		}
	}
	s.sessions[id] = expires
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "alfagen_admin", Value: id, Path: "/", HttpOnly: true, Secure: s.opts.SecureCookies, SameSite: http.SameSiteStrictMode, Expires: expires, MaxAge: int(s.opts.SessionTTL.Seconds())})
	writeJSON(w, 200, map[string]any{"authenticated": true, "expires_at": expires})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("alfagen_admin"); err == nil {
		s.mu.Lock()
		delete(s.sessions, cookie.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "alfagen_admin", Path: "/", HttpOnly: true, Secure: s.opts.SecureCookies, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("alfagen_admin")
		if err != nil {
			writeError(w, 401, "unauthorized", "authentication required")
			return
		}
		s.mu.Lock()
		expires, ok := s.sessions[cookie.Value]
		if ok && time.Now().After(expires) {
			delete(s.sessions, cookie.Value)
			ok = false
		}
		s.mu.Unlock()
		if !ok {
			writeError(w, 401, "unauthorized", "session expired")
			return
		}
		next(w, r)
	}
}

func (s *Server) mutate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-AlfaGen-CSRF") != "1" {
			writeError(w, 403, "csrf", "missing CSRF header")
			return
		}
		next(w, r)
	}
}

func (s *Server) dashboard(w http.ResponseWriter, _ *http.Request) {
	access, err := s.store.AccessSnapshot()
	if err != nil {
		s.fail(w, err)
		return
	}
	certs, err := s.store.Certificates()
	if err != nil {
		s.fail(w, err)
		return
	}
	test, err := s.store.TestSnapshot()
	if err != nil {
		s.fail(w, err)
		return
	}
	activeCerts := 0
	for _, cert := range certs {
		if !cert.Revoked && cert.NotAfter.After(time.Now()) {
			activeCerts++
		}
	}
	writeJSON(w, 200, map[string]any{"certificates_enabled": !s.opts.DisableCertificates, "access": access, "certificates": certs, "test": test, "summary": map[string]any{"systems": len(access.Systems), "active_certificates": activeCerts, "test_running": test.Status.State == "running"}})
}

func (s *Server) systems(w http.ResponseWriter, _ *http.Request) {
	result, err := s.store.AccessSnapshot()
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, result)
}
func (s *Server) putSystem(w http.ResponseWriter, r *http.Request) {
	var input SystemInput
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, 400, "invalid_request", err.Error())
		return
	}
	result, err := s.store.UpsertSystem(r.PathValue("id"), input)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, result)
}
func (s *Server) deleteSystem(w http.ResponseWriter, r *http.Request) {
	result, err := s.store.DeleteSystem(r.PathValue("id"), r.URL.Query().Get("revision"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, result)
}
func (s *Server) rotateKey(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Revision string `json:"revision"`
	}
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, 400, "invalid_request", err.Error())
		return
	}
	result, err := s.store.RotateAPIKey(r.PathValue("id"), input.Revision)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, result)
}
func (s *Server) certificates(w http.ResponseWriter, _ *http.Request) {
	result, err := s.store.Certificates()
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"certificates": result, "crl_path": "ca.crl", "reload_required_after_revocation": true})
}
func (s *Server) issueCertificate(w http.ResponseWriter, r *http.Request) {
	result, err := s.store.IssueCertificate(r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 201, result)
}
func (s *Server) revokeCertificate(w http.ResponseWriter, r *http.Request) {
	result, err := s.store.RevokeCertificate(r.PathValue("id"), r.PathValue("serial"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"certificate": result, "edge_reload_required": true})
}
func (s *Server) testConfig(w http.ResponseWriter, _ *http.Request) {
	result, err := s.store.TestSnapshot()
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, result)
}
func (s *Server) putTestConfig(w http.ResponseWriter, r *http.Request) {
	var input TestInput
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, 400, "invalid_request", err.Error())
		return
	}
	result, err := s.store.UpdateTest(input)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, result)
}
func (s *Server) startTest(w http.ResponseWriter, r *http.Request) { s.toggleTest(w, r, true) }
func (s *Server) stopTest(w http.ResponseWriter, r *http.Request)  { s.toggleTest(w, r, false) }
func (s *Server) toggleTest(w http.ResponseWriter, r *http.Request, enabled bool) {
	var input struct {
		Revision string            `json:"revision"`
		Config   *client.DocConfig `json:"config,omitempty"`
	}
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, 400, "invalid_request", err.Error())
		return
	}
	var result MutationResult
	var err error
	if enabled {
		result, err = s.store.StartTest(input.Revision, input.Config)
	} else {
		result, err = s.store.SetTestEnabled(input.Revision, false)
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, result)
}
func (s *Server) testReport(w http.ResponseWriter, _ *http.Request) {
	result, err := s.store.ReadReport()
	if errors.Is(err, os.ErrNotExist) {
		writeJSON(w, 200, map[string]any{"available": false})
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	var report any
	if err := json.Unmarshal(result, &report); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"available": true, "report": report})
}
func (s *Server) audit(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	result, err := s.store.Audit(limit)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"entries": result})
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	status, code, message := 500, "internal", "operation failed"
	if errors.Is(err, ErrRevisionConflict) {
		status, code, message = 409, "revision_conflict", err.Error()
	} else if errors.Is(err, ErrTestActive) {
		status, code, message = 409, "test_active", err.Error()
	} else if errors.Is(err, os.ErrNotExist) {
		status, code, message = 404, "not_found", "resource not found"
	} else if text := err.Error(); strings.HasPrefix(text, "config:") || strings.HasPrefix(text, "mock-client config:") || strings.HasPrefix(text, "admin: invalid") || strings.Contains(text, "requires key generation") || strings.Contains(text, "cannot be deleted") || strings.Contains(text, "access_mode must") {
		status, code, message = 400, "invalid_request", text
	}
	if status >= 500 {
		s.opts.Logger.Error("admin request failed", "error", err)
	}
	writeError(w, status, code, message)
}

func decodeJSON(r *http.Request, target any) error {
	limited := &io.LimitedReader{R: r.Body, N: (1 << 20) + 1}
	dec := json.NewDecoder(limited)
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return errors.New("expected one JSON document")
	}
	if limited.N <= 0 {
		return errors.New("JSON document is too large")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/assets/") || r.URL.Path == "/" {
			w.Header().Set("Cache-Control", "no-store")
		}
		if s.opts.DisableCertificates && strings.HasPrefix(r.URL.Path, "/api/v1/certificates") {
			writeError(w, 409, "certificates_disabled", "Client certificates are not enabled on this HTTPS deployment")
			return
		}
		next.ServeHTTP(w, r)
	})
}
