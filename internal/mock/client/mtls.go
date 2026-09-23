package client

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
)

// ConfigureMTLS installs a client certificate and a dedicated trust bundle.
// It must be called before Run; certificate material is never copied into the
// reloadable workload configuration or reports.
func (r *Runner) ConfigureMTLS(caFile, certFile, keyFile string) error {
	if caFile == "" || certFile == "" || keyFile == "" {
		return errors.New("mTLS CA, certificate and key files are all required")
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return fmt.Errorf("read mTLS CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return errors.New("mTLS CA file contains no certificates")
	}
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("load mTLS client certificate: %w", err)
	}
	transport := runnerTransport(r.currentConfig().MaxConnections)
	transport.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{certificate},
	}
	r.httpClient = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}, Transport: &mtlsTransport{Transport: transport}}
	return nil
}

// Enforce HTTPS at dispatch time, including targets changed by config reload.
type mtlsTransport struct{ *http.Transport }

func (t *mtlsTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" {
		return nil, errors.New("mTLS requires an HTTPS target")
	}
	return t.Transport.RoundTrip(req)
}
