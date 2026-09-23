package admin

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/alfagen/pii-service/internal/platform/config"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const caCertificateFile = "ca.crt"

type CertificateView struct {
	SystemID    string    `json:"system_id"`
	Serial      string    `json:"serial"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	Fingerprint string    `json:"fingerprint"`
	Revoked     bool      `json:"revoked"`
}

type CertificateBundle struct {
	Certificate    CertificateView `json:"certificate"`
	CertificatePEM string          `json:"certificate_pem"`
	PrivateKeyPEM  string          `json:"private_key_pem"`
	CAPEM          string          `json:"ca_pem"`
	Notice         string          `json:"notice"`
}

type revocationRecord struct {
	Serial    string    `json:"serial"`
	SystemID  string    `json:"system_id"`
	RevokedAt time.Time `json:"revoked_at"`
}

func (s *Store) Certificates() ([]CertificateView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.certificatesLocked()
}

func (s *Store) IssueCertificate(systemID string) (CertificateBundle, error) {
	if !managedIDPattern.MatchString(systemID) {
		return CertificateBundle{}, errors.New("admin: invalid system id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	backend, _, err := s.loadBackendLocked()
	if err != nil {
		return CertificateBundle{}, err
	}
	if !enabledSystem(backend.Systems, systemID) {
		return CertificateBundle{}, errors.New("admin: certificate requires an enabled allowlisted system")
	}
	ca, signer, caPEM, err := s.loadCALocked()
	if err != nil {
		return CertificateBundle{}, err
	}
	serial, err := randomSerial()
	if err != nil {
		return CertificateBundle{}, err
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: systemID, Organization: []string{"AlfaGen consumers"}},
		NotBefore:    now.Add(-time.Minute), NotAfter: minTime(now.Add(s.opts.CertificateTTL), ca.NotAfter),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return CertificateBundle{}, err
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, signer)
	if err != nil {
		return CertificateBundle{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := s.saveCertificate(systemID, serial.Text(16), certPEM, keyPEM, caPEM); err != nil {
		return CertificateBundle{}, err
	}
	view, err := certificateView(der, false)
	if err != nil {
		return CertificateBundle{}, err
	}
	_ = s.appendAuditLocked("mtls.issue", systemID, "success")
	return CertificateBundle{
		Certificate: view, CertificatePEM: string(certPEM), PrivateKeyPEM: string(keyPEM), CAPEM: string(caPEM),
		Notice: "Private key is returned once. Store it securely; it cannot be retrieved from the admin API.",
	}, nil
}

func (s *Store) RevokeCertificate(systemID, serial string) (CertificateView, error) {
	if !managedIDPattern.MatchString(systemID) || serial == "" {
		return CertificateView{}, errors.New("admin: invalid certificate identity")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := s.lockPKI()
	if err != nil {
		return CertificateView{}, err
	}
	defer unlock()
	path := filepath.Join(s.opts.MTLSDir, "clients", systemID, serial+".crt")
	raw, err := readLimited(path)
	if err != nil {
		return CertificateView{}, err
	}
	cert, err := parseCertificatePEM(raw)
	if err != nil || cert.SerialNumber.Text(16) != serial || cert.Subject.CommonName != systemID {
		return CertificateView{}, errors.New("admin: certificate identity mismatch")
	}
	records, err := s.allRevocationsLocked()
	if err != nil {
		return CertificateView{}, err
	}
	for _, record := range records {
		if record.Serial == serial {
			if err := s.writeRevocationsAndCRLLocked(records); err != nil {
				return CertificateView{}, err
			}
			return certificateView(cert.Raw, true)
		}
	}
	records = append(records, revocationRecord{Serial: serial, SystemID: systemID, RevokedAt: time.Now().UTC()})
	if err := s.writeRevocationsAndCRLLocked(records); err != nil {
		return CertificateView{}, err
	}
	_ = s.appendAuditLocked("mtls.revoke", systemID+":"+serial, "success")
	return certificateView(cert.Raw, true)
}

func (s *Store) certificatesLocked() ([]CertificateView, error) {
	records, err := s.loadRevocationsLocked()
	if err != nil {
		return nil, err
	}
	revoked := make(map[string]bool, len(records))
	for _, record := range records {
		revoked[record.Serial] = true
	}
	root := filepath.Join(s.opts.MTLSDir, "clients")
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return []CertificateView{}, nil
	}
	if err != nil {
		return nil, err
	}
	var views []CertificateView
	for _, entry := range entries {
		if !entry.IsDir() || !managedIDPattern.MatchString(entry.Name()) {
			continue
		}
		found, err := certificatesInDirectory(filepath.Join(root, entry.Name()), revoked)
		if err != nil {
			return nil, err
		}
		views = append(views, found...)

	}
	sort.Slice(views, func(i, j int) bool { return views[i].NotAfter.After(views[j].NotAfter) })
	return views, nil
}

func (s *Store) loadCALocked() (*x509.Certificate, crypto.Signer, []byte, error) {
	certPEM, err := readLimited(filepath.Join(s.opts.MTLSDir, caCertificateFile))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("admin: read mTLS CA certificate: %w", err)
	}
	keyPEM, err := readLimited(filepath.Join(s.opts.MTLSDir, "ca.key"))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("admin: read mTLS CA key: %w", err)
	}
	cert, err := parseCertificatePEM(certPEM)
	if err != nil {
		return nil, nil, nil, err
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, nil, nil, errors.New("admin: invalid CA key PEM")
	}
	var key any
	if parsed, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes); parseErr == nil {
		key = parsed
	} else if parsed, parseErr := x509.ParsePKCS1PrivateKey(block.Bytes); parseErr == nil {
		key = parsed
	} else {
		return nil, nil, nil, errors.New("admin: unsupported CA private key")
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, nil, nil, errors.New("admin: CA key cannot sign")
	}
	return cert, signer, certPEM, nil
}

func (s *Store) loadRevocationsLocked() ([]revocationRecord, error) {
	raw, err := readLimited(filepath.Join(s.opts.MTLSDir, "revocations.json"))
	if errors.Is(err, os.ErrNotExist) {
		return []revocationRecord{}, nil
	}
	if err != nil {
		return nil, err
	}
	var records []revocationRecord
	if err := json.Unmarshal(raw, &records); err != nil {
		return nil, errors.New("admin: invalid revocation registry")
	}
	return records, nil
}

func (s *Store) writeRevocationsAndCRLLocked(records []revocationRecord) error {
	ca, signer, _, err := s.loadCALocked()
	if err != nil {
		return err
	}
	entries := make([]x509.RevocationListEntry, 0, len(records))
	for _, record := range records {
		serial := new(big.Int)
		if _, ok := serial.SetString(record.Serial, 16); !ok {
			return errors.New("admin: invalid revoked serial")
		}
		entries = append(entries, x509.RevocationListEntry{SerialNumber: serial, RevocationTime: record.RevokedAt})
	}
	now := time.Now().UTC()
	number := big.NewInt(now.UnixNano())
	// The original AlfaGen bootstrap produced an X.509 v1 CA without a
	// keyUsage extension. OpenSSL treats the absent extension as unrestricted,
	// while crypto/x509 requires the in-memory issuer to carry cRLSign. Set the
	// bit on a copy for backwards-compatible CRL generation; the CA certificate
	// and trust anchor are not modified.
	crlIssuer := *ca
	crlIssuer.KeyUsage |= x509.KeyUsageCRLSign
	if len(crlIssuer.SubjectKeyId) == 0 {
		identifier := sha256.Sum256(crlIssuer.RawSubjectPublicKeyInfo)
		crlIssuer.SubjectKeyId = append([]byte(nil), identifier[:20]...)
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: number, ThisUpdate: now.Add(-time.Minute), NextUpdate: minTime(now.Add(s.crlLifetime()), ca.NotAfter), RevokedCertificateEntries: entries}, &crlIssuer, signer)
	if err != nil {
		return err
	}
	registry, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}
	registry = append(registry, '\n')
	if err := atomicWrite(filepath.Join(s.opts.MTLSDir, "revocations.json"), registry, 0o600); err != nil {
		return err
	}
	crl := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
	if err := atomicWrite(filepath.Join(s.opts.MTLSDir, "ca.crl"), crl, 0o644); err != nil {
		return err
	}
	return s.publishCRLLocked(crl)
}

func parseCertificatePEM(raw []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("admin: invalid certificate PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

func certificateView(der []byte, revoked bool) (CertificateView, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return CertificateView{}, err
	}
	fingerprint := sha256Hex(cert.Raw)
	return CertificateView{SystemID: cert.Subject.CommonName, Serial: cert.SerialNumber.Text(16), NotBefore: cert.NotBefore, NotAfter: cert.NotAfter, Fingerprint: fingerprint, Revoked: revoked}, nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, err
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	return serial, nil
}

func sha256Hex(raw []byte) string {
	sum := sha256.Sum256(raw)
	return fmt.Sprintf("%x", sum[:])
}

func enabledSystem(systems []config.SystemConfig, id string) bool {
	for _, system := range systems {
		if system.ID == id && (system.Enabled == nil || *system.Enabled) {
			return true
		}
	}
	return false
}

func (s *Store) saveCertificate(systemID, serialName string, certPEM, keyPEM, caPEM []byte) error {
	dir := filepath.Join(s.opts.MTLSDir, "clients", systemID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// Versioned files avoid destroying a still-working credential if a later
	// control-plane step fails. current.* is only metadata, never a secret.

	crtPath := filepath.Join(dir, serialName+".crt")
	keyPath := filepath.Join(dir, serialName+".key")
	if err := atomicWrite(crtPath, certPEM, 0o644); err != nil {
		return err
	}
	if err := atomicWrite(keyPath, keyPEM, 0o600); err != nil {
		_ = os.Remove(crtPath)
		return err
	}
	if err := atomicWrite(filepath.Join(dir, caCertificateFile), caPEM, 0o644); err != nil {
		_ = os.Remove(crtPath)
		_ = os.Remove(keyPath)
		return err
	}
	return nil
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func certificatesInDirectory(dir string, revoked map[string]bool) ([]CertificateView, error) {
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var views []CertificateView
	for _, file := range files {
		if file.IsDir() || filepath.Ext(file.Name()) != ".crt" || file.Name() == caCertificateFile {
			continue
		}
		raw, err := readLimited(filepath.Join(dir, file.Name()))
		if err != nil {
			return nil, err
		}
		cert, err := parseCertificatePEM(raw)
		if err != nil {
			return nil, err
		}
		view, err := certificateView(cert.Raw, revoked[cert.SerialNumber.Text(16)])
		if err != nil {
			return nil, err
		}
		views = append(views, view)
	}
	return views, nil
}
