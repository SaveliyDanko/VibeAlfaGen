package admin

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

func (s *Store) crlLifetime() time.Duration {
	if s.opts.CRLLifetime > 0 {
		return s.opts.CRLLifetime
	}
	return 7 * 24 * time.Hour
}

// A separate renewal process shares the same writer lock as certificate revokes.
func (s *Store) lockPKI() (func(), error) {
	file, err := os.OpenFile(filepath.Join(s.opts.MTLSDir, ".pki.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := inheritDirectoryOwner(file, s.opts.MTLSDir); err != nil {
		file.Close()
		return nil, err
	}
	if err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		file.Close()
		return nil, err
	}
	return func() { _ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN); file.Close() }, nil
}

func (s *Store) readCRLLocked() (*x509.RevocationList, error) {
	raw, err := readLimited(filepath.Join(s.opts.MTLSDir, "ca.crl"))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("admin: invalid CRL PEM")
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return nil, err
	}
	ca, _, _, err := s.loadCALocked()
	if err != nil {
		return nil, err
	}
	if err := crl.CheckSignatureFrom(ca); err != nil {
		return nil, err
	}
	return crl, nil
}

// Union both persistent sources, including revocations from imported CRLs.
// A partially completed write must never reinstate a revoked certificate.
func (s *Store) allRevocationsLocked() ([]revocationRecord, error) {
	records, err := s.loadRevocationsLocked()
	if err != nil {
		return nil, err
	}
	crl, err := s.readCRLLocked()
	if errors.Is(err, os.ErrNotExist) {
		return records, nil
	}
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, r := range records {
		seen[r.Serial] = true
	}
	for _, r := range crl.RevokedCertificateEntries {
		serial := r.SerialNumber.Text(16)
		if !seen[serial] {
			records = append(records, revocationRecord{Serial: serial, RevokedAt: r.RevocationTime})
			seen[serial] = true
		}
	}
	return records, nil
}

// RefreshCRL renews before expiry, retaining every revocation. force is for
// offline profiles that explicitly choose a CRL lifetime up to CA expiration.
func (s *Store) RefreshCRL(now time.Time, force bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := s.lockPKI()
	if err != nil {
		return err
	}
	defer unlock()
	crl, err := s.readCRLLocked()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if !force && err == nil && crl.NextUpdate.After(now.Add(24*time.Hour)) {
		return s.publishCRLLocked(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crl.Raw}))
	}
	records, err := s.allRevocationsLocked()
	if err != nil {
		return err
	}
	return s.writeRevocationsAndCRLLocked(records)
}

// The base Compose renewal service can run as root while the optional admin
// uses the host UID. Keep newly written state owned by the mounted directory.
func inheritDirectoryOwner(file *os.File, dir string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	stat := info.Sys().(*syscall.Stat_t)
	return file.Chown(int(stat.Uid), int(stat.Gid))
}

func (s *Store) publishCRLLocked(raw []byte) error {
	dir := filepath.Join(s.opts.MTLSDir, "public")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	path := filepath.Join(dir, "ca.crl")
	existing, err := os.ReadFile(path)
	if err == nil && bytes.Equal(existing, raw) {
		return nil
	}
	return atomicWrite(path, raw, 0644)
}
