package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

const envelopeVersion = 2

type encryptedEnvelope struct {
	Version      int    `json:"version"`
	KeyID        string `json:"key_id"`
	Nonce        string `json:"nonce"`
	Ciphertext   string `json:"ciphertext"`
	OriginalHMAC string `json:"original_hmac"`
	MaskedHMAC   string `json:"masked_hmac"`
}

// Codec encrypts context records at rest and supports decrypting records made
// with older configured keys during key rotation.
type Codec struct {
	activeID string
	ciphers  map[string]cipher.AEAD
	macKeys  map[string][2][]byte
}

func NewCodec(activeID string, keys map[string][]byte) (*Codec, error) {
	if activeID == "" {
		return nil, errors.New("store codec: active key ID is required")
	}
	copyKeys := make(map[string][]byte, len(keys))
	for id, key := range keys {
		if len(key) != 32 {
			return nil, fmt.Errorf("store codec: key %q must be 32 bytes", id)
		}
		copyKeys[id] = append([]byte(nil), key...)
	}
	if _, ok := copyKeys[activeID]; !ok {
		return nil, errors.New("store codec: active key is missing")
	}
	c := &Codec{activeID: activeID, ciphers: make(map[string]cipher.AEAD, len(keys)), macKeys: make(map[string][2][]byte, len(keys))}
	for id, key := range copyKeys {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		c.ciphers[id] = gcm
		c.macKeys[id] = [2][]byte{deriveMACKey(key, "original"), deriveMACKey(key, "masked")}
	}
	return c, nil
}

func DecodeKey(value string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(key) != 32 {
		return nil, errors.New("store codec: key must be base64-encoded 32 bytes")
	}
	return key, nil
}

func (c *Codec) Seal(id string, rec *Record) ([]byte, error) {
	gcm := c.ciphers[c.activeID]
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	plaintext, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	aad, _ := json.Marshal([]any{"alfagen-context", envelopeVersion, c.activeID, id})
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)
	envelope := encryptedEnvelope{
		Version: envelopeVersion, KeyID: c.activeID,
		Nonce:        base64.StdEncoding.EncodeToString(nonce),
		Ciphertext:   base64.StdEncoding.EncodeToString(ciphertext),
		OriginalHMAC: macValue(c.macKeys[c.activeID][0], rec.Original),
		MaskedHMAC:   macValue(c.macKeys[c.activeID][1], rec.Masked),
	}
	return json.Marshal(envelope)
}

func (c *Codec) Open(id string, encoded []byte) (*Record, error) {
	var envelope encryptedEnvelope
	if err := json.Unmarshal(encoded, &envelope); err != nil || envelope.Version != envelopeVersion {
		return nil, errors.New("store codec: invalid envelope")
	}
	gcm, ok := c.ciphers[envelope.KeyID]
	if !ok {
		return nil, errors.New("store codec: unknown key version")
	}
	nonce, err := base64.StdEncoding.DecodeString(envelope.Nonce)
	if err != nil {
		return nil, errors.New("store codec: invalid nonce")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		return nil, errors.New("store codec: invalid ciphertext")
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, errors.New("store codec: invalid nonce length")
	}
	aad, _ := json.Marshal([]any{"alfagen-context", envelope.Version, envelope.KeyID, id})
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, errors.New("store codec: authentication failed")
	}
	var rec Record
	if err := json.Unmarshal(plaintext, &rec); err != nil {
		return nil, errors.New("store codec: invalid record")
	}
	if !hmac.Equal([]byte(envelope.OriginalHMAC), []byte(macValue(c.macKeys[envelope.KeyID][0], rec.Original))) ||
		!hmac.Equal([]byte(envelope.MaskedHMAC), []byte(macValue(c.macKeys[envelope.KeyID][1], rec.Masked))) {
		return nil, errors.New("store codec: record digest mismatch")
	}
	return &rec, nil
}

func recordMAC(key []byte, domain, value string) string {
	return macValue(deriveMACKey(key, domain), value)
}

func deriveMACKey(key []byte, domain string) []byte {
	derived := hmac.New(sha256.New, key)
	_, _ = derived.Write([]byte("alfagen-hmac:" + domain))
	return derived.Sum(nil)
}

func macValue(macKey []byte, value string) string {
	mac := hmac.New(sha256.New, macKey)
	_, _ = mac.Write([]byte(value))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
