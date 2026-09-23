package client

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"unicode/utf8"
)

// LoadDataset checks fixture integrity at startup; token counts are certified
// offline by scripts/generate-load-data.py --verify using the named tokenizer.
// No tokenizer runs on the load-generation hot path.
func LoadDataset(path string) ([]string, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	var manifest struct {
		Schema   string `json:"schema"`
		Encoding string `json:"encoding"`
		Tokens   int    `json:"tokens_per_payload"`
		Payloads []struct {
			File   string `json:"file"`
			Bytes  int    `json:"bytes"`
			Tokens int    `json:"tokens"`
			SHA256 string `json:"sha256"`
		} `json:"payloads"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, "", fmt.Errorf("invalid dataset manifest")
	}
	if manifest.Schema != "alfagen.load-data.v1" || manifest.Encoding != "cl100k_base" || manifest.Tokens != 100000 || len(manifest.Payloads) == 0 || len(manifest.Payloads) > 100 {
		return nil, "", fmt.Errorf("unsupported dataset manifest")
	}
	payloads := make([]string, 0, len(manifest.Payloads))
	for i, entry := range manifest.Payloads {
		if entry.File != filepath.Base(entry.File) || entry.File == "." || entry.Tokens != manifest.Tokens || entry.Bytes <= 0 || entry.Bytes > 2<<20 {
			return nil, "", fmt.Errorf("invalid dataset entry %d", i)
		}
		raw, err := os.ReadFile(filepath.Join(filepath.Dir(path), entry.File))
		if err != nil {
			return nil, "", fmt.Errorf("read dataset entry %d: %w", i, err)
		}
		sum := sha256.Sum256(raw)
		if !utf8.Valid(raw) || len(raw) != entry.Bytes || hex.EncodeToString(sum[:]) != entry.SHA256 {
			return nil, "", fmt.Errorf("dataset entry %d failed integrity check", i)
		}
		payloads = append(payloads, string(raw))
	}
	sum := sha256.Sum256(data)
	return payloads, hex.EncodeToString(sum[:]), nil
}
