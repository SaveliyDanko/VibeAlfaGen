package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"unicode/utf8"
)

var (
	ErrInvalidJSON  = errors.New("invalid_json")
	ErrMissingField = errors.New("missing_field")
	ErrExtraField   = errors.New("extra_field")
	ErrBodyTooLarge = errors.New("body_too_large")
)

type request struct {
	Payload   *string `json:"payload"`
	PayloadID *string `json:"payload_id"`
}
type response struct {
	Result string `json:"result"`
}

func decodeObject(r *http.Request, maxBytes int64, allowed []string, values []**string) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBytes+1))
	if err != nil {
		if r.Context().Err() != nil {
			return r.Context().Err()
		}
		return ErrInvalidJSON
	}
	if int64(len(body)) > maxBytes {
		return ErrBodyTooLarge
	}
	if !utf8.Valid(body) {
		return ErrInvalidJSON
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	token, err := dec.Token()
	if err != nil || token != json.Delim('{') {
		return ErrInvalidJSON
	}
	if err := decodeFields(dec, allowed, values); err != nil {
		return err
	}
	if _, err = dec.Token(); err != nil {
		return ErrInvalidJSON
	}
	if _, err = dec.Token(); err != io.EOF {
		return ErrExtraField
	}
	return nil
}
func decodeRequest(r *http.Request, maxBytes int64) (*request, error) {
	var req request
	if err := decodeObject(r, maxBytes, []string{"payload", "payload_id"}, []**string{&req.Payload, &req.PayloadID}); err != nil {
		return nil, err
	}
	if req.Payload == nil || req.PayloadID == nil || *req.PayloadID == "" {
		return nil, ErrMissingField
	}
	return &req, nil
}

func decodeFields(dec *json.Decoder, allowed []string, values []**string) error {
	var seen uint32
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return ErrInvalidJSON
		}
		name, ok := token.(string)
		if !ok {
			return ErrInvalidJSON
		}
		index := slices.Index(allowed, name)
		if index < 0 || seen&(1<<index) != 0 {
			return ErrExtraField
		}
		seen |= 1 << index
		if dec.Decode(values[index]) != nil {
			return ErrInvalidJSON
		}
	}
	return nil
}
