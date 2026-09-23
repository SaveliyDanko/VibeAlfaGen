// Package store defines the Store interface and a concurrent in-memory TTL
// store. The store keeps original + masked + findings per payload_id so that
// retries and demasking can be served deterministically.
package store

import (
	"context"
	"sync"
	"time"

	"github.com/alfagen/pii-service/internal/pii"
)

// Record is a stored entry for a payload_id.
type Record struct {
	// Original is the exact original text.
	Original string
	// Masked is the masked text returned to the caller.
	Masked string
	// Findings are the applied findings (values are internal, never logged).
	Findings []pii.Finding `json:",omitempty"`
	// TransformMap maps unique generated markers to their original fragments.
	// It is used only inside the trusted process for proxy demasking.
	TransformMap map[string]string `json:",omitempty"`
	// TokenNonce is generated once for a new token context and encrypted with
	// the rest of the record. Optional for legacy envelope-v2 compatibility.
	TokenNonce string `json:",omitempty"`
	// CreatedAt is the creation time.
	CreatedAt     time.Time
	ExpiresAt     time.Time
	PolicyVersion string
}

// Store is the persistence interface for processed payloads.
type Store interface {
	// Get returns the record for id, or nil if absent.
	Get(context.Context, string) (*Record, bool, error)
	// CreateIfAbsent atomically stores rec for id only if id is absent.
	// It returns the stored record and whether it was newly created.
	CreateIfAbsent(context.Context, string, *Record) (*Record, bool, error)
}

// TTLStore is a concurrent in-memory store with TTL-based expiry.
type TTLStore struct {
	mu      sync.RWMutex
	items   map[string]*item
	ttl     time.Duration
	nowFunc func() time.Time
}

type item struct {
	rec     *Record
	expires time.Time
}

// NewTTLStore creates a TTL store. ttl <= 0 disables expiry.
func NewTTLStore(ttl time.Duration) *TTLStore {
	return &TTLStore{
		items:   make(map[string]*item),
		ttl:     ttl,
		nowFunc: time.Now,
	}
}

// Get implements Store.
func (s *TTLStore) Get(ctx context.Context, id string) (*Record, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	s.mu.RLock()
	it, ok := s.items[id]
	if !ok {
		s.mu.RUnlock()
		return nil, false, nil
	}
	if s.expired(it) {
		s.mu.RUnlock()
		s.mu.Lock()
		if s.items[id] == it {
			delete(s.items, id)
		}
		s.mu.Unlock()
		return nil, false, nil
	}
	// Stored records are immutable; map replacement/cleanup cannot mutate them.
	rec := it.rec
	s.mu.RUnlock()
	return cloneRecord(rec), true, nil
}

// Put implements Store.
func (s *TTLStore) Put(id string, rec *Record) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[id] = &item{rec: cloneRecord(rec), expires: s.recordExpiry(rec)}
}

// CreateIfAbsent implements Store atomically.
func (s *TTLStore) CreateIfAbsent(ctx context.Context, id string, rec *Record) (*Record, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if it, ok := s.items[id]; ok && !s.expired(it) {
		return cloneRecord(it.rec), false, nil
	}
	it := &item{rec: cloneRecord(rec), expires: s.recordExpiry(rec)}
	s.items[id] = it
	return cloneRecord(rec), true, nil
}

func cloneRecord(rec *Record) *Record {
	if rec == nil {
		return nil
	}
	clone := *rec
	clone.Findings = append([]pii.Finding(nil), rec.Findings...)
	if rec.TransformMap != nil {
		clone.TransformMap = make(map[string]string, len(rec.TransformMap))
		for key, value := range rec.TransformMap {
			clone.TransformMap[key] = value
		}
	}
	return &clone
}

// Delete implements Store.
func (s *TTLStore) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, id)
}

// Len implements Store.
func (s *TTLStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.items)
}

// Cleanup removes expired entries. It is safe to call periodically.
func (s *TTLStore) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.nowFunc()
	for id, it := range s.items {
		if !it.expires.IsZero() && !now.Before(it.expires) {
			delete(s.items, id)
		}
	}
}

func (s *TTLStore) expired(it *item) bool {
	if it.expires.IsZero() {
		return false
	}
	return !s.nowFunc().Before(it.expires)
}

func (s *TTLStore) recordExpiry(rec *Record) time.Time {
	if !rec.ExpiresAt.IsZero() {
		return rec.ExpiresAt
	}
	return s.expiry()
}
func (s *TTLStore) Check(ctx context.Context) error { return ctx.Err() }

func (s *TTLStore) expiry() time.Time {
	if s.ttl <= 0 {
		return time.Time{}
	}
	return s.nowFunc().Add(s.ttl)
}
