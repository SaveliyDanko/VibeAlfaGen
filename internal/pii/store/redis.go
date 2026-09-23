package store

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisStore struct {
	client redis.UniversalClient
	codec  *Codec
	ttl    time.Duration
	prefix string
}

func NewRedisStore(client redis.UniversalClient, codec *Codec, ttl time.Duration, prefix string) (*RedisStore, error) {
	if client == nil || codec == nil {
		return nil, errors.New("redis store: client and codec are required")
	}
	if ttl <= 0 {
		return nil, errors.New("redis store: positive TTL is required")
	}
	if prefix == "" {
		prefix = "alfagen:context:"
	}
	return &RedisStore{client: client, codec: codec, ttl: ttl, prefix: prefix}, nil
}

func (s *RedisStore) Get(ctx context.Context, id string) (*Record, bool, error) {
	value, err := s.client.Get(ctx, s.prefix+id).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	record, err := s.codec.Open(s.prefix+id, value)
	if err != nil {
		return nil, false, err
	}
	return record, true, nil
}

func (s *RedisStore) CreateIfAbsent(ctx context.Context, id string, rec *Record) (*Record, bool, error) {
	value, err := s.codec.Seal(s.prefix+id, rec)
	if err != nil {
		return nil, false, err
	}
	ttl := s.ttl
	if !rec.ExpiresAt.IsZero() {
		ttl = time.Until(rec.ExpiresAt)
		if ttl <= 0 {
			return nil, false, errors.New("redis store: expired record")
		}
	}
	created, err := s.client.SetNX(ctx, s.prefix+id, value, ttl).Result()
	if err != nil {
		return nil, false, err
	}
	if created {
		return cloneRecord(rec), true, nil
	}
	stored, ok, err := s.Get(ctx, id)
	if err != nil {
		return nil, false, err
	}
	if !ok {
		return nil, false, errors.New("redis store: winner disappeared")
	}
	return stored, false, nil
}

func (s *RedisStore) Check(ctx context.Context) error { return s.client.Ping(ctx).Err() }
