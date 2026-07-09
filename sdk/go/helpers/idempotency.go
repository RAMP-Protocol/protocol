package helpers

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
)

// Idempotency (ADR-019 §4). idempotency_key is a required, persisted,
// settlement-bound field on the mutating RPCs (ExecuteTransaction, ReportUsage,
// DisputeTransaction): the server dedupes on it so a replay returns the original
// result and cannot double-charge. The SDK mints a fresh key per call by default;
// to make a call a deliberate replay, the application reuses a stored key. The
// SDK never tracks keys — the server owns the dedup store.

// idempotencyKeyBytes is the entropy per key (128 bits → 22 base64url chars).
const idempotencyKeyBytes = 16

// ErrEmptyIdempotencyKey is returned by ValidateIdempotencyKey for an empty key.
var ErrEmptyIdempotencyKey = errors.New("helpers: idempotency_key must be non-empty")

// NewIdempotencyKey returns a fresh cryptographically-random, URL-safe
// idempotency key. Use it once per logical operation; reuse a stored key only to
// deliberately replay.
func NewIdempotencyKey() (string, error) {
	b := make([]byte, idempotencyKeyBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("helpers: idempotency key entropy: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ValidateIdempotencyKey enforces the protocol's min_len=1 constraint, so the
// SDK rejects an empty key before the server does.
func ValidateIdempotencyKey(key string) error {
	if key == "" {
		return ErrEmptyIdempotencyKey
	}
	return nil
}
