package helpers_test

import (
	"encoding/base64"
	"errors"
	"testing"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

func TestNewIdempotencyKey_formatAndUniqueness(t *testing.T) {
	seen := make(map[string]bool, 1000)
	for i := 0; i < 1000; i++ {
		k, err := helpers.NewIdempotencyKey()
		if err != nil {
			t.Fatal(err)
		}
		if err := helpers.ValidateIdempotencyKey(k); err != nil {
			t.Fatalf("generated key invalid: %v", err)
		}
		if _, err := base64.RawURLEncoding.DecodeString(k); err != nil {
			t.Fatalf("key not base64url-no-pad: %q", k)
		}
		if seen[k] {
			t.Fatalf("collision on %q", k)
		}
		seen[k] = true
	}
}

func TestValidateIdempotencyKey_empty(t *testing.T) {
	if err := helpers.ValidateIdempotencyKey(""); !errors.Is(err, helpers.ErrEmptyIdempotencyKey) {
		t.Errorf("err = %v, want ErrEmptyIdempotencyKey", err)
	}
}
