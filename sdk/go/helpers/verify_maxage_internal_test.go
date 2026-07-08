package helpers

// Internal test: the MaxSignatureAge lifetime clamp lives in the unexported
// enforceCreatedExpires, so it is exercised from inside the package.

import (
	"errors"
	"testing"
	"time"
)

func TestEnforceCreatedExpires_MaxAgeClamp(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	nowUnix := now.Unix()
	const skew = 300 * time.Second

	cases := []struct {
		name    string
		created int64
		expires int64
		maxAge  time.Duration
		wantErr error
	}{
		{
			name: "no clamp: far-future expires accepted when maxAge unset",
			// The pre-M-5 behavior — a 10y window passes without a lifetime bound.
			created: nowUnix, expires: nowUnix + int64((10 * 365 * 24 * time.Hour).Seconds()),
			maxAge: 0, wantErr: nil,
		},
		{
			name:    "clamp: window within maxAge accepted",
			created: nowUnix, expires: nowUnix + 120,
			maxAge: 5 * time.Minute, wantErr: nil,
		},
		{
			name:    "clamp: window equal to maxAge accepted (inclusive)",
			created: nowUnix, expires: nowUnix + 300,
			maxAge: 5 * time.Minute, wantErr: nil,
		},
		{
			name:    "clamp: window exceeding maxAge rejected",
			created: nowUnix, expires: nowUnix + 301,
			maxAge: 5 * time.Minute, wantErr: ErrSignatureLifetimeTooLong,
		},
		{
			name: "clamp: signer-chosen 10y window rejected under a minutes clamp",
			created: nowUnix, expires: nowUnix + int64((10 * 365 * 24 * time.Hour).Seconds()),
			maxAge: 5 * time.Minute, wantErr: ErrSignatureLifetimeTooLong,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := sigParams{Created: tc.created, Expires: tc.expires}
			err := enforceCreatedExpires(p, now, skew, tc.maxAge)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("enforceCreatedExpires = %v, want %v", err, tc.wantErr)
			}
		})
	}
}
