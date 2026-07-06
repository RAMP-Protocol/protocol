package connectserver_test

// ClassifyReject is the SDK-owned single source of verify-gate reject
// classification: each meaningful cause maps to a distinct, stable audit token,
// keyed off the gate's own sentinels — so no consumer re-derives the mapping.

import (
	"errors"
	"fmt"
	"testing"

	rampserver "github.com/RAMP-Protocol/protocol/sdk/go/connectserver"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

func TestClassifyReject_DistinctReasonPerSentinel(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		err   error
		want  rampserver.RejectReason
		token string
	}{
		{"hop budget", helpers.ErrTooManyHops, rampserver.ReasonHopBudget, "hop_budget"},
		{"replay", rampserver.ErrReplayed, rampserver.ReasonReplay, "replay"},
		{"broken chain", helpers.ErrBrokenSignatureChain, rampserver.ReasonBrokenChain, "broken_chain"},
		{"signature", helpers.ErrSignatureVerify, rampserver.ReasonSignature, "signature"},
		{"unknown", errors.New("boom"), rampserver.ReasonSignature, "signature"},
		{"wrapped replay", fmt.Errorf("gate: %w", rampserver.ErrReplayed), rampserver.ReasonReplay, "replay"},
		{"wrapped chain", fmt.Errorf("x: %w", helpers.ErrBrokenSignatureChain), rampserver.ReasonBrokenChain, "broken_chain"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := rampserver.ClassifyReject(tc.err)
			if got != tc.want {
				t.Fatalf("ClassifyReject(%v) = %v, want %v", tc.err, got, tc.want)
			}
			if got.String() != tc.token {
				t.Fatalf("%v.String() = %q, want %q", got, got.String(), tc.token)
			}
		})
	}
}
