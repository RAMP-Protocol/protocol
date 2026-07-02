package ramp_test

// Coverage for the opt-in bidirectional protovalidate interceptor
// (WithValidation(ValidationStrict)). The binding round-trip suites in
// client_verify_test.go exercise the DEFAULT (ValidationOff) so their minimal
// offer fixtures reach the origin; this file pins the OTHER half of the option:
// once a caller opts into strict validation, a proto-invalid request is rejected
// with CodeInvalidArgument before it can be executed. Together they prove the
// interceptor is present, wired via the option, and correct.

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/ramp"
)

// TestWithValidation_StrictRejectsInvalidRequest pins that under
// WithValidation(ValidationStrict) the client's validate interceptor rejects a
// request whose reflected offer violates the proto rules (an offer with no
// pricing.model — not_in [0]) with CodeInvalidArgument, before the round-trip. The
// default suites leave validation Off so their minimal fixtures pass; this asserts
// the strict path is real.
func TestWithValidation_StrictRejectsInvalidRequest(t *testing.T) {
	t.Parallel()
	sig := newSigningFixture(t)
	off := newOfferFixture(t)
	replay := newMemReplayStore()
	srv := newVerifyingServer(t, sig, replay, []*rampv1.Offer{off.good})

	// Client A (validation Off) surfaces the offer so we can obtain a VerifiedOffer
	// wrapping the proto-minimal fixture (no pricing.model).
	surfacer := ramp.NewClient(srv.URL,
		ramp.WithSigner(sig.signer),
		ramp.WithVerification(ramp.Off),
	)
	res, err := surfacer.Discover(context.Background(), &rampv1.ResourceQuery{})
	if err != nil {
		t.Fatalf("Discover under Off verification must surface the offer: %v", err)
	}
	if len(res.Verified) != 1 {
		t.Fatalf("want 1 surfaced offer, got %d", len(res.Verified))
	}

	// Client B opts into strict validation: its outbound Execute request reflects
	// the model-less offer, which the bidirectional validate interceptor must reject
	// with CodeInvalidArgument BEFORE the round-trip.
	strict := ramp.NewClient(srv.URL,
		ramp.WithSigner(sig.signer),
		ramp.WithValidation(ramp.ValidationStrict),
	)
	_, err = strict.Execute(context.Background(), res.Verified[0])
	if err == nil {
		t.Fatal("strict validation must reject an offer with no pricing.model")
	}
	if got := connect.CodeOf(err); got != connect.CodeInvalidArgument {
		t.Fatalf("strict validation: want CodeInvalidArgument, got %v (err=%v)", got, err)
	}
}
