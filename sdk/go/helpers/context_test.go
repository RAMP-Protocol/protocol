package helpers_test

import (
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// Ported from v2 internal/httpsig/context_test.go: the pure context slot +
// accessors over verified signatures (no Middleware in L1).

func ctxVerified(keyID, label string) helpers.VerifiedRequest {
	pub, _, _ := ed25519.GenerateKey(nil)
	return helpers.VerifiedRequest{
		KeyID:     keyID,
		Algorithm: helpers.AlgEd25519,
		Label:     label,
		Signature: "abc123",
		Created:   1700000000,
		Expires:   1700000300,
		PublicKey: pub,
	}
}

func TestAllSignaturesFromContext_NilContext(t *testing.T) {
	if sigs := helpers.AllSignaturesFromContext(context.Background()); sigs != nil {
		t.Fatalf("AllSignaturesFromContext on empty context = %+v, want nil", sigs)
	}
}

func TestAllSignaturesFromContext_SingleSignature(t *testing.T) {
	v := ctxVerified("key1", "sig1")
	ctx := helpers.NewMultisigContext(context.Background(), []helpers.VerifiedRequest{v})
	sigs := helpers.AllSignaturesFromContext(ctx)
	if len(sigs) != 1 {
		t.Fatalf("AllSignaturesFromContext returned %d sigs, want 1", len(sigs))
	}
	if sigs[0].KeyID != "key1" {
		t.Fatalf("sig[0].KeyID = %q, want key1", sigs[0].KeyID)
	}
}

func TestAllSignaturesFromContext_MultipleSignatures(t *testing.T) {
	v1 := ctxVerified("key1", "sig1")
	v2 := ctxVerified("key2", "sig2")
	ctx := helpers.NewMultisigContext(context.Background(), []helpers.VerifiedRequest{v1, v2})
	sigs := helpers.AllSignaturesFromContext(ctx)
	if len(sigs) != 2 {
		t.Fatalf("AllSignaturesFromContext returned %d sigs, want 2", len(sigs))
	}
	if sigs[0].KeyID != "key1" || sigs[1].KeyID != "key2" {
		t.Fatalf("keyids = %q,%q want key1,key2", sigs[0].KeyID, sigs[1].KeyID)
	}
}

func TestFromContext_BackwardCompatWithMultisig(t *testing.T) {
	v := ctxVerified("key1", "sig1")
	ctx := helpers.NewMultisigContext(context.Background(), []helpers.VerifiedRequest{v})
	sig := helpers.FromContext(ctx)
	if sig == nil || sig.KeyID != "key1" {
		t.Fatalf("FromContext = %+v, want first signature key1", sig)
	}
}

func TestFromContext_BackwardCompatWithSingleSlot(t *testing.T) {
	v := ctxVerified("key1", "sig1")
	ctx := helpers.NewContext(context.Background(), &v)
	sig := helpers.FromContext(ctx)
	if sig == nil || sig.KeyID != "key1" {
		t.Fatalf("FromContext = %+v, want key1", sig)
	}
	// AllSignaturesFromContext falls back to the single slot.
	all := helpers.AllSignaturesFromContext(ctx)
	if len(all) != 1 || all[0].KeyID != "key1" {
		t.Fatalf("AllSignaturesFromContext fallback = %+v, want [key1]", all)
	}
}
