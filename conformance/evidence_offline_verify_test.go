// Package conformance — evidence_offline_verify_test.go executes the offline
// re-verification recipe the TransactionEvidence proto comment states:
//
//	ed25519.Verify(exchange_signing_public_key, offer_canonical_bytes, hex-decoded offer_sig)
//	ed25519.Verify(agent_public_key, agent_acceptance_canonical_bytes, hex-decoded agent_acceptance_signature)
//
// Every corpus vector is a field-rule mutant carrying filler key material, so
// nothing else in the repo runs the recipe against a row whose signatures are
// real. This test builds one and runs it.
//
// WHAT CAN TURN THIS RED, and what cannot — worth stating, because the two
// halves below look equally load-bearing and are not.
//
// The protovalidate call IS the gate. It asserts that a row built exactly as
// the recipe requires is CONTRACT-VALID, so a field rule that tightens past
// what a legitimate evidence row can satisfy fails here rather than in
// production. It also pins the mixed-case hex claim the field comments make:
// offer_sig is stored lowercase and agent_acceptance_signature uppercase, so
// a pattern narrowed to one case would fail this row.
//
// The ed25519.Verify assertions are NOT a gate. That a genuine signature
// verifies, and that flipping a byte of the signed bytes breaks it, is
// crypto/ed25519's contract rather than this repo's — no change here can turn
// those lines red. They stay because they execute the documented recipe
// literally instead of paraphrasing it: a reader sees the exact call sequence
// the comment promises, performed on a row the contract accepts, with the
// tamper cases showing which side each signature covers. Read them as
// executable documentation, not as proof that the row detects tampering.
package conformance

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	protovalidate "buf.build/go/protovalidate"
	"google.golang.org/protobuf/types/known/timestamppb"

	rampadminv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/admin/v1"
)

// evidenceRow builds a TransactionEvidence whose signatures are REAL: each
// side's canonical bytes are signed with a deterministic Ed25519 key (fixed
// seeds, so a failure reproduces byte-for-byte). offer_sig is stored lowercase
// and agent_acceptance_signature uppercase, pinning the field comments' claim
// that the hex rides verbatim in either case.
func evidenceRow() *rampadminv1.TransactionEvidence {
	exchangeKey := ed25519.NewKeyFromSeed([]byte(strings.Repeat("exchange-seed-01", 2)))
	agentKey := ed25519.NewKeyFromSeed([]byte(strings.Repeat("agent-seed-00001", 2)))

	offerCanonical := []byte(`{"offer_id":"offer-verify","price":{"amount":"1.00","currency":"USD"}}`)
	acceptanceCanonical := []byte(`{"idempotency_key":"idem-verify","offer_sig":"…","requester_id":"agent-verify"}`)

	return &rampadminv1.TransactionEvidence{
		TransactionId:                     "tx-verify",
		TenantId:                          "tenant-verify",
		OfferId:                           "offer-verify",
		OfferJson:                         `{"offer_id":"offer-verify"}`,
		OfferCanonicalBytes:               offerCanonical,
		OfferSig:                          strings.ToLower(hex.EncodeToString(ed25519.Sign(exchangeKey, offerCanonical))),
		OfferSigAlgorithm:                 "EdDSA",
		ExchangeSigningPublicKey:          exchangeKey.Public().(ed25519.PublicKey),
		AgentAcceptanceSignature:          strings.ToUpper(hex.EncodeToString(ed25519.Sign(agentKey, acceptanceCanonical))),
		AgentAcceptanceCanonicalBytes:     acceptanceCanonical,
		AgentAcceptanceSignatureAlgorithm: "EdDSA",
		RequesterId:                       "agent-verify",
		RequesterDomain:                   "agent.example",
		RequestIdempotencyKey:             "idem-verify",
		AgentPublicKey:                    agentKey.Public().(ed25519.PublicKey),
		AgentDirectoryUrl:                 "https://agent.example/.well-known/ramp-agent.json",
		CreatedAt:                         timestamppb.New(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)),
	}
}

// verifyRecipe is the documented procedure, literally: hex-decode the stored
// signature, then ed25519.Verify against the stored key and canonical bytes.
// It operates on the row alone — no registry, no key file, no live service —
// which is the property the proto comment promises.
func verifyRecipe(t *testing.T, key, canonical []byte, hexSig string) bool {
	t.Helper()
	sig, err := hex.DecodeString(hexSig)
	if err != nil {
		t.Fatalf("hex-decoding signature %q: %v", hexSig, err)
	}
	return ed25519.Verify(key, canonical, sig)
}

func TestEvidenceOfflineVerificationRecipe(t *testing.T) {
	row := evidenceRow()

	// The row the recipe runs on is contract-valid, not merely well-formed:
	// a recipe demonstrated on a row the contract rejects would prove nothing
	// about rows the read RPC can actually return.
	v, err := protovalidate.New()
	if err != nil {
		t.Fatalf("protovalidate.New: %v", err)
	}
	if err := v.Validate(row); err != nil {
		t.Fatalf("evidence row must pass the wire contract before the recipe runs: %v", err)
	}

	if !verifyRecipe(t, row.ExchangeSigningPublicKey, row.OfferCanonicalBytes, row.OfferSig) {
		t.Error("offer signature must verify: ed25519.Verify(exchange_signing_public_key, offer_canonical_bytes, hex-decoded offer_sig)")
	}
	if !verifyRecipe(t, row.AgentPublicKey, row.AgentAcceptanceCanonicalBytes, row.AgentAcceptanceSignature) {
		t.Error("acceptance signature must verify: ed25519.Verify(agent_public_key, agent_acceptance_canonical_bytes, hex-decoded agent_acceptance_signature)")
	}

	// Tamper half: one flipped bit in the canonical bytes breaks the matching
	// verification and leaves the other side intact. This demonstrates which
	// side each signature covers; it cannot fail on a repo change (see the
	// file header).
	t.Run("tampered offer_canonical_bytes fails", func(t *testing.T) {
		tampered := evidenceRow()
		tampered.OfferCanonicalBytes[0] ^= 0x01
		if verifyRecipe(t, tampered.ExchangeSigningPublicKey, tampered.OfferCanonicalBytes, tampered.OfferSig) {
			t.Error("offer signature verified over tampered offer_canonical_bytes — the recipe does not detect tampering")
		}
		if !verifyRecipe(t, tampered.AgentPublicKey, tampered.AgentAcceptanceCanonicalBytes, tampered.AgentAcceptanceSignature) {
			t.Error("acceptance verification must be unaffected by offer-side tampering")
		}
	})
	t.Run("tampered agent_acceptance_canonical_bytes fails", func(t *testing.T) {
		tampered := evidenceRow()
		tampered.AgentAcceptanceCanonicalBytes[0] ^= 0x01
		if verifyRecipe(t, tampered.AgentPublicKey, tampered.AgentAcceptanceCanonicalBytes, tampered.AgentAcceptanceSignature) {
			t.Error("acceptance signature verified over tampered agent_acceptance_canonical_bytes — the recipe does not detect tampering")
		}
		if !verifyRecipe(t, tampered.ExchangeSigningPublicKey, tampered.OfferCanonicalBytes, tampered.OfferSig) {
			t.Error("offer verification must be unaffected by acceptance-side tampering")
		}
	})
}
