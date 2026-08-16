// Package conformance — evidence_offline_verify_test.go executes the offline
// re-verification recipe the TransactionEvidence proto comment states:
//
//	ed25519.Verify(exchange_signing_public_key, offer_canonical_bytes, hex-decoded offer_sig)
//	ed25519.Verify(agent_public_key, agent_acceptance_canonical_bytes, hex-decoded agent_acceptance_signature)
//	JCS-parse(agent_acceptance_canonical_bytes) matches the row on all four
//	  signed members (offer_sig, requester_id, requester_domain, and
//	  idempotency_key against the row's request_idempotency_key)
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
//
// The two MEMBER-COMPARISON cases ARE gates, and they are the reason the third
// step exists. Both build rows whose halves are individually genuine, so the
// ed25519.Verify calls above pass on rows that assert something false. One
// covers splicing an acceptance from another offer, caught by offer_sig. The
// other covers reusing one acceptance for a second execute against the SAME
// offer, where offer_sig is identical and only the idempotency key differs.
// Narrow the check back to offer_sig alone and the second case starts passing,
// which is exactly the regression it is here to refuse.
package conformance

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
//
// offerID and idemKey vary the two halves of the binding independently, so a
// caller can build two rows that differ ONLY in which offer was accepted (the
// splice case) or ONLY in which execute the acceptance covers (the reuse case).
func evidenceRow() *rampadminv1.TransactionEvidence {
	return evidenceRowFor("offer-verify", "idem-verify")
}

func evidenceRowFor(offerID, idemKey string) *rampadminv1.TransactionEvidence {
	exchangeKey := ed25519.NewKeyFromSeed([]byte(strings.Repeat("exchange-seed-01", 2)))
	agentKey := ed25519.NewKeyFromSeed([]byte(strings.Repeat("agent-seed-00001", 2)))

	offerCanonical := []byte(fmt.Sprintf(`{"offer_id":%q,"price":{"amount":"1.00","currency":"USD"}}`, offerID))
	offerSig := strings.ToLower(hex.EncodeToString(ed25519.Sign(exchangeKey, offerCanonical)))

	// The acceptance carries all four AgentAcceptancePayload members, which is
	// what the row's four stored copies are compared against. JCS orders members
	// lexicographically: idempotency_key < offer_sig < requester_domain <
	// requester_id.
	acceptanceCanonical := []byte(fmt.Sprintf(
		`{"idempotency_key":%q,"offer_sig":%q,"requester_domain":"agent.example","requester_id":"agent-verify"}`,
		idemKey, offerSig))

	return &rampadminv1.TransactionEvidence{
		TransactionId:            "tx-verify",
		TenantId:                 "tenant-verify",
		OfferId:                  offerID,
		OfferJson:                fmt.Sprintf(`{"offer_id":%q}`, offerID),
		OfferCanonicalBytes:      offerCanonical,
		OfferSig:                 offerSig,
		OfferSigAlgorithm:        "EdDSA",
		ExchangeSigningPublicKey: exchangeKey.Public().(ed25519.PublicKey),
		// The ToLower above and the ToUpper here are DELIBERATE and load-bearing:
		// together they pin the "either case" promise against the live contract.
		// Do not normalise them to one case. TestHexSignaturePatternAdmits states
		// the same property directly, so this row is no longer the only thing
		// holding it — but it is the only place that holds it on a row built the
		// way the recipe requires.
		AgentAcceptanceSignature:          strings.ToUpper(hex.EncodeToString(ed25519.Sign(agentKey, acceptanceCanonical))),
		AgentAcceptanceCanonicalBytes:     acceptanceCanonical,
		AgentAcceptanceSignatureAlgorithm: "EdDSA",
		RequesterId:                       "agent-verify",
		RequesterDomain:                   "agent.example",
		RequestIdempotencyKey:             idemKey,
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

// acceptanceMatchesRow is the recipe's third step: parse the signed acceptance
// bytes and compare EVERY member of the payload to the row's stored copy.
//
// All four, not just offer_sig. Two acceptances by one agent against one offer
// share offer_sig and differ only in the idempotency key, so an offer_sig-only
// check lets a single genuine acceptance stand behind two rows for two
// different executes. It returns the name of the first member that does not
// match, or "" when the row and the acceptance agree.
//
// Note the fourth name: the payload member is idempotency_key, and the row
// stores it as request_idempotency_key.
func acceptanceMatchesRow(t *testing.T, row *rampadminv1.TransactionEvidence) string {
	t.Helper()
	var payload struct {
		OfferSig        *string `json:"offer_sig"`
		RequesterID     *string `json:"requester_id"`
		RequesterDomain *string `json:"requester_domain"`
		IdempotencyKey  *string `json:"idempotency_key"`
	}
	if err := json.Unmarshal(row.AgentAcceptanceCanonicalBytes, &payload); err != nil {
		t.Fatalf("parsing agent_acceptance_canonical_bytes as JCS JSON: %v", err)
	}
	// A missing member is fatal, not a mismatch: the signed bytes cannot be
	// audited against the row at all, which is a different and worse problem
	// than the two disagreeing.
	for name, got := range map[string]*string{
		"offer_sig":        payload.OfferSig,
		"requester_id":     payload.RequesterID,
		"requester_domain": payload.RequesterDomain,
		"idempotency_key":  payload.IdempotencyKey,
	} {
		if got == nil {
			t.Fatalf("the acceptance payload carries no %s — the row cannot prove which "+
				"agreement this acceptance covers", name)
		}
	}
	// offer_sig alone is case-insensitive: the contract admits either hex case
	// verbatim, so the row's copy and the signed copy can legitimately differ in
	// case. The other three are exact.
	if !strings.EqualFold(*payload.OfferSig, row.OfferSig) {
		return "offer_sig"
	}
	for _, c := range []struct{ name, payload, row string }{
		{"requester_id", *payload.RequesterID, row.RequesterId},
		{"requester_domain", *payload.RequesterDomain, row.RequesterDomain},
		{"idempotency_key vs request_idempotency_key", *payload.IdempotencyKey, row.RequestIdempotencyKey},
	} {
		if c.payload != c.row {
			return c.name
		}
	}
	return ""
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
	if mismatch := acceptanceMatchesRow(t, row); mismatch != "" {
		t.Errorf("an honest row must match its acceptance on every signed member; %s differs", mismatch)
	}

	// The two cases below are the gate. Both build a row whose halves are
	// individually genuine, so both ed25519.Verify calls pass on a row that
	// asserts something false — only the member comparison separates them from an
	// honest row. They cover DIFFERENT attacks and neither subsumes the other.

	// SPLICING, by an outsider: two genuine halves of two different
	// transactions, joined. Caught by offer_sig.
	t.Run("spliced acceptance from another offer", func(t *testing.T) {
		spliced := evidenceRowFor("offer-verify", "idem-verify")
		other := evidenceRowFor("offer-other", "idem-verify")
		spliced.AgentAcceptanceCanonicalBytes = other.AgentAcceptanceCanonicalBytes
		spliced.AgentAcceptanceSignature = other.AgentAcceptanceSignature

		if err := v.Validate(spliced); err != nil {
			t.Fatalf("the spliced row is still contract-valid — that is the point: %v", err)
		}
		if !verifyRecipe(t, spliced.ExchangeSigningPublicKey, spliced.OfferCanonicalBytes, spliced.OfferSig) {
			t.Error("the offer half of a spliced row is genuine and must still verify")
		}
		if !verifyRecipe(t, spliced.AgentPublicKey, spliced.AgentAcceptanceCanonicalBytes, spliced.AgentAcceptanceSignature) {
			t.Error("the acceptance half of a spliced row is genuine and must still verify")
		}
		if got := acceptanceMatchesRow(t, spliced); got != "offer_sig" {
			t.Errorf("a spliced row must be caught on offer_sig, got %q — the recipe cannot tell an "+
				"agreement from two unrelated genuine signatures", got)
		}
	})

	// FABRICATION, by whoever writes the row: ONE genuine acceptance reused
	// across two executes against the SAME offer. offer_sig is identical in both
	// rows, so an offer_sig-only check accepts this. Only the idempotency key
	// separates them, which is exactly what that payload member exists to bind.
	t.Run("one acceptance reused for a second execute against the same offer", func(t *testing.T) {
		reused := evidenceRowFor("offer-verify", "idem-second-execute")
		first := evidenceRowFor("offer-verify", "idem-verify")
		reused.AgentAcceptanceCanonicalBytes = first.AgentAcceptanceCanonicalBytes
		reused.AgentAcceptanceSignature = first.AgentAcceptanceSignature

		if err := v.Validate(reused); err != nil {
			t.Fatalf("the fabricated row is still contract-valid — that is the point: %v", err)
		}
		if !verifyRecipe(t, reused.ExchangeSigningPublicKey, reused.OfferCanonicalBytes, reused.OfferSig) {
			t.Error("the offer half is genuine and must still verify")
		}
		if !verifyRecipe(t, reused.AgentPublicKey, reused.AgentAcceptanceCanonicalBytes, reused.AgentAcceptanceSignature) {
			t.Error("the acceptance half is genuine and must still verify")
		}
		// The offer halves are identical, so offer_sig cannot catch this. Assert
		// that directly, or a later reader will think the check below is redundant.
		if !strings.EqualFold(reused.OfferSig, first.OfferSig) {
			t.Fatal("the two rows must share an offer_sig, or this case is not testing reuse")
		}
		if got := acceptanceMatchesRow(t, reused); got != "idempotency_key vs request_idempotency_key" {
			t.Errorf("a reused acceptance must be caught on the idempotency key, got %q — one genuine "+
				"acceptance is standing behind two rows for two different executes", got)
		}
	})

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
