// Package conformance — evidence_offline_verify_test.go executes the offline
// re-verification recipe the TransactionEvidence proto comment states:
//
//	ed25519.Verify(exchange_signing_public_key, offer_canonical_bytes, hex-decoded offer_sig)
//	ed25519.Verify(agent_public_key, agent_acceptance_canonical_bytes, hex-decoded agent_acceptance_signature)
//	JCS-parse(agent_acceptance_canonical_bytes)["offer_sig"] == offer_sig
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
// The SPLICE case IS a gate, and it is the reason the third step exists. Both
// signatures on a spliced row are genuine, so the two ed25519.Verify calls
// above pass on a row that asserts an agreement nobody made. Only the binding
// comparison separates the two. Remove that step from the recipe and this case
// starts passing, which is exactly the regression it is here to refuse.
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
// offerID varies the offer so a caller can build two rows that differ only in
// which offer was accepted — which is what the splice case needs.
func evidenceRow() *rampadminv1.TransactionEvidence { return evidenceRowFor("offer-verify") }

func evidenceRowFor(offerID string) *rampadminv1.TransactionEvidence {
	exchangeKey := ed25519.NewKeyFromSeed([]byte(strings.Repeat("exchange-seed-01", 2)))
	agentKey := ed25519.NewKeyFromSeed([]byte(strings.Repeat("agent-seed-00001", 2)))

	offerCanonical := []byte(fmt.Sprintf(`{"offer_id":%q,"price":{"amount":"1.00","currency":"USD"}}`, offerID))
	offerSig := strings.ToLower(hex.EncodeToString(ed25519.Sign(exchangeKey, offerCanonical)))

	// The acceptance embeds the REAL offer_sig, which is what binds it to this
	// offer and nothing else. JCS orders members lexicographically, so
	// idempotency_key < offer_sig < requester_id.
	acceptanceCanonical := []byte(fmt.Sprintf(
		`{"idempotency_key":"idem-verify","offer_sig":%q,"requester_id":"agent-verify"}`, offerSig))

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

// acceptanceBindsToOffer is the recipe's third step: read offer_sig back out of
// the signed acceptance bytes and compare it to the row's own offer_sig. The
// comparison is case-insensitive because the contract accepts either hex case
// verbatim, so the two copies of one value can legitimately differ in case.
func acceptanceBindsToOffer(t *testing.T, row *rampadminv1.TransactionEvidence) bool {
	t.Helper()
	var payload struct {
		OfferSig string `json:"offer_sig"`
	}
	if err := json.Unmarshal(row.AgentAcceptanceCanonicalBytes, &payload); err != nil {
		t.Fatalf("parsing agent_acceptance_canonical_bytes as JCS JSON: %v", err)
	}
	if payload.OfferSig == "" {
		t.Fatal("the acceptance payload carries no offer_sig — the binding cannot be checked, " +
			"which means the row cannot prove the acceptance is for this offer")
	}
	return strings.EqualFold(payload.OfferSig, row.OfferSig)
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
	if !acceptanceBindsToOffer(t, row) {
		t.Error("the acceptance must bind to this offer: offer_sig inside agent_acceptance_canonical_bytes must equal the row's offer_sig")
	}

	// SPLICE. Two genuine halves of two different transactions, joined. Both
	// signatures still verify against real keys, because both halves are real —
	// only the binding check separates this row from an honest one. This is the
	// assertion the file header's "nothing here can turn red" caveat does NOT
	// cover: delete the third recipe step and this case starts passing.
	t.Run("spliced acceptance from another offer is caught only by the binding check", func(t *testing.T) {
		spliced := evidenceRowFor("offer-verify")
		other := evidenceRowFor("offer-other")
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
		if acceptanceBindsToOffer(t, spliced) {
			t.Error("a spliced row passed the binding check — the recipe cannot tell an agreement " +
				"from two unrelated genuine signatures")
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
