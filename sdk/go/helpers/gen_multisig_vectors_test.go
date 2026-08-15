package helpers

// Multisig forwarding-chain golden-vector emitter.
//
// The sdk/ts and sdk/python multisig append/verify faces assert
// byte-parity against this Go oracle: a chain signed by SignRequest(sig1) +
// AppendSignature(sig2[,sig3]) must reconstruct byte-for-byte in TS and Python,
// and the hop-budget / broken-chain / tampered-predecessor rejections must match
// the Go taxonomy token-for-token. Rather than hand-author the wire bytes, this
// emitter signs with the REAL Go signer+appender and DERIVES every expected
// outcome/reason from the REAL VerifyMultisigRequestResolved — the same
// self-contained-oracle shape gen_vectors_test.go uses for the single-sig corpus.
//
// The single-sig oracleNegReason (gen_vectors_test.go) runs
// VerifyRequest and CANNOT emit hop_budget (no MaxSignatures / multi-hop
// resolver). This file therefore carries a NEW multisig oracle-reason wrapper
// (multisigOracleReason) that calls VerifyMultisigRequestResolved with a per-hop
// KeyResolver + opts.MaxSignatures; only classifyNegReason is reused unchanged
// (it already maps ErrTooManyHops→hop_budget, ErrBrokenSignatureChain→broken_chain).
//
// Determinism: every hop key is derived from a FIXED fixedSeed byte and the
// created/expires window is pinned, so a re-emit is byte-identical (drift-gated).

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Shared request material for every chain vector — one target, one body, one
// window — so the vectors differ only in their signature chain and mutation.
const (
	msMethod   = http.MethodPost
	msURL      = "https://exchange.example.com/ramp.v1.ExchangeService/ExecuteTransaction"
	msAuth     = "Bearer chain-token"
	msSigAgent = "https://agent.example"
	msCreated  = int64(1_700_000_000)
	msExpires  = int64(1_700_000_600)
	msNow      = int64(1_700_000_100) // inside the window
)

// keyIDs for the chain hops. The agent signs sig1; broker relay keys carry the
// broker.* convention and chain sig2/sig3 on top.
const (
	msAgentKeyID   = "agent-demo.v1"
	msBrokerAKeyID = BrokerKeyIDPrefix + "relay.a"
	msBrokerBKeyID = BrokerKeyIDPrefix + "relay.b"
)

// multisigHop records one hop's identity so a TS/Python port can re-derive the
// exact chain: it re-signs sig1 under the agent seed, appends sig2 under the
// broker seed, and byte-matches the emitted signature_input/signature. pubkey is
// what the port injects into its resolver to verify.
type multisigHop struct {
	KeyID        string `json:"keyid"`
	PubkeyB64URL string `json:"pubkey_b64url"`
	SeedHex      string `json:"seed_hex"`
}

// multisigChainVector is one forwarding-chain case: the full wire request (all
// labels in Signature-Input/Signature), the per-hop identities, and the outcome
// the REAL Go oracle reaches — verified keyids in chain order for a positive, or
// the reject reason token for a negative (hop_budget / broken_chain / signature).
type multisigChainVector struct {
	Name           string        `json:"name"`
	Method         string        `json:"method"`
	URL            string        `json:"url"`
	BodyHex        string        `json:"body_hex"`
	Authorization  string        `json:"authorization"`
	SignatureAgent string        `json:"signature_agent"`
	Created        int64         `json:"created"`
	Expires        int64         `json:"expires"`
	ContentDigest  string        `json:"content_digest"`
	SignatureInput string        `json:"signature_input"`
	Signature      string        `json:"signature"`
	Hops           []multisigHop `json:"hops"`
	// MaxSignatures is the hop budget the verifier is pinned to (0 = unbounded).
	MaxSignatures int `json:"max_signatures"`
	// ExpectedVerified is the positive/negative verdict; ExpectedKeyIDs are the
	// verified keyids in chain order (present only when verified); ExpectedReason
	// is the RejectReason token for a negative ("" for a positive).
	ExpectedVerified bool     `json:"expected_verified"`
	ExpectedKeyIDs   []string `json:"expected_keyids"`
	ExpectedReason   string   `json:"expected_reason"`
}

// hopSpec names a chain hop's keyID and its deterministic seed byte.
type hopSpec struct {
	keyID    string
	seedByte byte
}

// signMultisigChain builds a request and signs the given hops: hop[0] via the
// REAL SignRequest (sig1) and each subsequent hop via the REAL AppendSignature
// (sig2, sig3, …), returning the signed request and the per-hop identities.
func signMultisigChain(t *testing.T, body []byte, hops []hopSpec) (*http.Request, []multisigHop) {
	t.Helper()
	ctx := context.Background()
	req, err := http.NewRequest(msMethod, msURL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", msAuth)
	req.Header.Set(SignatureAgentHeader, msSigAgent)
	opts := SignOptions{Created: msCreated, Expires: msExpires}
	out := make([]multisigHop, 0, len(hops))
	for i, h := range hops {
		seed := fixedSeed(h.seedByte)
		signer, serr := NewEd25519SignerFromSeed(h.keyID, seed)
		if serr != nil {
			t.Fatalf("hop %d signer: %v", i, serr)
		}
		if i == 0 {
			if err := SignRequest(ctx, req, body, signer, opts); err != nil {
				t.Fatalf("hop %d SignRequest: %v", i, err)
			}
		} else {
			if err := AppendSignature(ctx, req, body, signer, opts); err != nil {
				t.Fatalf("hop %d AppendSignature: %v", i, err)
			}
		}
		pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
		out = append(out, multisigHop{
			KeyID:        h.keyID,
			PubkeyB64URL: b64urlNoPad(pub),
			SeedHex:      hex.EncodeToString(seed),
		})
	}
	return req, out
}

// mkChainVector templates a vector from a signed request's wire bytes + hops.
func mkChainVector(name string, req *http.Request, hops []multisigHop, body []byte, maxSig int) multisigChainVector {
	return multisigChainVector{
		Name:           name,
		Method:         msMethod,
		URL:            msURL,
		BodyHex:        hex.EncodeToString(body),
		Authorization:  msAuth,
		SignatureAgent: msSigAgent,
		Created:        msCreated,
		Expires:        msExpires,
		ContentDigest:  req.Header.Get("Content-Digest"),
		SignatureInput: req.Header.Get("Signature-Input"),
		Signature:      req.Header.Get("Signature"),
		Hops:           hops,
		MaxSignatures:  maxSig,
	}
}

// buildMultisigChainVectors emits the forwarding-chain corpus: a positive 2-hop
// chain, the hop-budget overflow (3 hops under MaxSignatures=2), the three
// broken-chain structural rejects (reordered / stripped-middle / missing-link),
// and the tampered-predecessor crypto reject. Every outcome/reason is DERIVED
// from the REAL VerifyMultisigRequestResolved via multisigOracleReason — never
// hand-authored.
func buildMultisigChainVectors(t *testing.T) []multisigChainVector {
	t.Helper()
	body := []byte(`{"idempotency_key":"idem-1"}`)

	agent := hopSpec{msAgentKeyID, 0x90}
	brokerA := hopSpec{msBrokerAKeyID, 0x91}
	brokerB := hopSpec{msBrokerBKeyID, 0x92}

	// positive_two_hop: agent(sig1) + broker(sig2), unbounded budget → verifies.
	req2, hops2 := signMultisigChain(t, body, []hopSpec{agent, brokerA})
	positive := mkChainVector("positive_two_hop", req2, hops2, body, 0)

	// hop_budget_three_over_two: a valid 3-hop chain verified under MaxSignatures=2
	// → ErrTooManyHops before any crypto (hop_budget precedence).
	req3, hops3 := signMultisigChain(t, body, []hopSpec{agent, brokerA, brokerB})
	hopBudget := mkChainVector("hop_budget_three_over_two", req3, hops3, body, 2)

	// broken_chain_reordered: swap sig1/sig2 header order → labels non-contiguous.
	reqR, hopsR := signMultisigChain(t, body, []hopSpec{agent, brokerA})
	reordered := mkChainVector("broken_chain_reordered", reqR, hopsR, body, 0)
	reordered.SignatureInput = msSwapTwoMembers(reordered.SignatureInput)
	reordered.Signature = msSwapTwoMembers(reordered.Signature)

	// broken_chain_stripped_middle: drop sig2 from a 3-hop chain → gap in the
	// sig1..sigN contiguity (sig3 now covers a missing sig2).
	reqS, hopsS := signMultisigChain(t, body, []hopSpec{agent, brokerA, brokerB})
	stripped := mkChainVector("broken_chain_stripped_middle", reqS, hopsS, body, 0)
	stripped.SignatureInput = msDropMember(stripped.SignatureInput, "sig2")
	stripped.Signature = msDropMember(stripped.Signature, "sig2")

	// broken_chain_missing_link: a sig2 that does NOT cover sig1 (parallel co-sign
	// shape) — an independent sig1 relabeled sig2, so the structural link is absent.
	missingLink := buildMissingLinkVector(t, body, agent, brokerA)

	// tampered_predecessor: corrupt sig1's signature bytes on a valid 2-hop chain.
	// Structural chain still holds; sig1's own crypto check fails → "signature".
	reqT, hopsT := signMultisigChain(t, body, []hopSpec{agent, brokerA})
	tampered := mkChainVector("tampered_predecessor", reqT, hopsT, body, 0)
	tampered.Signature = msCorruptFirstMember(tampered.Signature)

	out := []multisigChainVector{positive, hopBudget, reordered, stripped, missingLink, tampered}
	for i := range out {
		keyids, reason := multisigOracleReason(t, out[i])
		out[i].ExpectedKeyIDs = keyids
		out[i].ExpectedReason = reason
		out[i].ExpectedVerified = reason == ""
	}
	return out
}

// buildMissingLinkVector forges the missing-link shape: a valid agent sig1 plus a
// SECOND independent sig1 (broker key) relabeled as sig2 — so sig2 carries the
// PLAIN covered set with no "signature";key="sig1" link. enforceSignatureChain
// rejects it (sig2 must cover its predecessor). Mirrors TestChain_MissingLink.
func buildMissingLinkVector(t *testing.T, body []byte, agent, broker hopSpec) multisigChainVector {
	t.Helper()
	req1, hop1 := signMultisigChain(t, body, []hopSpec{agent})
	req2, hop2 := signMultisigChain(t, body, []hopSpec{broker})
	sig2AsInput := msRelabelMember(req2.Header.Get("Signature-Input"), "sig1", "sig2")
	sig2AsSig := msRelabelMember(req2.Header.Get("Signature"), "sig1", "sig2")

	v := mkChainVector("broken_chain_missing_link", req1, append(hop1, hop2...), body, 0)
	v.SignatureInput = req1.Header.Get("Signature-Input") + ", " + sig2AsInput
	v.Signature = req1.Header.Get("Signature") + ", " + sig2AsSig
	return v
}

// multisigOracleReason drives the REAL VerifyMultisigRequestResolved over the
// reconstructed request with a per-hop resolver + MaxSignatures, returning the
// verified keyids (in chain order) on success or the classified reject reason.
// The multisig sibling of oracleNegReason: reuses classifyNegReason
// unchanged; the multi-hop resolver + MaxSignatures is what lets it emit
// hop_budget, which the single-sig path cannot.
func multisigOracleReason(t *testing.T, v multisigChainVector) (keyids []string, reason string) {
	t.Helper()
	body, err := hex.DecodeString(v.BodyHex)
	if err != nil {
		t.Fatalf("%s: decode body: %v", v.Name, err)
	}
	req, err := http.NewRequest(v.Method, v.URL, nil)
	if err != nil {
		t.Fatalf("%s: new request: %v", v.Name, err)
	}
	req.Header.Set("Content-Digest", v.ContentDigest)
	req.Header.Set("Authorization", v.Authorization)
	req.Header.Set(SignatureAgentHeader, v.SignatureAgent)
	req.Header.Set("Signature-Input", v.SignatureInput)
	req.Header.Set("Signature", v.Signature)

	keys := make(map[string]ed25519.PublicKey, len(v.Hops))
	for _, h := range v.Hops {
		raw, derr := base64.RawURLEncoding.DecodeString(h.PubkeyB64URL)
		if derr != nil {
			t.Fatalf("%s: decode hop pub: %v", v.Name, derr)
		}
		keys[h.KeyID] = ed25519.PublicKey(raw)
	}
	resolver := NewStaticKeyResolver(keys)
	opts := VerifyOptions{Now: time.Unix(msNow, 0), MaxSignatures: v.MaxSignatures}
	verified, verr := VerifyMultisigRequestResolved(context.Background(), req, body, resolver, opts)
	if verr != nil {
		return nil, classifyNegReason(verr)
	}
	ids := make([]string, 0, len(verified))
	for i := range verified {
		ids = append(ids, verified[i].KeyID)
	}
	return ids, ""
}

// verifyMultisigChainVector is the self-consistency guard: it re-runs the oracle
// over the emitted vector and asserts the recorded outcome matches — so
// expected_verified/expected_keyids/expected_reason are authoritative, never
// hand-authored (mirrors verifyNegVectorReason for the single-sig corpus).
func verifyMultisigChainVector(t *testing.T, v multisigChainVector) {
	t.Helper()
	keyids, reason := multisigOracleReason(t, v)
	if reason != v.ExpectedReason {
		t.Fatalf("chain vector %s: oracle reason=%q, recorded=%q", v.Name, reason, v.ExpectedReason)
	}
	if (reason == "") != v.ExpectedVerified {
		t.Fatalf("chain vector %s: oracle verified=%v, recorded=%v", v.Name, reason == "", v.ExpectedVerified)
	}
	if strings.Join(keyids, ",") != strings.Join(v.ExpectedKeyIDs, ",") {
		t.Fatalf("chain vector %s: oracle keyids=%v, recorded=%v", v.Name, keyids, v.ExpectedKeyIDs)
	}
}

// --- structured-field member surgery (comma-separated, ", " join) ---
//
// Local to package helpers (the multisig_chain_extra_test.go helpers live in
// package helpers_test and are not visible here). Mirror those exactly so the
// emitted broken-chain vectors match the hand-written extra tests' mutations.

func msDropMember(raw, label string) string {
	var members []string
	for _, m := range strings.Split(raw, ", ") {
		if strings.HasPrefix(strings.TrimSpace(m), label+"=") {
			continue
		}
		members = append(members, m)
	}
	return strings.Join(members, ", ")
}

func msSwapTwoMembers(raw string) string {
	parts := strings.SplitN(raw, ", ", 2)
	if len(parts) != 2 {
		return raw
	}
	return parts[1] + ", " + parts[0]
}

func msMemberOf(raw, label string) string {
	for _, p := range strings.Split(raw, ", ") {
		if strings.HasPrefix(strings.TrimSpace(p), label+"=") {
			return strings.TrimSpace(p)
		}
	}
	return ""
}

func msRelabelMember(raw, oldLabel, newLabel string) string {
	m := msMemberOf(raw, oldLabel)
	return newLabel + strings.TrimPrefix(m, oldLabel)
}

// msCorruptFirstMember flips the first base64 char after the opening colon of the
// first Signature dictionary member — corrupting sig1's bytes while keeping the
// wire form well-formed, so the reject is a signature failure, not a parse error.
func msCorruptFirstMember(sig string) string {
	b := []byte(sig)
	for i := 0; i < len(b); i++ {
		if b[i] == ':' && i+1 < len(b) {
			if b[i+1] == 'A' {
				b[i+1] = 'B'
			} else {
				b[i+1] = 'A'
			}
			break
		}
	}
	return string(b)
}

// TestGenerateMultisigChainVectors emits the multisig forwarding-chain golden
// corpus. Like TestGenerateVectors it is a verification no-op by default (asserts
// the committed file matches a fresh emit) and (re)writes it under
// RAMP_UPDATE_VECTORS=1 — the emitter is both generator and drift gate.
func TestGenerateMultisigChainVectors(t *testing.T) {
	vectors := buildMultisigChainVectors(t)
	for _, v := range vectors {
		verifyMultisigChainVector(t, v)
	}
	path := filepath.Join("testdata", "multisig-chain-vectors.json")
	doc := map[string]any{"vectors": vectors}

	if os.Getenv("RAMP_UPDATE_VECTORS") == "1" {
		writeJSON(t, path, doc)
		return
	}
	assertMatches(t, path, doc)
}
