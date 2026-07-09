package helpers_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// Ported from v2 internal/httpsig/chain_test.go, re-expressed in the L1 idiom
// (Signer interface + VerifyOptions.Now). These pin the forwarding-chain
// behaviour: byte-exact signature base (Risk R1), chain-link presence, and the
// structural + cryptographic rejection vectors (strip / reorder / missing-link /
// substituted-predecessor / hop-budget).

const goldenChainTarget = "https://exchange.example/ramp.v1.ExchangeService/DiscoverResources"

func fixedSigner(t *testing.T, keyID string, b byte) (helpers.Signer, ed25519.PublicKey) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = b
	}
	priv := ed25519.NewKeyFromSeed(seed)
	s, err := helpers.NewEd25519Signer(keyID, priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return s, priv.Public().(ed25519.PublicKey)
}

func goldenSignedRequest(t *testing.T, body []byte, signer helpers.Signer, now time.Time) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, goldenChainTarget, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer test-jwt")
	opts := helpers.SignOptions{Created: now.Unix(), Expires: now.Add(30 * time.Second).Unix()}
	if err := helpers.SignRequest(context.Background(), req, body, signer, opts); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}
	return req
}

// TestChain_GoldenSignatureBase pins the byte-exact signature base for sig1 and
// the chain-linked sig2 inner list — the byte-preservation contract (Risk R1).
// The sig1 base here is also the single-sig golden: it proves the N=1 covered
// rendering is unchanged after the []string→[]CoveredComponent widen.
func TestChain_GoldenSignatureBase(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1700000000, 0)
	body := []byte(`{"query":"foo"}`)

	agentSigner, _ := fixedSigner(t, "agent-demo.v1", 0x01)
	brokerSigner, _ := fixedSigner(t, helpers.BrokerKeyIDPrefix+"relay.a", 0x02)

	req := goldenSignedRequest(t, body, agentSigner, now)

	// Capture the exact sig1 Signature-Input value BEFORE appending — this is the
	// single-sig golden the widen must not perturb.
	gotSig1Input := req.Header.Get("Signature-Input")
	digest := "sha-256=:" + base64.StdEncoding.EncodeToString(sha256SumGolden(body)) + ":"
	if req.Header.Get("Content-Digest") != digest {
		t.Fatalf("content-digest = %q, want %q", req.Header.Get("Content-Digest"), digest)
	}
	wantSig1Input := `sig1=("@method" "@target-uri" "content-digest" "authorization" "signature-agent");keyid="agent-demo.v1";alg="ed25519";created=1700000000;expires=1700000030`
	if gotSig1Input != wantSig1Input {
		t.Fatalf("sig1 Signature-Input (single-sig golden) mismatch:\n got: %s\nwant: %s", gotSig1Input, wantSig1Input)
	}

	opts := helpers.SignOptions{Created: now.Unix(), Expires: now.Add(30 * time.Second).Unix()}
	if err := helpers.AppendSignature(ctx, req, body, brokerSigner, opts); err != nil {
		t.Fatalf("append: %v", err)
	}

	// sig2's Signature-Input inner list must carry exactly the chain link.
	wantInner := `("@method" "@target-uri" "content-digest" "authorization" "signature-agent" "signature";key="sig1")`
	si := req.Header.Get("Signature-Input")
	if !strings.Contains(si, wantInner) {
		t.Fatalf("sig2 inner list missing chain link:\n%s", si)
	}
	// sig1's member must still be present unchanged after the append.
	if !strings.Contains(si, wantSig1Input) {
		t.Fatalf("sig1 member changed by append:\n%s", si)
	}
}

func sha256SumGolden(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

// chainEnv builds a valid agent(sig1)+broker(sig2) request and its resolver.
func chainEnv(t *testing.T, now time.Time) (*http.Request, []byte, helpers.KeyResolver) {
	t.Helper()
	ctx := context.Background()
	agentSigner, agentPub := fixedSigner(t, "agent-demo.v1", 0x05)
	brokerSigner, brokerPub := fixedSigner(t, helpers.BrokerKeyIDPrefix+"relay.a", 0x06)
	body := []byte(`{"q":"chain"}`)
	req := goldenSignedRequest(t, body, agentSigner, now)
	opts := helpers.SignOptions{Created: now.Unix(), Expires: now.Add(30 * time.Second).Unix()}
	if err := helpers.AppendSignature(ctx, req, body, brokerSigner, opts); err != nil {
		t.Fatalf("append: %v", err)
	}
	resolver := helpers.NewStaticKeyResolver(map[string]ed25519.PublicKey{
		"agent-demo.v1":                       agentPub,
		helpers.BrokerKeyIDPrefix + "relay.a": brokerPub,
	})
	return req, body, resolver
}

// TestChain_ValidChainVerifies is the positive control.
func TestChain_ValidChainVerifies(t *testing.T) {
	now := time.Unix(1700000000, 0)
	req, body, resolver := chainEnv(t, now)
	verified, err := helpers.VerifyMultisigRequestResolved(context.Background(), req, body, resolver, helpers.VerifyOptions{Now: now})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(verified) != 2 {
		t.Fatalf("got %d verified, want 2", len(verified))
	}
}

// TestChain_StrippedMiddleHop drops sig2 from a 3-sig chain → labels no longer
// contiguous → ErrBrokenSignatureChain.
func TestChain_StrippedMiddleHop(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1700000000, 0)
	s1, p1 := fixedSigner(t, "agent-demo.v1", 0x07)
	s2, p2 := fixedSigner(t, helpers.BrokerKeyIDPrefix+"relay.a", 0x08)
	s3, p3 := fixedSigner(t, helpers.BrokerKeyIDPrefix+"relay.b", 0x09)
	body := []byte(`{"q":"three"}`)
	req := goldenSignedRequest(t, body, s1, now)
	opts := helpers.SignOptions{Created: now.Unix(), Expires: now.Add(30 * time.Second).Unix()}
	if err := helpers.AppendSignature(ctx, req, body, s2, opts); err != nil {
		t.Fatalf("append sig2: %v", err)
	}
	if err := helpers.AppendSignature(ctx, req, body, s3, opts); err != nil {
		t.Fatalf("append sig3: %v", err)
	}
	resolver := helpers.NewStaticKeyResolver(map[string]ed25519.PublicKey{
		"agent-demo.v1":                       p1,
		helpers.BrokerKeyIDPrefix + "relay.a": p2,
		helpers.BrokerKeyIDPrefix + "relay.b": p3,
	})

	req.Header.Set("Signature-Input", dropMember(req.Header.Get("Signature-Input"), "sig2"))
	req.Header.Set("Signature", dropMember(req.Header.Get("Signature"), "sig2"))

	_, err := helpers.VerifyMultisigRequestResolved(ctx, req, body, resolver, helpers.VerifyOptions{Now: now})
	if !errors.Is(err, helpers.ErrBrokenSignatureChain) {
		t.Fatalf("want ErrBrokenSignatureChain, got %v", err)
	}
	if !strings.Contains(err.Error(), `want "sig2"`) {
		t.Fatalf("stripped-hop error should report the contiguity gap, got %v", err)
	}
}

// TestChain_Reordered swaps sig1/sig2 header order → ErrBrokenSignatureChain.
func TestChain_Reordered(t *testing.T) {
	now := time.Unix(1700000000, 0)
	req, body, resolver := chainEnv(t, now)
	req.Header.Set("Signature-Input", swapTwoMembers(req.Header.Get("Signature-Input")))
	req.Header.Set("Signature", swapTwoMembers(req.Header.Get("Signature")))

	_, err := helpers.VerifyMultisigRequestResolved(context.Background(), req, body, resolver, helpers.VerifyOptions{Now: now})
	if !errors.Is(err, helpers.ErrBrokenSignatureChain) {
		t.Fatalf("want ErrBrokenSignatureChain, got %v", err)
	}
	if !strings.Contains(err.Error(), `want "sig1"`) {
		t.Fatalf("reorder error should report the position-1 mismatch, got %v", err)
	}
}

// TestChain_MissingLink: a sig2 that does NOT cover sig1 (parallel co-sign shape)
// → ErrBrokenSignatureChain. AppendSignature always adds the link, so we forge
// the missing-link shape by signing a second request and splicing its sig1
// member in as a (mislabeled) sig2 — simplest path that keeps the wire emission
// in the production signer. Instead, we build it by appending then stripping the
// chain link param via header surgery is brittle; we drive it by re-signing the
// SAME request as a fresh sig1 and renaming the member to sig2.
func TestChain_MissingLink(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1700000000, 0)
	s1, p1 := fixedSigner(t, "agent-demo.v1", 0x0a)
	s2, p2 := fixedSigner(t, helpers.BrokerKeyIDPrefix+"relay.a", 0x0b)
	body := []byte(`{"q":"nolink"}`)

	req := goldenSignedRequest(t, body, s1, now)
	sig1Input := req.Header.Get("Signature-Input")
	sig1Sig := req.Header.Get("Signature")

	// Build a second independent sig1 (broker key) over the same request, then
	// relabel it sig2 and concatenate — a sig2 with the PLAIN base set, no link.
	req2 := goldenSignedRequest(t, body, s2, now)
	sig2AsInput := relabelMember(req2.Header.Get("Signature-Input"), "sig1", "sig2")
	sig2AsSig := relabelMember(req2.Header.Get("Signature"), "sig1", "sig2")

	req.Header.Set("Signature-Input", sig1Input+", "+sig2AsInput)
	req.Header.Set("Signature", sig1Sig+", "+sig2AsSig)

	resolver := helpers.NewStaticKeyResolver(map[string]ed25519.PublicKey{
		"agent-demo.v1":                       p1,
		helpers.BrokerKeyIDPrefix + "relay.a": p2,
	})
	_, err := helpers.VerifyMultisigRequestResolved(ctx, req, body, resolver, helpers.VerifyOptions{Now: now})
	if !errors.Is(err, helpers.ErrBrokenSignatureChain) {
		t.Fatalf("want ErrBrokenSignatureChain, got %v", err)
	}
	if !strings.Contains(err.Error(), "must cover") {
		t.Fatalf("missing-link error should name the coverage failure, got %v", err)
	}
}

// TestChain_SubstitutedPredecessorRejected is the BINDING test: a relay cannot
// swap a peer's signature. A valid agent sig1_A + broker sig2 (chained to sig1_A)
// has sig1 replaced by a DIFFERENT but individually-valid agent sig1_B (same key,
// different created). sig1_B verifies on its own, but sig2's base resolves the
// chain link to sig1_B's bytes — which sig2 never signed — so sig2's verify fails.
func TestChain_SubstitutedPredecessorRejected(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1700000000, 0)
	agentSigner, agentPub := fixedSigner(t, "agent-demo.v1", 0x0c)
	brokerSigner, brokerPub := fixedSigner(t, helpers.BrokerKeyIDPrefix+"relay.a", 0x0d)
	body := []byte(`{"q":"subst"}`)

	req := goldenSignedRequest(t, body, agentSigner, now)
	opts := helpers.SignOptions{Created: now.Unix(), Expires: now.Add(30 * time.Second).Unix()}
	if err := helpers.AppendSignature(ctx, req, body, brokerSigner, opts); err != nil {
		t.Fatalf("append sig2: %v", err)
	}

	// sig1_B: same agent key + body, different created → different signature bytes.
	reqB := goldenSignedRequest(t, body, agentSigner, now.Add(time.Second))
	sig1BInput := memberOf(reqB.Header.Get("Signature-Input"), "sig1")
	sig1BSig := memberOf(reqB.Header.Get("Signature"), "sig1")

	req.Header.Set("Signature-Input", replaceMember(req.Header.Get("Signature-Input"), "sig1", sig1BInput))
	req.Header.Set("Signature", replaceMember(req.Header.Get("Signature"), "sig1", sig1BSig))

	resolver := helpers.NewStaticKeyResolver(map[string]ed25519.PublicKey{
		"agent-demo.v1":                       agentPub,
		helpers.BrokerKeyIDPrefix + "relay.a": brokerPub,
	})
	_, err := helpers.VerifyMultisigRequestResolved(ctx, req, body, resolver, helpers.VerifyOptions{Now: now.Add(time.Second)})
	if !errors.Is(err, helpers.ErrSignatureVerify) {
		t.Fatalf("want ErrSignatureVerify (sig2 bound to the substituted sig1), got %v", err)
	}
}

// TestChain_TooManyHops rejects a 2-sig chain under MaxSignatures=1.
func TestChain_TooManyHops(t *testing.T) {
	now := time.Unix(1700000000, 0)
	req, body, resolver := chainEnv(t, now)
	_, err := helpers.VerifyMultisigRequestResolved(context.Background(), req, body, resolver,
		helpers.VerifyOptions{Now: now, MaxSignatures: 1})
	if !errors.Is(err, helpers.ErrTooManyHops) {
		t.Fatalf("want ErrTooManyHops, got %v", err)
	}
}

// TestChain_WithinHopBudget accepts a chain exactly at the budget.
func TestChain_WithinHopBudget(t *testing.T) {
	now := time.Unix(1700000000, 0)
	req, body, resolver := chainEnv(t, now)
	if _, err := helpers.VerifyMultisigRequestResolved(context.Background(), req, body, resolver,
		helpers.VerifyOptions{Now: now, MaxSignatures: 2}); err != nil {
		t.Fatalf("verify at budget: %v", err)
	}
}

// --- structured-field member helpers (comma-separated, ", " join) ---

func dropMember(raw, label string) string {
	var members []string
	for _, m := range strings.Split(raw, ", ") {
		if strings.HasPrefix(strings.TrimSpace(m), label+"=") {
			continue
		}
		members = append(members, m)
	}
	return strings.Join(members, ", ")
}

func swapTwoMembers(raw string) string {
	parts := strings.SplitN(raw, ", ", 2)
	if len(parts) != 2 {
		return raw
	}
	return parts[1] + ", " + parts[0]
}

func memberOf(raw, label string) string {
	for _, p := range strings.Split(raw, ", ") {
		if strings.HasPrefix(strings.TrimSpace(p), label+"=") {
			return strings.TrimSpace(p)
		}
	}
	return ""
}

func replaceMember(raw, label, newMember string) string {
	var parts []string
	for _, p := range strings.Split(raw, ", ") {
		if strings.HasPrefix(strings.TrimSpace(p), label+"=") {
			parts = append(parts, newMember)
		} else {
			parts = append(parts, p)
		}
	}
	return strings.Join(parts, ", ")
}

func relabelMember(raw, oldLabel, newLabel string) string {
	m := memberOf(raw, oldLabel)
	return newLabel + strings.TrimPrefix(m, oldLabel)
}
