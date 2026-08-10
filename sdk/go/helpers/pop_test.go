package helpers_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// The agent-binding sign face. The positive assertion is a replay of the shared
// cross-language corpus: pop-vectors.json stores the seed that produced each
// stored signature, so re-signing the same inputs must reproduce the stored
// header bytes exactly (Ed25519 is deterministic). Python replays the same file
// against its own signer, which is what makes the three faces one contract.

const popVectorsFile = "pop-vectors.json"

type popVector struct {
	Name               string `json:"name"`
	Method             string `json:"method"`
	URL                string `json:"url"`
	AgentID            string `json:"agent_id"`
	PresentedKeyB64URL string `json:"presented_key_b64url"`
	SignerSeedHex      string `json:"signer_seed_hex"`
	SignatureInput     string `json:"signature_input"`
	Signature          string `json:"signature"`
	ExpectedValid      bool   `json:"expected_valid"`
}

func loadPopVectors(t *testing.T) []popVector {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", popVectorsFile))
	if err != nil {
		t.Fatalf("read pop vectors: %v", err)
	}
	var vectors []popVector
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("unmarshal pop vectors: %v", err)
	}
	if len(vectors) == 0 {
		t.Fatal("pop vectors file has no vectors")
	}
	return vectors
}

// validPopVector returns the one vector whose stored proof is expected to verify.
func validPopVector(t *testing.T) popVector {
	t.Helper()
	for _, v := range loadPopVectors(t) {
		if v.ExpectedValid {
			return v
		}
	}
	t.Fatal("no valid pop vector found")
	return popVector{}
}

// signerFor rebuilds the keypair a vector was produced with.
func signerFor(t *testing.T, seedHex, keyID string) (helpers.Signer, ed25519.PublicKey) {
	t.Helper()
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		t.Fatalf("decode signer seed: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	signer, err := helpers.NewEd25519Signer(keyID, priv)
	if err != nil {
		t.Fatalf("build signer: %v", err)
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("signing key has no ed25519 public half")
	}
	return signer, pub
}

// parseWindow pulls created and expires back out of a stored Signature-Input, so
// the replay signs over the same window the vector was minted with.
func parseWindow(t *testing.T, signatureInput string) (created, expires int64) {
	t.Helper()
	var c, e int64
	for _, part := range strings.Split(signatureInput, ";") {
		switch {
		case strings.HasPrefix(part, "created="):
			c = mustAtoi(t, strings.TrimPrefix(part, "created="))
		case strings.HasPrefix(part, "expires="):
			e = mustAtoi(t, strings.TrimPrefix(part, "expires="))
		}
	}
	if c == 0 || e == 0 {
		t.Fatalf("signature input carries no created/expires: %q", signatureInput)
	}
	return c, e
}

func mustAtoi(t *testing.T, s string) int64 {
	t.Helper()
	var n int64
	for _, r := range s {
		if r < '0' || r > '9' {
			t.Fatalf("non-numeric signature parameter %q", s)
		}
		n = n*10 + int64(r-'0')
	}
	return n
}

func TestSignAgentBinding_ReproducesSharedVector(t *testing.T) {
	v := validPopVector(t)
	signer, pub := signerFor(t, v.SignerSeedHex, v.AgentID)
	created, expires := parseWindow(t, v.SignatureInput)

	got, err := helpers.SignAgentBinding(context.Background(), signer, pub, helpers.PoPOptions{
		URL: v.URL, KeyID: v.AgentID, Created: created, Expires: expires, Method: v.Method,
	})
	if err != nil {
		t.Fatalf("sign agent binding: %v", err)
	}
	if got.SignatureInput != v.SignatureInput {
		t.Errorf("Signature-Input\n got %q\nwant %q", got.SignatureInput, v.SignatureInput)
	}
	if got.Signature != v.Signature {
		t.Errorf("Signature\n got %q\nwant %q", got.Signature, v.Signature)
	}
	if got.AgentKey != v.PresentedKeyB64URL {
		t.Errorf("X-RAMP-Agent-Key got %q, want %q", got.AgentKey, v.PresentedKeyB64URL)
	}
}

// The two encodings differ on purpose and a verifier will not forgive a swap:
// the presented key is base64url-no-pad, the RFC 8941 byte sequence is standard
// base64 inside colons.
func TestSignAgentBinding_EncodingAsymmetry(t *testing.T) {
	v := validPopVector(t)
	signer, pub := signerFor(t, v.SignerSeedHex, v.AgentID)
	created, expires := parseWindow(t, v.SignatureInput)

	got, err := helpers.SignAgentBinding(context.Background(), signer, pub, helpers.PoPOptions{
		URL: v.URL, KeyID: v.AgentID, Created: created, Expires: expires,
	})
	if err != nil {
		t.Fatalf("sign agent binding: %v", err)
	}
	if strings.ContainsAny(got.AgentKey, "+/=") {
		t.Errorf("agent key is not base64url-no-pad: %q", got.AgentKey)
	}
	if _, err = base64.RawURLEncoding.DecodeString(got.AgentKey); err != nil {
		t.Errorf("agent key does not decode as base64url-no-pad: %v", err)
	}
	inner := strings.TrimSuffix(strings.TrimPrefix(got.Signature, "sig1=:"), ":")
	if _, err = base64.StdEncoding.DecodeString(inner); err != nil {
		t.Errorf("signature byte string does not decode as standard base64: %v", err)
	}
}

// The covered set is exactly the two components. content-digest and authorization
// are absent by design: a GET has no body, and the signed URL is itself the
// credential and is already covered by @target-uri.
func TestSignAgentBinding_CoversExactlyMethodAndTargetURI(t *testing.T) {
	v := validPopVector(t)
	signer, pub := signerFor(t, v.SignerSeedHex, v.AgentID)
	created, expires := parseWindow(t, v.SignatureInput)

	got, err := helpers.SignAgentBinding(context.Background(), signer, pub, helpers.PoPOptions{
		URL: v.URL, KeyID: v.AgentID, Created: created, Expires: expires,
	})
	if err != nil {
		t.Fatalf("sign agent binding: %v", err)
	}
	if !strings.HasPrefix(got.SignatureInput, `sig1=("@method" "@target-uri");`) {
		t.Errorf("covered set is not the agent-binding pair: %q", got.SignatureInput)
	}
	for _, banned := range []string{"content-digest", "authorization", "signature-agent"} {
		if strings.Contains(got.SignatureInput, banned) {
			t.Errorf("covered set carries %q, which this profile must not bind: %q", banned, got.SignatureInput)
		}
	}
	// keyid, alg, created, expires — the order the verifiers reconstruct from.
	wantOrder := []string{";keyid=", ";alg=", ";created=", ";expires="}
	at := 0
	for _, token := range wantOrder {
		idx := strings.Index(got.SignatureInput[at:], token)
		if idx < 0 {
			t.Fatalf("signature parameters out of order or missing %q: %q", token, got.SignatureInput)
		}
		at += idx + len(token)
	}
}

func TestAgentBinding_ApplyWritesTheThreeHeaders(t *testing.T) {
	binding := helpers.AgentBinding{AgentKey: "key", SignatureInput: "sig1=()", Signature: "sig1=::"}
	h := http.Header{}
	binding.Apply(h)

	if got := h.Get(helpers.AgentKeyHeader); got != "key" {
		t.Errorf("%s = %q, want %q", helpers.AgentKeyHeader, got, "key")
	}
	if got := h.Get("Signature-Input"); got != "sig1=()" {
		t.Errorf("Signature-Input = %q", got)
	}
	if got := h.Get("Signature"); got != "sig1=::" {
		t.Errorf("Signature = %q", got)
	}
	if len(h) != 3 {
		t.Errorf("Apply wrote %d headers, want exactly 3: %v", len(h), h)
	}
}

// Every precondition is refused BEFORE anything is signed, so a mispaired key or
// an absent window is named here rather than surfacing as an undifferentiated 403.
func TestSignAgentBinding_RefusesBadPreconditions(t *testing.T) {
	v := validPopVector(t)
	signer, pub := signerFor(t, v.SignerSeedHex, v.AgentID)
	created, expires := parseWindow(t, v.SignatureInput)
	ok := helpers.PoPOptions{URL: v.URL, KeyID: v.AgentID, Created: created, Expires: expires}

	// A second keypair whose thumbprint is NOT the vector's agent_id.
	otherSigner, otherPub := signerFor(t, strings.Repeat("44", ed25519.SeedSize), v.AgentID)

	tests := []struct {
		name   string
		signer helpers.Signer
		pub    ed25519.PublicKey
		opts   helpers.PoPOptions
		want   error
	}{
		{"nil signer", nil, pub, ok, nil},
		{"short public key", signer, pub[:16], ok, nil},
		{"empty target uri", signer, pub, withURL(ok, ""), helpers.ErrMissingTargetURI},
		{"missing created", signer, pub, withWindow(ok, 0, expires), helpers.ErrMissingCreated},
		{"missing expires", signer, pub, withWindow(ok, created, 0), helpers.ErrMissingExpires},
		{"keyid is not the presented key's thumbprint", otherSigner, otherPub, ok, helpers.ErrKeyIDMismatch},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := helpers.SignAgentBinding(context.Background(), tc.signer, tc.pub, tc.opts)
			if err == nil {
				t.Fatalf("expected a refusal, got binding %+v", got)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("error %v does not match sentinel %v", err, tc.want)
			}
		})
	}
}

// An absent keyid falls back to the Signer's own key id, which is the common
// case: the agent's signing key id already IS its thumbprint.
func TestSignAgentBinding_KeyIDDefaultsToTheSigner(t *testing.T) {
	v := validPopVector(t)
	signer, pub := signerFor(t, v.SignerSeedHex, v.AgentID)
	created, expires := parseWindow(t, v.SignatureInput)

	got, err := helpers.SignAgentBinding(context.Background(), signer, pub, helpers.PoPOptions{
		URL: v.URL, Created: created, Expires: expires,
	})
	if err != nil {
		t.Fatalf("sign agent binding: %v", err)
	}
	if got.SignatureInput != v.SignatureInput {
		t.Errorf("defaulted keyid changed the bytes\n got %q\nwant %q", got.SignatureInput, v.SignatureInput)
	}
}

func withURL(o helpers.PoPOptions, url string) helpers.PoPOptions {
	o.URL = url
	return o
}

func withWindow(o helpers.PoPOptions, created, expires int64) helpers.PoPOptions {
	o.Created, o.Expires = created, expires
	return o
}
