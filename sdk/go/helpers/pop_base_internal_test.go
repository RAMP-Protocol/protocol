package helpers

import (
	"net/http"
	"strings"
	"testing"
)

// Why the agent-binding profile builds its own signature base instead of routing
// through the RAMP one.
//
// buildSignatureBase reconstructs @target-uri from a PARSED URL, which re-encodes
// the path and normalizes the host. The edge rebuilds its base from the raw
// request line it received, so for any URL that does not survive that round trip
// the two disagree, the signature cannot verify, and the edge answers an
// undifferentiated 403 that names nothing.
//
// These tests pin both halves: agreement where the URL is round-trip stable, and
// DISAGREEMENT where it is not. The disagreement cases are the reason
// popSignatureBase takes the verbatim string, so anyone tempted to "simplify" it
// back onto the request type fails here with the reason attached.

// rampBaseFor renders the RAMP base builder's view of the same two covered
// components, so the two builders can be compared directly.
func rampBaseFor(t *testing.T, method, rawURL, keyID string, created, expires int64) string {
	t.Helper()
	req, err := http.NewRequest(method, rawURL, nil)
	if err != nil {
		t.Fatalf("build request for %q: %v", rawURL, err)
	}
	base, err := buildSignatureBase(req, sigParams{
		Label:   popLabel,
		Covered: plainComponents("@method", "@target-uri"),
		KeyID:   keyID,
		Alg:     AlgEd25519,
		Created: created,
		Expires: expires,
	})
	if err != nil {
		t.Fatalf("build ramp signature base for %q: %v", rawURL, err)
	}
	return base
}

const (
	baseTestKeyID   = "wSp1Ud8Phi33WBixrTcV5U38Q5JZ0VGpTAetgQUQw2k"
	baseTestCreated = int64(1_700_000_000)
	baseTestExpires = int64(1_700_000_600)
)

func popBaseFor(rawURL string) string {
	return popSignatureBase(http.MethodGet, rawURL,
		popSignatureParams(baseTestKeyID, baseTestCreated, baseTestExpires))
}

// Where the two builders agree, and it is a wider set than one might assume: a
// URL value preserves host case, an explicit default port, and a raw space in the
// path, so none of those is a reason for this profile to own a builder.
func TestPopSignatureBase_AgreesWithRAMPBuilderOnStableURLs(t *testing.T) {
	stable := map[string]string{
		"ordinary delivery url": "https://cdn.example/doc?agent_id=" + baseTestKeyID,
		"full signed query":     "https://cdn.example/a/b/c.html?exp=1700000600&kid=ex.v1&sig=abc",
		"no query":              "https://cdn.example/doc",
		"mixed-case host":       "https://CDN.Example/doc?agent_id=" + baseTestKeyID,
		"explicit default port": "https://cdn.example:443/doc?agent_id=" + baseTestKeyID,
		"raw space in path":     "https://cdn.example/a b/doc?agent_id=" + baseTestKeyID,
	}
	for name, rawURL := range stable {
		t.Run(name, func(t *testing.T) {
			want := rampBaseFor(t, http.MethodGet, rawURL, baseTestKeyID, baseTestCreated, baseTestExpires)
			if got := popBaseFor(rawURL); got != want {
				t.Errorf("signature bases disagree on a stable URL\n got %q\nwant %q", got, want)
			}
		})
	}
}

// The one shape that genuinely diverges, and the reason this profile signs the
// verbatim string: the RAMP builder reads the DECODED path off the URL value, so
// every percent-escape in the path is expanded before it reaches the signed bytes.
//
// %2F is the sharpest case — it decodes to a real separator, so the signature
// would cover a different path structure than the wire carried. %20 and a
// non-ASCII escape lose their encoding the same way. An edge rebuilding its base
// from the raw request line reconstructs the ESCAPED form, so a signer that
// signed the decoded one produces a proof that cannot verify, and the failure
// surfaces as a blanket 403 naming nothing.
func TestPopSignatureBase_DivergesOnAPercentEncodedPath(t *testing.T) {
	tricky := map[string]string{
		"encoded separator in path": "https://cdn.example/a%2Fb/doc?agent_id=" + baseTestKeyID,
		"encoded space in path":     "https://cdn.example/a%20b/doc?agent_id=" + baseTestKeyID,
		"encoded non-ascii in path": "https://cdn.example/caf%C3%A9?agent_id=" + baseTestKeyID,
	}
	for name, rawURL := range tricky {
		t.Run(name, func(t *testing.T) {
			ramp := rampBaseFor(t, http.MethodGet, rawURL, baseTestKeyID, baseTestCreated, baseTestExpires)
			pop := popBaseFor(rawURL)
			if pop == ramp {
				t.Errorf("expected the two builders to disagree on %q, but both produced %q — "+
					"if the RAMP builder stopped decoding the path, this profile's verbatim contract needs rechecking",
					rawURL, pop)
			}
			// The profile's own base must carry the URL exactly as handed over.
			if want := `"@target-uri": ` + rawURL; !strings.Contains(pop, want) {
				t.Errorf("agent-binding base did not carry the verbatim URL\n got %q\nwant it to contain %q", pop, want)
			}
		})
	}
}
