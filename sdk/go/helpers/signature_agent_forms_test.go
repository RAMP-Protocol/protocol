package helpers_test

// Signature-Agent wire forms. Web Bot Auth defines the header value as an RFC
// 8941 String, so the conformant form is QUOTED — quoting is not optional in
// structured fields, a String has exactly one serialization. RAMP itself emits
// the value bare, which is a Token rather than a String.
//
// Both forms must yield the same directory URI, on the VerifiedRequest and in the
// resolver context. Reading the quoted form verbatim is what made a conformant
// signer unresolvable: the quotes travelled into the directory URI, no host could
// be parsed out of it, and key resolution failed the request.
//
// The spec's sf-dictionary form and its data: URI scheme are deliberately NOT
// supported; see TestSignatureAgent_dictionaryFormNotUnwrapped.

import (
	"context"
	"net/http"
	"testing"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

const wantDirectory = "https://agent.example"

// TestSignatureAgent_formsYieldSameDirectory pins that the quoted and bare forms
// both verify and both surface the same bare URI. Verification passing is half
// the assertion: the signature base is built from the header's raw bytes, so a
// quoted value must be signed and verified WITH its quotes while the value read
// off the result has them stripped. If those two ever collapsed into one
// treatment, one of these subtests would fail.
func TestSignatureAgent_formsYieldSameDirectory(t *testing.T) {
	for _, tc := range []struct {
		name   string
		header string
	}{
		{"quoted sf-string (Web Bot Auth conformant)", `"` + wantDirectory + `"`},
		{"bare token (RAMP's own emission)", wantDirectory},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(`{"resource_id":"r1"}`)
			req, pub := signFixture(t, body, func(r *http.Request) {
				r.Header.Set(helpers.SignatureAgentHeader, tc.header)
			})

			vr, err := helpers.VerifyRequest(req, body, pub, helpers.VerifyOptions{Now: tNow})
			if err != nil {
				t.Fatalf("VerifyRequest with Signature-Agent %s: %v", tc.header, err)
			}
			if vr.SignatureAgent != wantDirectory {
				t.Errorf("SignatureAgent = %q; want %q (header on the wire was %s)",
					vr.SignatureAgent, wantDirectory, tc.header)
			}
			// The wire bytes are untouched: a relay forwards this header verbatim so
			// the agent's signature still verifies at the next hop.
			if got := req.Header.Get(helpers.SignatureAgentHeader); got != tc.header {
				t.Errorf("header mutated to %q; want %q left on the wire", got, tc.header)
			}
		})
	}
}

// TestSignatureAgent_quotedFormReachesResolver covers the failure that made this
// a 401 rather than a cosmetic storage-format wart: the resolver fetches the
// signer's directory from the value threaded into its context. Given the quotes
// verbatim it can parse no host, reports the key unknown, and the request is
// rejected.
func TestSignatureAgent_quotedFormReachesResolver(t *testing.T) {
	body := []byte(`{"resource_id":"r2"}`)
	req, spy, captured := signResolvedFixture(t, body, "thumbprint.v1", `"`+wantDirectory+`"`)

	if _, err := helpers.VerifyRequestResolved(
		context.Background(), req, body, spy, helpers.VerifyOptions{Now: tNow},
	); err != nil {
		t.Fatalf("VerifyRequestResolved: %v", err)
	}
	if captured() != wantDirectory {
		t.Errorf("resolver context directory = %q; want %q — a resolver cannot fetch a directory whose URI still carries quotes",
			captured(), wantDirectory)
	}
}

// TestSignatureAgent_dictionaryFormNotUnwrapped pins a deliberate refusal, not an
// oversight. The current directory draft makes Signature-Agent an sf-dictionary
// (`agent2="https://…"`), and RAMP does not read it: the member value would have
// to be selected by the covered component's key param, and the same draft admits
// a data: member that inlines an entire key directory into the header. Key
// resolution here rests on FETCHING the directory from a location the signer had
// to control, so an inline directory removes the boundary it depends on.
//
// The dictionary form therefore falls through verbatim and is rejected downstream
// where a directory has to resolve to a real host. The assertion is that no
// unwrapping happens — a future decision to support the form should break this
// test and be made deliberately.
func TestSignatureAgent_dictionaryFormNotUnwrapped(t *testing.T) {
	const dictForm = `agent2="` + wantDirectory + `"`
	body := []byte(`{"resource_id":"r3"}`)
	req, pub := signFixture(t, body, func(r *http.Request) {
		r.Header.Set(helpers.SignatureAgentHeader, dictForm)
	})

	vr, err := helpers.VerifyRequest(req, body, pub, helpers.VerifyOptions{Now: tNow})
	if err != nil {
		t.Fatalf("VerifyRequest: %v", err)
	}
	if vr.SignatureAgent == wantDirectory {
		t.Fatalf("SignatureAgent = %q: the sf-dictionary form was unwrapped, but RAMP does not support it", vr.SignatureAgent)
	}
	if vr.SignatureAgent != dictForm {
		t.Errorf("SignatureAgent = %q; want the value passed through verbatim as %q", vr.SignatureAgent, dictForm)
	}
}

// TestSignatureAgent_emptyStaysEmpty guards the static bootstrap path, where the
// signer binds an empty Signature-Agent so the covered set is uniform. An empty
// value must not be turned into anything by the structured-field parsing.
func TestSignatureAgent_emptyStaysEmpty(t *testing.T) {
	body := []byte(`{"resource_id":"r4"}`)
	req, pub := signFixture(t, body, nil)

	vr, err := helpers.VerifyRequest(req, body, pub, helpers.VerifyOptions{Now: tNow})
	if err != nil {
		t.Fatalf("VerifyRequest: %v", err)
	}
	if vr.SignatureAgent != "" {
		t.Errorf("SignatureAgent = %q; want empty (empty-bind bootstrap path)", vr.SignatureAgent)
	}
}

// TestSignatureAgent_edgeShapes pins the parser's contract across the shapes a
// single example does not reach: the fallback for values no structured-field
// parser admits, an item carrying parameters, and a string with escapes.
//
// The fallback matters because a host that fails structured-field parsing must
// still reach the caller unchanged rather than becoming empty — values that
// worked before this parsing existed keep working. The draft permits ignoring a
// malformed field but does not require it, and every consumer already has to cope
// with a directory it cannot resolve.
func TestSignatureAgent_edgeShapes(t *testing.T) {
	for _, tc := range []struct {
		name string
		wire string
		want string
	}{
		{
			name: "unterminated string falls back verbatim",
			wire: `"unterminated`,
			want: `"unterminated`,
		},
		{
			// The case the fallback exists for: no structured-field parser admits a
			// non-ASCII name, and this one is an ordinary host that resolves.
			name: "internationalized host falls back verbatim and stays usable",
			wire: "bücher.example",
			want: "bücher.example",
		},
		{
			// Also falls back verbatim, but is NOT usable — the resolver refuses it,
			// because parentheses are not host characters. Recorded next to the case
			// above so the fallback is not read as a promise that whatever survives
			// here will resolve: this function types the wire value and stops there.
			name: "unusable host also falls back verbatim",
			wire: "agent_(1).example",
			want: "agent_(1).example",
		},
		{
			// Parameters are not defined for this field. They parse, and the
			// directory is the item's value — the params are dropped, not appended
			// to the URI. Pinned because silently folding ";v=1" into the directory
			// would produce an unresolvable host.
			name: "parameters on a quoted string are ignored",
			wire: `"https://agent.example";v=1`,
			want: "https://agent.example",
		},
		{
			name: "parameters on a bare token are ignored",
			wire: `https://agent.example;v=1`,
			want: "https://agent.example",
		},
		{
			// RFC 8941 strings escape \ and ". The parser unescapes; the surfaced
			// directory is the decoded text.
			name: "escaped quote inside a string is decoded",
			wire: `"https://agent.example/\"x"`,
			want: `https://agent.example/"x`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(`{"resource_id":"r5"}`)
			req, pub := signFixture(t, body, func(r *http.Request) {
				r.Header.Set(helpers.SignatureAgentHeader, tc.wire)
			})

			vr, err := helpers.VerifyRequest(req, body, pub, helpers.VerifyOptions{Now: tNow})
			if err != nil {
				t.Fatalf("VerifyRequest with Signature-Agent %s: %v", tc.wire, err)
			}
			if vr.SignatureAgent != tc.want {
				t.Errorf("SignatureAgent = %q; want %q", vr.SignatureAgent, tc.want)
			}
			// Whatever the shape, the wire bytes are never rewritten.
			if got := req.Header.Get(helpers.SignatureAgentHeader); got != tc.wire {
				t.Errorf("header mutated to %q; want %q", got, tc.wire)
			}
		})
	}
}
