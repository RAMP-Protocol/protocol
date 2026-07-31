package helpers

// The signature base must carry the Signature-Agent header's bytes VERBATIM,
// quotes included. This is the whole interop property of reading the quoted form:
// an external conformant signer computes its base over `"https://a.example"` with
// the quotes, so if this side canonicalized the header any other way the two bases
// would differ and that signer's signature would not verify here.
//
// A round-trip test cannot pin this. Signing and verifying share
// buildSignatureBase, so a symmetric change — stripping quotes on both sides —
// keeps every self-signed round trip green while breaking exactly the external
// interop the unquoting exists to provide. Verified by mutation: adding a
// quote-strip to componentValue passes the entire helpers suite. These tests
// assert the base bytes directly, so that mutation fails here.

import (
	"net/http"
	"strings"
	"testing"
)

// baseLineFor builds the signature base over a single covered header and returns
// the rendered line for it.
func baseLineFor(t *testing.T, header, value string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "https://exchange.example/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(header, value)
	base, err := buildSignatureBase(req, sigParams{
		Covered: plainComponents(strings.ToLower(header)),
		KeyID:   "k", Alg: AlgEd25519, Created: 1700000000, Expires: 1700000300,
	})
	if err != nil {
		t.Fatalf("buildSignatureBase: %v", err)
	}
	for _, line := range strings.Split(base, "\n") {
		if strings.HasPrefix(line, `"`+strings.ToLower(header)+`"`) {
			return line
		}
	}
	t.Fatalf("no %q line in base:\n%s", header, base)
	return ""
}

// TestSignatureBase_quotedSignatureAgentKeepsItsQuotes is the assertion the
// mutation defeats. The covered value is the header as sent — the SDK unquotes
// only the value it SURFACES to callers, never the bytes it signs over.
func TestSignatureBase_quotedSignatureAgentKeepsItsQuotes(t *testing.T) {
	const wire = `"https://agent.example"`
	line := baseLineFor(t, SignatureAgentHeader, wire)

	want := `"signature-agent": ` + wire
	if line != want {
		t.Errorf("base line = %s\nwant             %s\n\nthe covered value must be the header's bytes verbatim; an external signer computed its base over the quoted form",
			line, want)
	}
	if !strings.Contains(line, `"https://agent.example"`) {
		t.Error("the quotes were stripped from the signature base — an externally-signed quoted header will no longer verify")
	}
}

// TestSignatureBase_bareSignatureAgentUnchanged is the other half: the bare form
// RAMP itself emits must keep producing exactly the base it always did. Together
// with the test above this pins that the two wire forms produce DIFFERENT bases —
// which is correct, because they are different bytes, even though both surface
// the same directory through signatureAgentOf.
func TestSignatureBase_bareSignatureAgentUnchanged(t *testing.T) {
	const wire = "https://agent.example"
	line := baseLineFor(t, SignatureAgentHeader, wire)

	want := `"signature-agent": ` + wire
	if line != want {
		t.Errorf("base line = %s\nwant             %s", line, want)
	}
}

// TestSignatureAgentOf_readsEveryFieldLine pins that the reader and the signature
// base see the SAME header. HTTP allows a field to arrive as several lines; the
// base joins them all, so reading only the first would derive an identity from
// one value while the signature committed to both. The joined value is not a
// valid item, so it falls through verbatim — which is the point: both sides then
// agree on the same string.
func TestSignatureAgentOf_readsEveryFieldLine(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://exchange.example/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add(SignatureAgentHeader, `"https://a.example"`)
	req.Header.Add(SignatureAgentHeader, `"https://b.example"`)

	surfaced := signatureAgentOf(req)
	covered, err := componentValue(req, CoveredComponent{Name: signatureAgentLower})
	if err != nil {
		t.Fatalf("componentValue: %v", err)
	}
	if surfaced != covered {
		t.Errorf("surfaced %q but signed %q — a repeated header must not give the reader and the base different values",
			surfaced, covered)
	}
	if surfaced == "https://a.example" {
		t.Error("only the first field line was read; the signature covers both")
	}
}

// TestSignatureAgentOf_parametersDropped pins the third outcome the accept-or-
// verbatim pair does not cover, including that it WIDENS what reaches the
// resolver: the parameterized spelling used to be an unresolvable host and is now
// a fetchable one. Documented rather than prevented — no parameter is defined for
// this field, folding one into the URI would produce a host nothing resolves, and
// a signer could send the bare form directly anyway.
func TestSignatureAgentOf_parametersDropped(t *testing.T) {
	for _, tc := range []struct{ wire, want string }{
		{`"https://a.example";expires=1`, "https://a.example"},
		{`https://a.example;q=1`, "https://a.example"},
		{`https://evil.example;x="https://good.example"`, "https://evil.example"},
	} {
		req, err := http.NewRequest(http.MethodPost, "https://exchange.example/x", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set(SignatureAgentHeader, tc.wire)
		if got := signatureAgentOf(req); got != tc.want {
			t.Errorf("signatureAgentOf(%s) = %q; want %q", tc.wire, got, tc.want)
		}
		// The parameters stay in the signed bytes even though the reader drops them.
		if covered, err := componentValue(req, CoveredComponent{Name: signatureAgentLower}); err != nil {
			t.Fatalf("componentValue: %v", err)
		} else if covered != tc.wire {
			t.Errorf("covered value = %q; want the wire bytes %q", covered, tc.wire)
		}
	}
}

// TestSignatureAgentOf_doesNotDependOnTheBase states the split the two tests above
// rest on, as an executable claim rather than a comment: for one set of wire bytes
// the SURFACED value is unquoted while the SIGNED value is not. Reading the header
// and canonicalizing it are separate concerns, and collapsing them is the mutation.
func TestSignatureAgentOf_doesNotDependOnTheBase(t *testing.T) {
	const wire = `"https://agent.example"`
	req, err := http.NewRequest(http.MethodPost, "https://exchange.example/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(SignatureAgentHeader, wire)

	if surfaced := signatureAgentOf(req); surfaced != "https://agent.example" {
		t.Errorf("surfaced value = %q; want the directory without quotes", surfaced)
	}
	if signed := baseLineFor(t, SignatureAgentHeader, wire); !strings.HasSuffix(signed, wire) {
		t.Errorf("signed value = %s; want the wire bytes %s", signed, wire)
	}
	if got := req.Header.Get(SignatureAgentHeader); got != wire {
		t.Errorf("header mutated to %q; want %q untouched on the wire", got, wire)
	}
}
