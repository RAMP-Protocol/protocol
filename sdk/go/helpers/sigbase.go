package helpers

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
)

// RFC 9421 (HTTP Message Signatures) signature-base construction, shared by the
// signer (sign.go) and the verifier (verify.go). The base is the exact byte
// string both sides feed to the crypto: keeping it in one place is what makes
// sign→verify round-trip and what keeps this SDK byte-identical with the
// service-internal implementation it relocates (ADR-020 §8).
//
// Coverage is the RAMP-required set: @method and @target-uri (bind the verb and
// destination so a signature cannot be replayed against another path),
// content-digest (bind the body), and authorization (bind the bearer so a token
// cannot be swapped under a signed envelope). x-ramp-entitlement-biscuit is
// bound additionally whenever it is present.

// ComponentParam is a single RFC 9421 §2.4 parameter on a covered-component
// identifier — e.g. the key="sig1" on `"signature";key="sig1"`.
type ComponentParam struct {
	Key string
	Val string
}

// CoveredComponent is one entry in a signature's covered-component set: a
// component name plus any RFC 9421 component parameters. Plain components
// (@method, content-digest, …) carry nil Params; a forwarding-chain link carries
// a single {Key:"key", Val:"sigN-1"} param on Name "signature".
type CoveredComponent struct {
	Name   string
	Params []ComponentParam
}

// plainComponents builds CoveredComponents with no parameters from names.
func plainComponents(names ...string) []CoveredComponent {
	out := make([]CoveredComponent, 0, len(names))
	for _, n := range names {
		out = append(out, CoveredComponent{Name: n})
	}
	return out
}

// componentParam returns the value of the named parameter on c, or "" if absent.
func componentParam(c CoveredComponent, key string) string {
	for _, p := range c.Params {
		if p.Key == key {
			return p.Val
		}
	}
	return ""
}

// renderComponent serializes a covered-component identifier as it appears in the
// Signature-Input header and the @signature-params line: `"name";k="v";…`. The
// name is rendered verbatim (callers supply already-lowercased names) so the
// header inner list and the signature-base inner list are byte-identical. For a
// param-less component this yields exactly `"name"` — byte-equal to the old
// single-label quoted string, preserving the N=1 base.
func renderComponent(c CoveredComponent) string {
	var b strings.Builder
	b.WriteByte('"')
	b.WriteString(c.Name)
	b.WriteByte('"')
	for _, p := range c.Params {
		fmt.Fprintf(&b, ";%s=%q", p.Key, p.Val)
	}
	return b.String()
}

// sigParams captures the parameters of a single Signature-Input label.
type sigParams struct {
	Label   string
	Covered []CoveredComponent
	KeyID   string
	Alg     string
	Created int64
	Expires int64
	// RawInner is the VERBATIM member value from the wire Signature-Input
	// (everything after "label="). RFC 9421 §2.5 terminates the signature base
	// with this exact byte sequence — parameter order and spacing are the
	// signer's choice — so the VERIFY path must rebuild the base from it. Empty
	// on the SIGN path, where the base and the emitted header both come from
	// signatureInputInner and are identical by construction.
	RawInner string
}

// requiredCoveredComponents is the minimum covered-component set (by name). The
// biscuit header is appended conditionally (see coveredFor).
var requiredCoveredComponents = []string{"@method", "@target-uri", "content-digest", "authorization", signatureAgentLower}

// entitlementHeader is the canonical entitlement-biscuit header; when present on
// a request the signature MUST commit to it.
const (
	entitlementHeader      = "X-RAMP-Entitlement-Biscuit"
	entitlementHeaderLower = "x-ramp-entitlement-biscuit"
)

// ContentDigest returns the RFC 9530 Content-Digest header value for body:
// sha-256=:<base64(SHA-256(body))>:.
func ContentDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
}

// coveredFor returns the covered-component set for a request: the RAMP minimum
// plus the entitlement-biscuit header when it is populated on req. All names are
// lowercase so the rendered byte output is preserved.
func coveredFor(req *http.Request) []CoveredComponent {
	names := append([]string(nil), requiredCoveredComponents...)
	if req.Header.Get(entitlementHeader) != "" {
		names = append(names, entitlementHeaderLower)
	}
	return plainComponents(names...)
}

// rampChainCoveredComponents returns the covered set for an appended signature
// (sigN, N>1): the base set plus a forwarding-chain link
// "signature";key="<prevLabel>" so sigN cryptographically commits to its
// predecessor (RAMP-56, RFC 9421 §2.4). When hasPrev is false it degrades to the
// plain base set — identical to a sig1 covered set.
func rampChainCoveredComponents(req *http.Request, prevLabel string, hasPrev bool) []CoveredComponent {
	covered := coveredFor(req)
	if hasPrev {
		covered = append(covered, CoveredComponent{
			Name:   "signature",
			Params: []ComponentParam{{Key: "key", Val: prevLabel}},
		})
	}
	return covered
}

// buildSignatureBase assembles the RFC 9421 §2.5 signature base over the
// covered derived components (@method, @target-uri, …) and literal headers,
// terminated by the @signature-params line carrying the verbatim inner list and
// parameters. Canonical value rules per §2.4.
func buildSignatureBase(req *http.Request, params sigParams) (string, error) {
	var b bytes.Buffer
	for _, c := range params.Covered {
		v, err := componentValue(req, c)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "%s: %s\n", renderComponent(c), v)
	}
	// Verify path: the base terminates with the signer's verbatim inner list
	// from the wire (RFC 9421 §2.5) — never a re-rendering in our own parameter
	// order. Sign path: RawInner is empty and the rendered inner is what gets
	// emitted in Signature-Input, so base and header stay identical.
	inner := params.RawInner
	if inner == "" {
		inner = signatureInputInner(params)
	}
	fmt.Fprintf(&b, "\"@signature-params\": %s", inner)
	return b.String(), nil
}

// signatureInputInner renders the structured-field inner list + parameter tail,
// the exact value used both inside @signature-params and as the Signature-Input
// header body.
func signatureInputInner(p sigParams) string {
	return "(" + quotedList(p.Covered) + ")" + renderParamsTail(p)
}

func quotedList(items []CoveredComponent) string {
	parts := make([]string, 0, len(items))
	for _, it := range items {
		parts = append(parts, renderComponent(it))
	}
	return strings.Join(parts, " ")
}

func renderParamsTail(p sigParams) string {
	var b strings.Builder
	if p.KeyID != "" {
		fmt.Fprintf(&b, ";keyid=%q", p.KeyID)
	}
	if p.Alg != "" {
		fmt.Fprintf(&b, ";alg=%q", p.Alg)
	}
	if p.Created != 0 {
		fmt.Fprintf(&b, ";created=%d", p.Created)
	}
	if p.Expires != 0 {
		fmt.Fprintf(&b, ";expires=%d", p.Expires)
	}
	return b.String()
}

// componentValue yields the canonicalized value for a covered component:
// @method, @path, @authority, @target-uri, the RFC 9421 §2.4 "signature";key=…
// forwarding-chain link, or any literal request header.
func componentValue(req *http.Request, c CoveredComponent) (string, error) {
	switch strings.ToLower(c.Name) {
	case "@method":
		return strings.ToUpper(req.Method), nil
	case "@path":
		if req.URL == nil {
			return "", fmt.Errorf("helpers: request URL unset for @path")
		}
		p := req.URL.Path
		if p == "" {
			p = "/"
		}
		return p, nil
	case "@authority":
		auth := req.Host
		if auth == "" && req.URL != nil {
			auth = req.URL.Host
		}
		return strings.ToLower(auth), nil
	case "@target-uri":
		if req.URL == nil {
			return "", fmt.Errorf("helpers: request URL unset for @target-uri")
		}
		return reconstructTargetURI(req), nil
	case "signature":
		return chainLinkValue(req, c)
	default:
		// Values (not Get) so an explicitly-set empty header (bound
		// intentionally) is distinguished from an absent one.
		values := req.Header.Values(http.CanonicalHeaderKey(c.Name))
		if len(values) == 0 {
			return "", fmt.Errorf("helpers: header %q missing from request", c.Name)
		}
		return strings.TrimSpace(strings.Join(values, ", ")), nil
	}
}

// chainLinkValue resolves a "signature";key="sigN" component to the canonical
// RFC 8941 byte-sequence serialization of the referenced Signature dictionary
// member: :base64(bytes):. It decodes the referenced member to raw bytes and
// re-encodes canonically (base64.StdEncoding) rather than splicing the raw wire
// substring, so signer and verifier agree byte-for-byte regardless of incidental
// whitespace around the member on the wire (RAMP-56, Risk R1).
func chainLinkValue(req *http.Request, c CoveredComponent) (string, error) {
	key := componentParam(c, "key")
	if key == "" {
		return "", fmt.Errorf("%w: signature component missing key param", ErrMalformedSignatureInput)
	}
	prevBytes, err := signatureBytesForLabel(req.Header, key)
	if err != nil {
		return "", fmt.Errorf("helpers: resolve chain link %q: %w", key, err)
	}
	return ":" + base64.StdEncoding.EncodeToString(prevBytes) + ":", nil
}

// reconstructTargetURI builds an absolute-form target URI from either an
// outbound request (URL.Scheme/Host set) or an inbound one (Host + TLS), so the
// same helper produces an identical value on both client and server sides.
func reconstructTargetURI(req *http.Request) string {
	scheme := req.URL.Scheme
	if scheme == "" {
		if req.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	host := req.URL.Host
	if host == "" {
		host = req.Host
	}
	path := req.URL.Path
	if path == "" {
		path = "/"
	}
	if raw := req.URL.RawQuery; raw != "" {
		return scheme + "://" + host + path + "?" + raw
	}
	return scheme + "://" + host + path
}
