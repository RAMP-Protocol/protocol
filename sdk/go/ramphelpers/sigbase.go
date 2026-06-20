package ramphelpers

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

// sigParams captures the parameters of a single Signature-Input label.
type sigParams struct {
	Label   string
	Covered []string
	KeyID   string
	Alg     string
	Created int64
	Expires int64
}

// rampCoveredComponents is the minimum covered-component set. The biscuit header
// is appended conditionally (see coveredFor).
var rampCoveredComponents = []string{"@method", "@target-uri", "content-digest", "authorization"}

// entitlementHeader is the canonical entitlement-biscuit header; when present on
// a request the signature MUST commit to it.
const entitlementHeader = "X-RAMP-Entitlement-Biscuit"
const entitlementHeaderLower = "x-ramp-entitlement-biscuit"

// ContentDigest returns the RFC 9530 Content-Digest header value for body:
// sha-256=:<base64(SHA-256(body))>:.
func ContentDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
}

// coveredFor returns the covered-component set for a request: the RAMP minimum
// plus the entitlement-biscuit header when it is populated on req.
func coveredFor(req *http.Request) []string {
	covered := append([]string(nil), rampCoveredComponents...)
	if req.Header.Get(entitlementHeader) != "" {
		covered = append(covered, entitlementHeaderLower)
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
		fmt.Fprintf(&b, "\"%s\": %s\n", strings.ToLower(c), v)
	}
	fmt.Fprintf(&b, "\"@signature-params\": %s", signatureInputInner(params))
	return b.String(), nil
}

// signatureInputInner renders the structured-field inner list + parameter tail,
// the exact value used both inside @signature-params and as the Signature-Input
// header body.
func signatureInputInner(p sigParams) string {
	return "(" + quotedList(p.Covered) + ")" + renderParamsTail(p)
}

func quotedList(items []string) string {
	parts := make([]string, 0, len(items))
	for _, it := range items {
		parts = append(parts, `"`+it+`"`)
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
// @method, @path, @authority, @target-uri, or any literal request header.
func componentValue(req *http.Request, name string) (string, error) {
	switch strings.ToLower(name) {
	case "@method":
		return strings.ToUpper(req.Method), nil
	case "@path":
		if req.URL == nil {
			return "", fmt.Errorf("ramphelpers: request URL unset for @path")
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
			return "", fmt.Errorf("ramphelpers: request URL unset for @target-uri")
		}
		return reconstructTargetURI(req), nil
	default:
		// Values (not Get) so an explicitly-set empty header (bound
		// intentionally) is distinguished from an absent one.
		values := req.Header.Values(http.CanonicalHeaderKey(name))
		if len(values) == 0 {
			return "", fmt.Errorf("ramphelpers: header %q missing from request", name)
		}
		return strings.TrimSpace(strings.Join(values, ", ")), nil
	}
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
