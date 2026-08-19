package helpers

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Identity-document resolution: turning a WellKnownManifest.identity_documents
// member into a URL that may be fetched, or refusing it.
//
// This is a ROUTING predicate like HostAnchored, and it deliberately does NOT
// reuse it. HostAnchored answers the endpoint rule — host or subdomain — and the
// two fields fail differently. Whoever takes over the host an `endpoint` names
// misdirects calls they still cannot sign for; whoever takes over the host an
// identity document names publishes their own keys and BECOMES the participant.
// A dangling DNS record on one subdomain is enough for that, without the
// participant ever losing the host that serves ramp.json, so this rule is exact
// same origin and a subdomain is refused.
//
// Pure string work, no I/O, so it runs before anything is fetched.

// ResolveIdentityDocument resolves ref — an RFC 3986 URI reference read from
// WellKnownManifest.identity_documents — against manifestURL, the URL the
// manifest was actually FETCHED FROM, and returns the absolute URL to fetch.
//
// The base is the fetch URL, never the manifest's self-asserted `domain` member:
// a hostile manifest that named its own anchor would validate itself. Refusals,
// in order: the base must be https, name a host and carry no userinfo; the
// reference must be non-empty and parse; and after resolution the URL must be
// https, carry no userinfo, and sit on the SAME ORIGIN as the base — equal
// hostname, equal effective port, where an omitted port and :443 are the same
// port.
//
// Vetting the base is a refusal rather than a courtesy because the later checks
// cannot stand in for it. A base of http://a.example/ramp.json resolving to
// https://a.example/doc passes every one of them: the hostnames match and both
// sides fold to no port. Accepting it means trusting a manifest that arrived
// unauthenticated, which lets an on-path attacker who rewrote that plaintext
// document name any path on the host — a user-content upload path, say — and
// have it served back over TLS from the legitimate origin. The protocol already
// requires the manifest be served over TLS, so a base that is not https is out
// of contract and this says so instead of working around it.
func ResolveIdentityDocument(manifestURL, ref string) (string, error) {
	base, err := url.Parse(manifestURL)
	if err != nil {
		// Deliberately does not echo the value: an unparseable URL can still
		// carry a credential.
		return "", errors.New("identity document: manifest URL is not a URL")
	}
	if base.User != nil {
		// Deliberately does not echo the URL: it carries the credential.
		return "", errors.New("identity document: manifest URL carries userinfo")
	}
	// url.Parse lowercases the scheme, so this compares the scheme itself and
	// not how it was spelled.
	if base.Scheme != "https" {
		return "", fmt.Errorf("identity document: manifest URL %q is not https", manifestURL)
	}
	if base.Host == "" {
		return "", fmt.Errorf("identity document: manifest URL %q names no host", manifestURL)
	}

	if strings.TrimSpace(ref) == "" {
		return "", errors.New("identity document: empty reference")
	}
	refURL, err := url.Parse(ref)
	if err != nil {
		// Deliberately does not echo the value, and deliberately does not wrap
		// the parse error: an unparseable reference can still carry a
		// credential, and url.Error prints the input it failed on.
		return "", errors.New("identity document: reference is not a URI reference")
	}
	resolved := base.ResolveReference(refURL)
	if resolved.User != nil {
		// Deliberately does not echo the reference: it carries the credential.
		return "", errors.New("identity document: reference carries userinfo")
	}
	if resolved.Scheme != "https" {
		return "", fmt.Errorf("identity document: reference %q does not resolve to an https URL", ref)
	}

	baseHost, resolvedHost := base.Hostname(), resolved.Hostname()
	// Shape BEFORE case folding, the ordering audience.go already fixes: U+212A
	// KELVIN SIGN case-folds to a plain ASCII "k", so EqualFold reports a host
	// spelled with it and a plain ASCII host as the SAME name. IsBareDomain is
	// the repo's one answer to "is this the host shape the wire admits", it is
	// already ported and vector-tested in all three languages, and it refuses
	// everything a rebuilt authority below would have to special-case — a
	// non-ASCII label, an IP literal in brackets, an empty host, a trailing root
	// dot.
	if !IsBareDomain(baseHost) {
		return "", fmt.Errorf("identity document: manifest URL %q does not name a plain host", manifestURL)
	}
	if !IsBareDomain(resolvedHost) {
		return "", fmt.Errorf("identity document: reference %q does not name a plain host", ref)
	}
	if !strings.EqualFold(baseHost, resolvedHost) {
		return "", fmt.Errorf("identity document: reference %q is not on the manifest's origin", ref)
	}
	basePort := canonicalPort(base.Scheme, base.Port())
	if basePort != canonicalPort(resolved.Scheme, resolved.Port()) {
		return "", fmt.Errorf("identity document: reference %q is on a different port than the manifest", ref)
	}

	// Canonical output: the host lowercased and a default port folded away. The
	// same input then produces the same string in every SDK, instead of each
	// echoing however the manifest happened to spell the authority. Safe to
	// rebuild the authority by hand only because IsBareDomain has already refused every
	// shape that would need quoting.
	out := *resolved
	out.Host = strings.ToLower(resolvedHost)
	if basePort != "" {
		out.Host += ":" + basePort
	}
	return out.String(), nil
}
