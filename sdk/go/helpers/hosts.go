package helpers

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Host predicates for the routing checks that precede a signed call to an
// address a network party named.
//
// Both exist for the same reason: a value that arrives inside an offer, or
// inside a manifest that offer pointed at, is about to be concatenated into a URL
// or dialed directly. Neither check is about the network — they are pure string
// work, which is why they sit in the IO-free tier and can run before anything is
// fetched.

// ErrInvalidHost signals a reference that cannot be read as a host at all.
var ErrInvalidHost = errors.New("helpers: reference is not a usable host")

// HostOf extracts the host (including any port) from a bare domain, a host:port
// pair, or a full URL. A ref with no scheme is parsed as though it carried https,
// since a bare domain is otherwise indistinguishable from a path.
func HostOf(ref string) (string, error) {
	if strings.TrimSpace(ref) == "" {
		return "", fmt.Errorf("%w: empty reference", ErrInvalidHost)
	}
	toParse := ref
	if !strings.Contains(ref, "://") {
		toParse = "https://" + ref
	}
	parsed, err := url.Parse(toParse)
	if err != nil {
		return "", fmt.Errorf("%w: %q: %w", ErrInvalidHost, ref, err)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("%w: %q has no host", ErrInvalidHost, ref)
	}
	return parsed.Host, nil
}

// IsBareHost reports whether ref is EXACTLY a host — nothing a URL could carry
// besides the authority. It answers false for a ref with a scheme, userinfo, a
// path, a query, or a fragment, because HostOf had to strip something to reach
// the host. A port is NOT a strip: "exchange.example:8443" is a bare host, and
// the well-known resolver concatenates host-with-port unchanged.
//
// It exists for the callers that hand a network-supplied domain to code which
// builds a URL by concatenation. There, narrowing a rich reference to its host is
// the wrong repair: the value was never a domain, and accepting it silently means
// the far side chose the path that gets fetched, not just the host it is fetched
// from. Comparing against the extracted host is what makes the rejection
// structural, rather than a blocklist of the separators anyone thought to name.
func IsBareHost(ref string) (bool, error) {
	host, err := HostOf(ref)
	if err != nil {
		return false, err
	}
	return host == ref, nil
}

// HostAnchored reports whether candidate's host is anchored to anchor's host —
// equal to it, or a subdomain of it. Either side may be a bare domain, a
// host:port pair, or a full URL; a reference that does not parse is returned as
// an error, which callers treat as "not anchored".
//
// The use is checking a value a remote document supplied against the host that
// served that document: it may point at itself or at one of its own subdomains,
// and nothing else. Without it, a host could redirect a signed request — or a
// revocation poll — to an unrelated third-party address that a dial-time address
// guard would happily allow, because the address is perfectly public.
func HostAnchored(anchor, candidate string) (bool, error) {
	anchorHost, err := HostOf(anchor)
	if err != nil {
		return false, fmt.Errorf("anchor host: %w", err)
	}
	candidateHost, err := HostOf(candidate)
	if err != nil {
		return false, fmt.Errorf("candidate host: %w", err)
	}
	return sameOrSubdomain(anchorHost, candidateHost), nil
}

// sameOrSubdomain reports whether candidate equals anchor or is a subdomain of
// it. Comparison is case-insensitive and tolerant of a trailing root dot. A
// subdomain match requires a full dot-delimited label boundary, so "evil-a.com"
// is NOT treated as a subdomain of "a.com" — the check a bare suffix match gets
// wrong, and the one an attacker registers a domain to exploit.
func sameOrSubdomain(anchor, candidate string) bool {
	a := strings.ToLower(strings.TrimSuffix(anchor, "."))
	c := strings.ToLower(strings.TrimSuffix(candidate, "."))
	if a == "" {
		return false
	}
	return c == a || strings.HasSuffix(c, "."+a)
}
