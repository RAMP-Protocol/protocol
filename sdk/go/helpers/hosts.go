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
	// A trailing colon parses as a host with an empty port and would otherwise
	// compare equal to itself. It is not a domain anyone meant to write, and the
	// callers here concatenate the value into a URL, so it is refused rather than
	// quietly normalized away.
	if strings.HasSuffix(host, ":") {
		return false, nil
	}
	return host == ref, nil
}

// HostAnchored reports whether candidate's hostname is anchored to anchor's —
// equal to it, or a subdomain of it. Either side may be a bare domain, a
// host:port pair, or a full URL; a reference that does not parse is returned as
// an error, which callers treat as "not anchored".
//
// The use is checking a value a remote document supplied against the host that
// served that document: it may point at itself or at one of its own subdomains,
// and nothing else. Without it, a host could redirect a signed request — or a
// revocation poll — to an unrelated third-party address that a dial-time address
// guard would happily allow, because the address is perfectly public.
//
// The PORT is deliberately not part of the comparison. The property being
// enforced is "not an unrelated host", and a service on a non-default port of the
// same name is not another host — TLS binds hostnames, not ports. Comparing with
// the port would leave an Exchange that advertises https://exchange.example:8443
// permanently unable to receive a usage report, for no security gain.
func HostAnchored(anchor, candidate string) (bool, error) {
	anchorHost, err := hostnameOf(anchor)
	if err != nil {
		return false, fmt.Errorf("anchor host: %w", err)
	}
	candidateHost, err := hostnameOf(candidate)
	if err != nil {
		return false, fmt.Errorf("candidate host: %w", err)
	}
	return sameOrSubdomain(anchorHost, candidateHost), nil
}

// hostnameOf is HostOf without the port, and with IPv6 brackets removed. It backs
// the anchoring comparison; IsBareHost keeps using HostOf, because there a port is
// part of what the caller legitimately named.
func hostnameOf(ref string) (string, error) {
	host, err := HostOf(ref)
	if err != nil {
		return "", err
	}
	// url.URL.Hostname() strips a trailing :port and the brackets around an IPv6
	// literal. Re-parsing the extracted authority is the cheapest way to reuse
	// exactly that rule rather than restate it.
	parsed, err := url.Parse("//" + host)
	if err != nil {
		return "", fmt.Errorf("%w: %q: %w", ErrInvalidHost, ref, err)
	}
	return parsed.Hostname(), nil
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
