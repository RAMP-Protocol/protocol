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
	parsed, err := parseRef(ref)
	if err != nil {
		return "", err
	}
	return parsed.Host, nil
}

// parseRef reads a bare domain, a host:port pair, or a full URL into a URL with a
// non-empty Host. A ref with no scheme is parsed as though it carried https, since
// a bare domain is otherwise indistinguishable from a path. One parse behind both
// host predicates, so neither can disagree with the other about what a reference
// even is.
func parseRef(ref string) (*url.URL, error) {
	if strings.TrimSpace(ref) == "" {
		return nil, fmt.Errorf("%w: empty reference", ErrInvalidHost)
	}
	toParse := ref
	if !strings.Contains(ref, "://") {
		toParse = "https://" + ref
	}
	parsed, err := url.Parse(toParse)
	if err != nil {
		return nil, fmt.Errorf("%w: %q: %w", ErrInvalidHost, ref, err)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("%w: %q has no host", ErrInvalidHost, ref)
	}
	return parsed, nil
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

// HostAnchored reports whether candidate is anchored to anchor — the same host
// and port, or a subdomain of that host on that port. Either side may be a bare
// domain, a host:port pair, or a full URL; a reference that does not parse is
// returned as an error, which callers treat as "not anchored".
//
// The use is checking a value a remote document supplied against the host that
// served that document: it may point at itself or at one of its own subdomains,
// and nothing else. Without it, a host could redirect a signed request — or a
// revocation poll — to an unrelated third-party address that a dial-time address
// guard would happily allow, because the address is perfectly public.
//
// The PORT is part of the comparison. What is being anchored is a place a signed
// call is sent, and a different port is a different service — one the party that
// published the anchor need not control. An Exchange reachable on a non-default
// port says so on both sides: the port belongs in the value the offer names as
// much as in the endpoint the manifest advertises.
//
// A DEFAULT port and its omission are the same port, so https://x, https://x:443
// and x all anchor to one another. url.Parse does not materialize an implicit
// port, and refusing an operator who merely wrote :443 out in full would be a
// spelling check wearing a security check's clothes.
//
// The SCHEME is still not compared. Whether a leg may run in the clear is the
// guarded transport's decision, made in one place from one flag, and the default
// port normalization above is deliberately scheme-relative so that http://x and
// https://x continue to anchor rather than diverging on 80 versus 443.
func HostAnchored(anchor, candidate string) (bool, error) {
	anchorHost, anchorPort, err := hostPortOf(anchor)
	if err != nil {
		return false, fmt.Errorf("anchor host: %w", err)
	}
	candidateHost, candidatePort, err := hostPortOf(candidate)
	if err != nil {
		return false, fmt.Errorf("candidate host: %w", err)
	}
	// Compared as two values rather than one joined string. Joined, the label
	// boundary below would have to find ".a.com" at the end of "sub.a.com:8443"
	// and would refuse a subdomain for having a port — the right answer reached
	// through the wrong comparison is still the wrong comparison.
	return sameOrSubdomain(anchorHost, candidateHost) && anchorPort == candidatePort, nil
}

// hostPortOf splits a reference into its hostname and its CANONICAL port. It backs
// the anchoring comparison, which needs the two apart; IsBareHost keeps using
// HostOf, because there a port is part of what the caller legitimately named and
// the value is compared verbatim.
//
// url.URL.Hostname() drops a trailing :port and the brackets around an IPv6
// literal, and Port() yields the port alone, so the split is the standard
// library's rather than this package's.
func hostPortOf(ref string) (host, port string, err error) {
	parsed, err := parseRef(ref)
	if err != nil {
		return "", "", err
	}
	return parsed.Hostname(), canonicalPort(parsed.Scheme, parsed.Port()), nil
}

// defaultPorts is the port a scheme reaches when none is written.
var defaultPorts = map[string]string{"http": "80", "https": "443"}

// canonicalPort renders "the same port" as one string, so a port written out in
// full and the same port left implicit compare equal. An unknown scheme has no
// default to fold, so its port is kept verbatim.
func canonicalPort(scheme, port string) string {
	if port == "" {
		return ""
	}
	if def, ok := defaultPorts[strings.ToLower(scheme)]; ok && port == def {
		return ""
	}
	return port
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
