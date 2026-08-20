package helpers

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Host and domain predicates: what a network party's value is allowed to be
// before anything is done with it.
//
// Two kinds live here, and keeping them apart is the point. The ROUTING
// predicates — IsBareHost and HostAnchored — precede a signed call to an address
// a network party named: a value that arrives inside an offer, or inside a
// manifest that offer pointed at, is about to be concatenated into a URL or
// dialed directly. The SHAPE predicate — IsBareDomain — answers a different
// question: whether a value is the form the wire contract admits at all, the
// same rule protovalidate stamps on the domain-valued fields.
//
// None of them is about the network. They are pure string work, which is why
// they sit in the IO-free tier and can run before anything is fetched — and, for
// the audience check that builds on IsBareDomain, before anything is looked up.

// ErrInvalidHost signals a reference that cannot be read as a host at all.
var ErrInvalidHost = errors.New("helpers: reference is not a usable host")

// HostOf extracts the host (including any port) from a bare domain, a host:port
// pair, or a full URL. A ref with no scheme is parsed as though it carried https,
// since a bare domain is otherwise indistinguishable from a path.
func HostOf(ref string) (string, error) {
	parsed, _, err := parseRef(ref)
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
//
// hadScheme reports whether the caller actually WROTE a scheme, which the assumed
// https above would otherwise hide. Anchoring needs that: a scheme decides which
// port counts as the default, so a value that named none must not be treated as
// having named https.
func parseRef(ref string) (parsed *url.URL, hadScheme bool, err error) {
	if strings.TrimSpace(ref) == "" {
		return nil, false, fmt.Errorf("%w: empty reference", ErrInvalidHost)
	}
	toParse := ref
	hadScheme = strings.Contains(ref, "://")
	if !hadScheme {
		toParse = "https://" + ref
	}
	parsed, err = url.Parse(toParse)
	if err != nil {
		return nil, false, fmt.Errorf("%w: %q: %w", ErrInvalidHost, ref, err)
	}
	if parsed.Host == "" {
		return nil, false, fmt.Errorf("%w: %q has no host", ErrInvalidHost, ref)
	}
	// One colon separates a host from its port, and a second one means the value is
	// not a host[:port] at all. Decided HERE rather than left to net/url, because
	// there it is a GODEBUG: urlstrictcolons defaults on only for modules declaring
	// go 1.26, and the default is read from the MAIN module — so a consumer on an
	// older directive got "exchange.example::443", "a.example:44:3" and five near
	// relatives accepted, while the corpus this module publishes records them
	// refused. A rule that answers differently depending on who builds it is not the
	// rule; stating it in the code makes the committed vectors true for every
	// consumer rather than only for this repo's CI.
	//
	// Counted after the closing bracket when there is one, since the colons inside
	// an IPv6 literal are the address, not separators.
	//
	// Deliberately narrower than resolvers.wellFormedHost, which re-assembles the
	// authority and additionally requires a registered name and a 16-bit port. That
	// one is a fuller rule and lives a tier up; adopting it here would change far
	// more than the colon.
	authority := parsed.Host
	if bracket := strings.LastIndex(authority, "]"); bracket >= 0 {
		authority = authority[bracket+1:]
	}
	if strings.Count(authority, ":") > 1 {
		return nil, false, fmt.Errorf(
			"%w: %q: more than one colon after the host", ErrInvalidHost, ref)
	}
	return parsed, hadScheme, nil
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

// BareDomainPattern is the wire shape of a domain-valued field: a bare domain
// with an optional ":port", never a URL. "sub.example.com:443" passes; a value
// carrying a scheme, a path, userinfo, or a query never does.
//
// One rule, three copies, all gated. These bytes are the protovalidate pattern
// carried by the contract's recipient-addressing fields — the `exchange` field on
// each addressed request, Offer.exchange and their neighbours, NOT every field in
// ramp.proto that happens to hold a domain — so the check a client makes before
// sending and the check the wire makes on arrival cannot answer differently. The
// shared conformance vectors record the pattern beside the cases, and a guard in
// the conformance tier holds it against the descriptor; which fields belong to
// the family is pinned there too.
//
// The port is a real 1-65535 range rather than "one to five digits", which is
// why it is spelled out at this length. That distinction is load-bearing on
// exactly the values a digit count waves through: :0, :65536 and :99999 name no
// port at all, and :0443 is not a spelling of 443 but a different string that
// would compare unequal to it.
const BareDomainPattern = `^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*(:(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3}))?$`

// MaxBareDomainLen is the length bound belonging to the same rule — the
// protovalidate `string.max_len` those fields carry. Without it a client would
// accept a pattern-valid but over-length value the server then rejects, which is
// the client/server split the shared rule exists to close.
const MaxBareDomainLen = 260

var bareDomain = regexp.MustCompile(BareDomainPattern)

// IsBareDomain reports whether v is a bare domain of the shape the wire admits.
//
// This is NOT IsBareHost, and the two are deliberately kept apart because they
// answer different questions. IsBareHost asks whether a value is safe to
// concatenate into a URL — a structural question, answered by round-tripping
// the value through a URL parse, which accepts anything a host may hold.
// IsBareDomain asks whether a value is the SHAPE THE CONTRACT ADMITS, which is
// narrower: a trailing root dot, a leading or trailing hyphen, an underscore
// and a bracketed IPv6 literal are all usable hosts and none of them is a value
// the wire rule accepts. A caller vetting a value it is about to dial wants the
// first; a caller vetting a value that arrived in a message wants this one.
//
// The length is checked FIRST, so the work stays bounded on hostile input. This
// is insurance rather than a fix for a known blowup: the pattern is unambiguous —
// every repetition is anchored by a literal dot no label class can consume — so
// it cannot backtrack catastrophically, and the cost of matching it is linear in
// all three languages. Bounding that cost is still worth the one comparison it
// takes, since the Python and TypeScript ports run it on backtracking engines
// where linear work on an unbounded string is a caller's choice to make, not
// ours. Doing it in this order costs nothing in agreement, even though the three
// languages count length in different units — a value whose byte, code-point and
// UTF-16 counts disagree contains something outside ASCII, and the pattern
// refuses it whichever check runs first.
func IsBareDomain(v string) bool {
	return len(v) <= MaxBareDomainLen && bareDomain.MatchString(v)
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
// guarded transport's decision, made in one place from one flag. Its only job here
// is choosing which port counts as the default — and a side that NAMED no scheme
// borrows the other's for that purpose, rather than being assumed to mean https.
//
// That last part is load-bearing, not a nicety. Both anchors in this SDK arrive
// schemeless: a WBA directory's authority and an Offer.exchange host are bare
// host[:port] values. Assuming https for them meant an anchor of "a.example:80"
// kept its port (80 is not https's default) while the candidate
// "http://a.example:80" folded it away — the same authority reaching two answers,
// which silently un-anchored every plaintext directory that spelled :80 in full.
func HostAnchored(anchor, candidate string) (bool, error) {
	anchorURL, anchorHadScheme, err := parseRef(anchor)
	if err != nil {
		return false, fmt.Errorf("anchor host: %w", err)
	}
	candidateURL, candidateHadScheme, err := parseRef(candidate)
	if err != nil {
		return false, fmt.Errorf("candidate host: %w", err)
	}
	anchorScheme, candidateScheme := anchorURL.Scheme, candidateURL.Scheme
	if !anchorHadScheme {
		anchorScheme = candidateScheme
	}
	if !candidateHadScheme {
		candidateScheme = anchorScheme
	}
	// Compared as two values rather than one joined string. Joined, the label
	// boundary below would have to find ".a.com" at the end of "sub.a.com:8443"
	// and would refuse a subdomain for having a port — the right answer reached
	// through the wrong comparison is still the wrong comparison.
	return sameOrSubdomain(anchorURL.Hostname(), candidateURL.Hostname()) &&
		canonicalPort(anchorScheme, anchorURL.Port()) ==
			canonicalPort(candidateScheme, candidateURL.Port()), nil
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
