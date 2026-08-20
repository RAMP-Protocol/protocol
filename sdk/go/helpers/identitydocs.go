package helpers

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
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
// in order: BOTH strings must be tame — written in the coarse RFC 3986
// character set, with every percent-escape valid and no percent-encoded dot
// segment, see untameReason; the base must be https, name a host and carry no
// userinfo; the reference must be non-empty and parse; and after resolution the
// URL must be https, carry no userinfo, name a port inside 1-65535, and sit on
// the SAME ORIGIN as the base — equal hostname, equal effective port, where an
// omitted port and :443 are the same port.
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
//
// NO REFUSAL ECHOES ITS INPUT. Not just the two that name userinfo: a reference
// may carry a credential in a component this code never parses as userinfo. Go
// reads "https:u:pw@a.example/x" as an OPAQUE reference and
// "u:pw@a.example/x" as a schemeless one, and neither has a userinfo
// component at all, so both slip past the userinfo checks and reach a later
// refusal. Errors are logged; a message built with %q would put the credential
// in the log. Every refusal here is therefore a fixed string, which is also
// what the two ports already return.
func ResolveIdentityDocument(manifestURL, ref string) (string, error) {
	if why := untameReason(manifestURL); why != "" {
		// The base is checked as strictly as the reference. A tab in the base
		// PATH — not a leading one, which the scheme check already catches — is
		// accepted by two of the three SDKs and refused by the third, and every
		// answer downstream is computed from this string.
		return "", fmt.Errorf("identity document: manifest URL %s", why)
	}
	if strings.Contains(manifestURL, "#") {
		// A fragment is never sent to a server, so the URL a manifest was
		// FETCHED FROM cannot carry one. Refused rather than ignored: RFC 3986
		// 5.2.2 inherits the base's fragment for a reference that defines none,
		// and the three SDKs disagree about whether a reference of "#" defines
		// an empty fragment or none at all. No fragment on the base, no
		// question to disagree about.
		return "", errors.New("identity document: manifest URL carries a fragment")
	}
	base, err := url.Parse(manifestURL)
	if err != nil {
		return "", errors.New("identity document: manifest URL is not a URL")
	}
	if base.User != nil {
		return "", errors.New("identity document: manifest URL carries userinfo")
	}
	// url.Parse lowercases the scheme, so this compares the scheme itself and
	// not how it was spelled.
	if base.Scheme != "https" {
		return "", errors.New("identity document: manifest URL is not https")
	}
	if base.Host == "" {
		return "", errors.New("identity document: manifest URL names no host")
	}

	if strings.TrimSpace(ref) == "" {
		return "", errors.New("identity document: empty reference")
	}
	if why := untameReason(ref); why != "" {
		return "", fmt.Errorf("identity document: reference %s", why)
	}
	// A network-path reference is "//" followed by an AUTHORITY, and an empty
	// authority is no host. Spelled out because Go is the odd one here:
	// url.Parse declines to read a leading "//" as an authority marker when the
	// authority is empty and no scheme was written, so it hands back either a
	// plain path ("///x") or an entirely empty reference ("//"), and both then
	// inherit the base's host. Both other SDKs read the authority off the raw
	// string and refuse, and they are the ones matching RFC 3986.
	if strings.HasPrefix(ref, "//") {
		authority := ref[2:]
		if i := strings.IndexAny(authority, "/?#"); i >= 0 {
			authority = authority[:i]
		}
		if authority == "" {
			return "", errors.New("identity document: reference names an empty authority")
		}
	}
	// One hash at most. RFC 3986 3.5 gives a reference a single fragment that
	// runs to the end of the string, so a second hash is not a URI reference at
	// all — it is a fragment with a hash inside it, which has to be written
	// %23. The three parsers disagree about it: this one re-encodes the second
	// hash, the other two keep it. Refused rather than picked a winner for,
	// because no correct reference reaches this line.
	if strings.Count(ref, "#") > 1 {
		return "", errors.New("identity document: reference carries more than one fragment")
	}
	// RFC 3986 3.3 and 4.2: a reference with no scheme is path-noscheme, and its
	// FIRST segment may not contain a colon — ":/x" and "1:x" would otherwise be
	// ambiguous with a scheme. url.Parse refuses the first and accepts the
	// second; both other SDKs resolved both into an ordinary path segment.
	// Spelled out so the answer does not depend on which parser happens to
	// notice.
	if i := strings.IndexAny(ref, ":/?#"); i >= 0 && ref[i] == ':' && !isSchemeName(ref[:i]) {
		return "", errors.New("identity document: reference's first segment carries a colon")
	}
	refURL, err := url.Parse(ref)
	if err != nil {
		// Also does not WRAP the parse error: url.Error prints the input it
		// failed on, so %w would echo the reference by the back door.
		return "", errors.New("identity document: reference is not a URI reference")
	}
	resolved := base.ResolveReference(refURL)
	if resolved.User != nil {
		return "", errors.New("identity document: reference carries userinfo")
	}
	if resolved.Scheme != "https" {
		return "", errors.New("identity document: reference does not resolve to an https URL")
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
		return "", errors.New("identity document: manifest URL does not name a plain host")
	}
	if !IsBareDomain(resolvedHost) {
		return "", errors.New("identity document: reference does not name a plain host")
	}
	if !strings.EqualFold(baseHost, resolvedHost) {
		return "", errors.New("identity document: reference is not on the manifest's origin")
	}
	if !portIsWritable(base.Port()) {
		return "", errors.New("identity document: manifest URL names a port outside 1-65535")
	}
	if !portIsWritable(resolved.Port()) {
		return "", errors.New("identity document: reference names a port outside 1-65535")
	}
	basePort := canonicalPort(base.Scheme, base.Port())
	if basePort != canonicalPort(resolved.Scheme, resolved.Port()) {
		return "", errors.New("identity document: reference is on a different port than the manifest")
	}

	// Canonical output, assembled by hand. The authority is rebuilt from the
	// values already checked, so the same input produces the same string in
	// every SDK instead of each echoing however the manifest happened to spell
	// it. Safe only because IsBareDomain has already refused every host shape
	// that would need quoting.
	//
	// The PATH, the QUERY and the FRAGMENT are all taken from the strings the
	// author wrote, not from url.URL's serializer. RFC 3986 3.3, 3.4 and 3.5
	// define all three as substrings, and the three SDKs run three serializers
	// that disagree inside the character set untameReason admits on purpose:
	// WHATWG percent-encodes an apostrophe in a query, and this one used to
	// re-encode a second hash in a fragment.
	//
	// The path was the last component still coming from ResolveReference, and it
	// was wrong. net/url drops the empty segment when a "..' pops past the root,
	// where RFC 3986 5.2.4 keeps it: "..//x" against a base of /ramp.json is
	// //x, because step 2C removes nothing from an empty output buffer and step
	// 2E then moves the empty segment. Both ports answered //x while this oracle
	// answered /x — Python because it hand-writes 5.2.4, TypeScript because the
	// platform parser it used then happened to be right on this case. It was not
	// right on the next one, so that port now hand-writes 5.2.4 as well and all
	// three compute every component of the answer from the raw string.
	// ResolveReference is left to do only what it is still trusted for: the
	// scheme and the authority.
	path := resolvedPath(manifestURL, ref, refURL.Host != "")
	if path == "" {
		// RFC 3986 6.2.3: under a hierarchical scheme an empty path is
		// equivalent to "/", and "/" is the normalized form. The WHATWG parser
		// behind the TypeScript port already returns "/" here, so on this one
		// point that port was right and this oracle was the deviant.
		path = "/"
	}

	var out strings.Builder
	out.WriteString("https://")
	out.WriteString(strings.ToLower(resolvedHost))
	if basePort != "" {
		out.WriteString(":")
		out.WriteString(basePort)
	}
	out.WriteString(path)
	// RFC 3986 5.2.2 inherits the base's query in ONE case: the reference has an
	// empty path, no authority and no scheme, and defines no query of its own —
	// which in practice means a fragment-only reference. A reference carrying
	// any path drops the base's query even though it defines none.
	query, hasQuery := rawQueryOf(ref)
	if !hasQuery && refURL.Host == "" && !refURL.IsAbs() && refURL.Path == "" {
		// The base cannot carry a fragment, refused above, so everything after
		// its first "?" is its query.
		query, hasQuery = rawQueryOf(manifestURL)
	}
	// A query or a fragment that is DEFINED BUT EMPTY keeps its delimiter:
	// "/x?" answers "/x?" and "/x#" answers "/x#". RFC 3986 6.2.3 says
	// normalization "should not remove delimiters when their associated
	// component is empty", and names "http://example.com/?" as a URL that
	// cannot be assumed equivalent to "http://example.com/"; on the fragment it
	// says two URIs differing only by a trailing "#" "are considered different
	// regardless of the scheme". They are different request targets on the
	// wire, and this field names a document a verifier fetches. So PRESENCE
	// decides the delimiter and the contents decide nothing.
	if hasQuery {
		out.WriteString("?")
		out.WriteString(query)
	}
	// The fragment is never inherited: RFC 3986 5.2.2 takes it from the
	// reference on every branch. The base has none in any case.
	if fragment, hasFragment := rawFragmentOf(ref); hasFragment {
		out.WriteString("#")
		out.WriteString(fragment)
	}
	return out.String(), nil
}

// rawPathOf returns the path component of a URI reference or URL, exactly as
// written: the string with its fragment, query, scheme and authority removed.
func rawPathOf(s string) string {
	if i := strings.IndexByte(s, '#'); i >= 0 {
		s = s[:i]
	}
	if i := strings.IndexByte(s, '?'); i >= 0 {
		s = s[:i]
	}
	// A scheme is a colon reached before any "/", so "/a:b" keeps its colon.
	if i := strings.IndexAny(s, ":/"); i >= 0 && s[i] == ':' {
		s = s[i+1:]
	}
	if strings.HasPrefix(s, "//") {
		j := strings.IndexByte(s[2:], '/')
		if j < 0 {
			return ""
		}
		s = s[2+j:]
	}
	return s
}

// mergePath is RFC 3986 5.2.3. The base always names an authority by the time
// this runs, so an empty base path merges as if it were "/".
func mergePath(basePath, refPath string) string {
	if basePath == "" {
		return "/" + refPath
	}
	return basePath[:strings.LastIndexByte(basePath, '/')+1] + refPath
}

// removeDotSegments is RFC 3986 5.2.4, transcribed step by step.
//
// The UNDERFLOW cases are the reason this is written out rather than delegated:
// steps 2C and 2D pop the output buffer only "if any", so a "..' that pops past
// the root removes nothing and leaves whatever follows — including an empty
// segment — in place. net/url collapses that empty segment; both ports and the
// RFC keep it.
//
// Not a refusal: "../card.json" is a form the field is specified to support and
// there is a vector pinning it.
func removeDotSegments(path string) string {
	var out []string
	for path != "" {
		switch {
		case strings.HasPrefix(path, "../"):
			path = path[3:]
		case strings.HasPrefix(path, "./"):
			path = path[2:]
		case strings.HasPrefix(path, "/./"):
			path = "/" + path[3:]
		case path == "/.":
			path = "/"
		case strings.HasPrefix(path, "/../"):
			path = "/" + path[4:]
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		case path == "/..":
			path = "/"
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		case path == "." || path == "..":
			path = ""
		default:
			// Move one segment, its leading "/" included, to the output. Popping
			// one element above therefore drops a segment AND its slash, which
			// is what 5.2.4 asks for.
			i := strings.IndexByte(path, '/')
			if strings.HasPrefix(path, "/") {
				// Skip the leading slash: it belongs to THIS segment.
				if i = strings.IndexByte(path[1:], '/'); i >= 0 {
					i++
				}
			}
			if i < 0 {
				out = append(out, path)
				path = ""
			} else {
				out = append(out, path[:i])
				path = path[i:]
			}
		}
	}
	return strings.Join(out, "")
}

// resolvedPath is RFC 3986 5.2.2's path arm: pick the path, merge it if it is
// relative, then remove dot segments ONCE on whichever branch produced it.
func resolvedPath(manifestURL, ref string, refHasAuthority bool) string {
	refPath, basePath := rawPathOf(ref), rawPathOf(manifestURL)
	switch {
	case refHasAuthority, strings.HasPrefix(refPath, "/"):
		return removeDotSegments(refPath)
	case refPath == "":
		// The base path is INHERITED, and it goes through 5.2.4 like any other:
		// a base of /a/../ramp.json with a query-only reference must not keep
		// the dot segments.
		return removeDotSegments(basePath)
	default:
		return removeDotSegments(mergePath(basePath, refPath))
	}
}

// rawQueryOf returns the query a URI reference or URL DEFINES, exactly as
// written, and whether it defines one at all. RFC 3986 3.4: the query runs from
// the first "?" outside the fragment to the fragment or the end of the string.
func rawQueryOf(s string) (string, bool) {
	if i := strings.IndexByte(s, '#'); i >= 0 {
		s = s[:i]
	}
	i := strings.IndexByte(s, '?')
	if i < 0 {
		return "", false
	}
	return s[i+1:], true
}

// rawFragmentOf returns the fragment a URI reference DEFINES, exactly as
// written. RFC 3986 3.5: the fragment is everything after the first "#".
func rawFragmentOf(s string) (string, bool) {
	i := strings.IndexByte(s, '#')
	if i < 0 {
		return "", false
	}
	return s[i+1:], true
}

// uriPunctuation is every non-alphanumeric byte the coarse RFC 3986 character
// set admits: the unreserved punctuation, the gen-delims, the sub-delims, and
// the percent sign that introduces an escape.
const uriPunctuation = "-._~" + ":/?#[]@" + "!$&'()*+,;=" + "%"

// untameReason reports, as a fragment that completes "the reference <reason>",
// why a string may not be resolved — or "" when it may. It NEVER echoes the
// input, which can carry a credential.
//
// This exists because the three SDKs do not share a URL parser, and the three
// parsers disagree about everything outside this character set. Go percent-
// encodes a literal "|" and a space, the other two keep them; a control
// character makes the Python and TypeScript authority regexes read an absolute
// reference as a relative one and skip every origin check; Go refuses an
// invalid escape and the other two accept it. Reproducing three parsers byte
// for byte is not achievable, so the untame input is refused instead. A refusal
// ports cleanly; a divergent acceptance does not.
//
// DO NOT tighten this to the per-component pchar grammar. pchar would refuse
// "[" and "]", which all three SDKs currently agree on — "/a[b]c" stays literal
// in every one of them, and there is a vector pinning that. The coarse set is
// the one that lands on the right side of every measured case: it refuses "|"
// and "^", which diverge, and admits "[" and "]", which do not.
func untameReason(s string) string {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9':
			continue
		case strings.IndexByte(uriPunctuation, c) >= 0:
			// Admitted. A percent still has to introduce a real escape.
		default:
			// Every control character, every space, the backslash, and every
			// non-ASCII byte leaves through here.
			return "is not written in the RFC 3986 character set"
		}
		if c != '%' {
			continue
		}
		if i+2 >= len(s) || !isHexDigit(s[i+1]) || !isHexDigit(s[i+2]) {
			return "carries an invalid percent-escape"
		}
		// A percent-encoded dot needs its own refusal. The rule above admits a
		// percent followed by two hex digits, and remove_dot_segments only ever
		// sees a LITERAL dot, so "%2e" would survive every other check — and
		// the three SDKs split on it: Go and Python keep it, the WHATWG parser
		// behind the TypeScript port decodes it and then collapses the segment,
		// which names a DIFFERENT DOCUMENT.
		if s[i+1] == '2' && (s[i+2] == 'e' || s[i+2] == 'E') {
			return "carries a percent-encoded dot segment"
		}
	}
	return ""
}

// portIsWritable reports whether a written-out port is a decimal number a TCP
// port can actually take. An omitted port passes: the scheme's default applies.
//
// url.Parse already refuses a non-numeric port, but it accepts an out-of-range
// one — ":70000" resolves fine today — and the other two SDKs read the port off
// the raw string with no check at all, where ":abc" reaches the WHATWG parser
// and throws a raw TypeError outside the error family that port documents.
//
// The five-digit cap is not decoration. A padded ":0443" is accepted (it is a
// different string from ":443" and does not fold, which a vector pins), so the
// value cannot simply be compared as text — and without a length bound a long
// run of leading zeros overflows Go's Atoi while Python's unbounded int accepts
// it, which would be a new divergence.
func portIsWritable(port string) bool {
	if port == "" {
		return true
	}
	if len(port) > 5 {
		return false
	}
	for i := 0; i < len(port); i++ {
		if port[i] < '0' || port[i] > '9' {
			return false
		}
	}
	n, err := strconv.Atoi(port)
	return err == nil && n >= 1 && n <= 65535
}

// isSchemeName reports whether s is an RFC 3986 scheme name: one ALPHA followed
// by any run of ALPHA, DIGIT, "+", "-" and ".".
func isSchemeName(s string) bool {
	if s == "" {
		return false
	}
	if c := s[0]; !('A' <= c && c <= 'Z' || 'a' <= c && c <= 'z') {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !('A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' ||
			c == '+' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}
