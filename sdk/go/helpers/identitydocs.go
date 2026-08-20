package helpers

import (
	"errors"
	"fmt"
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
	// THE MANIFEST URL IS VETTED FIRST, on its own and to completion. That is
	// what the IdentityDocuments proto comment promises and what both ports do,
	// and this oracle used to contradict it: the base's host shape and port
	// range were checked only after the reference had been parsed, so a base
	// with an underscore in its host was reported as "the reference does not
	// resolve to an https URL".
	if uriSchemeOf(manifestURL) != "https" {
		return "", errors.New("identity document: manifest URL is not https")
	}
	baseAuthority, baseHasAuthority := uriAuthorityOf(manifestURL)
	if !baseHasAuthority {
		return "", errors.New("identity document: manifest URL names no authority")
	}
	baseHost, basePort, err := vetAuthority(baseAuthority, "manifest URL")
	if err != nil {
		return "", err
	}

	if strings.TrimSpace(ref) == "" {
		return "", errors.New("identity document: empty reference")
	}
	if why := untameReason(ref); why != "" {
		return "", fmt.Errorf("identity document: reference %s", why)
	}
	// One hash at most. RFC 3986 3.5 gives a reference a single fragment that
	// runs to the end of the string, so a second hash is not a URI reference at
	// all — it is a fragment with a hash inside it, which has to be written
	// %23. The three parsers disagree about it: this one used to re-encode the
	// second hash, the other two keep it. Refused rather than picked a winner
	// for, because no correct reference reaches this line.
	if strings.Count(ref, "#") > 1 {
		return "", errors.New("identity document: reference carries more than one fragment")
	}
	refScheme := uriSchemeOf(ref)
	// RFC 3986 3.3 and 4.2: a reference with no scheme is path-noscheme, and its
	// FIRST segment may not contain a colon — ":/x" and "1:x" would otherwise
	// be ambiguous with a scheme.
	if refScheme == "" {
		if i := strings.IndexAny(ref, ":/?#"); i >= 0 && ref[i] == ':' {
			return "", errors.New("identity document: reference's first segment carries a colon")
		}
	}
	if refScheme != "" && refScheme != "https" {
		return "", errors.New("identity document: reference does not resolve to an https URL")
	}
	refAuthority, refHasAuthority := uriAuthorityOf(ref)
	if refScheme != "" && !refHasAuthority {
		// "https:/dir" — a scheme with no "//" names no authority, so it
		// resolves to a URL with no host rather than borrowing the base's.
		return "", errors.New("identity document: reference names no authority")
	}
	if refHasAuthority {
		refHost, refPort, err := vetAuthority(refAuthority, "reference")
		if err != nil {
			return "", err
		}
		// Shape BEFORE case folding, the ordering audience.go already fixes:
		// U+212A KELVIN SIGN case-folds to a plain ASCII "k", so EqualFold
		// reports a host spelled with it and a plain ASCII host as the SAME
		// name. vetAuthority has run IsBareDomain on both by the time this
		// compares them.
		if !strings.EqualFold(refHost, baseHost) {
			return "", errors.New("identity document: reference is not on the manifest's origin")
		}
		if refPort != basePort {
			return "", errors.New("identity document: reference is on a different port than the manifest")
		}
	}

	// EVERY component of the answer is now read from the strings the author
	// wrote. RFC 3986 3.2, 3.3, 3.4 and 3.5 define the authority, the path, the
	// query and the fragment as substrings, and the three SDKs ran three
	// serializers that disagree inside the character set untameReason admits on
	// purpose: WHATWG percent-encodes an apostrophe in a query, and this one
	// used to re-encode a second hash in a fragment.
	//
	// The AUTHORITY was the last one still coming from a parser, and it was
	// wrong in a way the corpus could not see. net/url reads it with Hostname()
	// and Port(), which split on the LAST colon: "a.example:8443:9" put
	// "a.example:8443" in the host half, where IsBareDomain accepts it — its
	// pattern admits an optional port and cannot tell a host from one that
	// already carries a port. Every origin check downstream then ran against the
	// wrong hostname. That input was refused only because the parser itself
	// returned an error, and that error is new in Go 1.26: a consumer whose main
	// module declares go 1.25 gets the lenient parse and the accepting answer,
	// out of this same source. An oracle that emits the corpus two other
	// languages replay cannot have a verdict that depends on the consumer's
	// toolchain.
	path := resolvedPath(manifestURL, ref, refHasAuthority)
	if path == "" {
		// RFC 3986 6.2.3: under a hierarchical scheme an empty path is
		// equivalent to "/", and "/" is the normalized form. The WHATWG parser
		// behind the TypeScript port already returns "/" here, so on this one
		// point that port was right and this oracle was the deviant.
		path = "/"
	}

	// Canonical output, assembled by hand. The authority is rebuilt from the
	// values already checked, so the same input produces the same string in
	// every SDK instead of each echoing however the manifest happened to spell
	// it. Safe only because IsBareDomain has already refused every host shape
	// that would need quoting.
	//
	// The host written is the BASE's. When the reference names one too they are
	// EqualFold-equal by this point, so the two spellings of one identity
	// collapse to the one the manifest was fetched from.
	var out strings.Builder
	out.WriteString("https://")
	out.WriteString(strings.ToLower(baseHost))
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
	if !hasQuery && !refHasAuthority && refScheme == "" && rawPathOf(ref) == "" {
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

// uriSchemeOf returns the scheme of a URI reference, lowercased, or "" when it
// names none. RFC 3986 3.1: an ALPHA followed by ALPHA / DIGIT / "+" / "-" /
// "." and terminated by a colon. A colon reached after a "/" belongs to a path
// segment, and isSchemeName refuses the prefix in that case.
func uriSchemeOf(s string) string {
	i := strings.IndexByte(s, ':')
	if i <= 0 || !isSchemeName(s[:i]) {
		return ""
	}
	return strings.ToLower(s[:i])
}

// uriAuthorityOf returns the authority substring of a URI reference or URL, and
// whether one is PRESENT. RFC 3986 3.2: the run after "//" up to the first "/",
// "?" or "#". An authority can be present and empty — "//" alone, or "///x" --
// which is why presence is a separate answer rather than a test for "".
func uriAuthorityOf(s string) (string, bool) {
	if scheme := uriSchemeOf(s); scheme != "" {
		s = s[len(scheme)+1:]
	}
	if !strings.HasPrefix(s, "//") {
		return "", false
	}
	s = s[2:]
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	return s, true
}

// splitHostPort splits "host[:port]" on the FIRST colon; no colon means no port.
//
// The first colon, not the last, because the caller cannot check what this hands
// back. Splitting "a.example:8443:9" on the LAST colon gives the host half
// "a.example:8443", and IsBareDomain accepts that — its pattern admits an
// optional port, so it cannot tell a host from a host that already carries one.
// Splitting on the FIRST colon puts everything after it in the port half, where
// portIsWritable refuses it. Values that reached here through IsBareDomain hold
// at most one colon, so the two rules agree on them.
func splitHostPort(v string) (string, string) {
	if i := strings.IndexByte(v, ':'); i >= 0 {
		return v[:i], v[i+1:]
	}
	return v, ""
}

// vetAuthority checks one authority and returns its host and its folded port.
//
// Written once and called for both the base and the reference. The two used to
// hold the same checks inline, and the split rule they share is exactly the kind
// of thing that gets fixed in one copy and not the other. label names which of
// the two strings is at fault and is the only difference between the two calls.
//
// Refuses userinfo without echoing the value, since that is where a credential
// would be.
func vetAuthority(authority, label string) (string, string, error) {
	if strings.Contains(authority, "@") {
		return "", "", fmt.Errorf("identity document: %s carries userinfo", label)
	}
	host, port := splitHostPort(authority)
	if !IsBareDomain(host) {
		return "", "", fmt.Errorf("identity document: %s does not name a plain host", label)
	}
	if !portIsWritable(port) {
		return "", "", fmt.Errorf("identity document: %s names a port outside 1-65535", label)
	}
	return host, canonicalPort("https", port), nil
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
//
// Walks the string with an INDEX rather than reassigning the remainder. The RFC
// states the algorithm as "remove the prefix and repeat", and two of its four
// removal steps have to leave a slash behind — transcribing those literally
// gives `path = "/" + path[3:]`, which allocates and copies the whole remainder
// every time. The SLICE is free; the CONCATENATION is not. Only a dot segment
// reaches those branches, so the cost hid behind the input: with the literal
// transcription a reference of "/." repeated to 512 KiB took 6.6s here, while
// the same length of "/a" took 19ms. The reference is a member of a
// manifest fetched from a third party and carries no maximum length, so the
// input is reachable. The branches below are the RFC's, unchanged; only the way
// the prefix is dropped is different.
func removeDotSegments(path string) string {
	var out []string
	i, n := 0, len(path)
	for i < n {
		rest := n - i
		switch {
		case strings.HasPrefix(path[i:], "../"):
			i += 3
		case strings.HasPrefix(path[i:], "./"):
			i += 2
		case strings.HasPrefix(path[i:], "/./"):
			// Drop the dot and ONE slash; the other starts the next segment.
			i += 2
		case rest == 2 && strings.HasPrefix(path[i:], "/."):
			out = append(out, "/")
			i = n
		case strings.HasPrefix(path[i:], "/../"):
			i += 3
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		case rest == 3 && strings.HasPrefix(path[i:], "/.."):
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
			out = append(out, "/")
			i = n
		case rest == 1 && path[i] == '.', rest == 2 && strings.HasPrefix(path[i:], ".."):
			i = n
		default:
			// Move one segment, its leading "/" included, to the output. Popping
			// one element above therefore drops a segment AND its slash, which
			// is what 5.2.4 asks for.
			j := strings.IndexByte(path[i:], '/')
			if path[i] == '/' {
				// Skip the leading slash: it belongs to THIS segment.
				if j = strings.IndexByte(path[i+1:], '/'); j >= 0 {
					j++
				}
			}
			if j < 0 {
				out = append(out, path[i:])
				i = n
			} else {
				out = append(out, path[i:i+j])
				i += j
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
// Nothing upstream checks this any more. All three SDKs read the authority off
// the raw string, so ":abc" and ":70000" both arrive here unexamined and this is
// the only place either is refused. It used to sit behind net/url in this
// language, which refused a non-numeric port and accepted an out-of-range one.
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
