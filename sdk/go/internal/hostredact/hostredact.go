// Package hostredact keeps a credential out of a message built from a host
// reference.
//
// Three tiers refuse such references and each names the value it refused —
// helpers' host predicates, the endpoint rule, and the routing check that precedes
// a signed call. A reference carrying userinfo reaches all three, so redacting in
// one of them leaves the other two echoing, and a copy per tier is the shape this
// repo has already watched drift. Internal because it is message hygiene rather
// than a rule: nothing decides a verdict on what it returns.
package hostredact

import (
	"regexp"
	"strings"
)

// A scheme, and only at the front — the same rule the host parse applies when it
// decides whether "://" is a separator at all.
var schemeAtFront = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*://`)

// Userinfo replaces any userinfo in ref with a marker, so a message built from it
// cannot carry a credential.
//
// Deliberately conservative, and deliberately NOT the rule: it runs on strings a
// parse has already refused, so it cannot assume they are well formed, and
// over-redacting a message costs nothing while under-redacting is the bug. It
// redacts at the FIRST reading in authorityStarts that finds an "@" rather than
// deciding on one reading — a credential any reader could see is one that must not
// reach a log. It looks only for an "@" in what could be the authority, which is why
// an "@" in a path is left alone.
//
// The whole userinfo goes, not just the password. url.URL.Redacted keeps the
// username, which is right for a URL the caller owns — but these values arrive in a
// third-party manifest or an offer, where the username is as much the operator's
// secret as the password is.
func Userinfo(ref string) string {
	for _, start := range authorityStarts(ref) {
		authority, beyond := splitAuthority(ref[start:])
		if at := strings.LastIndex(authority, "@"); at >= 0 {
			return ref[:start] + "[redacted]" + authority[at:] + beyond
		}
	}
	return ref
}

// authorityStarts returns every index at which an authority could plausibly begin,
// most authoritative first, de-duplicated.
//
// A reference that has been REFUSED has no one true reading — that is what being
// refused means — so the redaction cannot pick a single one and be safe. Each of
// these is a reading something could take: past a valid scheme at the front, which
// is how the parse reads it; index 2 behind a bare "//", which opens an authority
// while naming no scheme and carries no "://" anywhere; index 0, a schemeless host
// or user:pw@host; and past the first "://" in the string, which is not a scheme
// separator to this parse but is what a laxer reader downstream may take it for.
//
// Taking only the first trades one leak for another: reading solely by search lets a
// path segment supply the start, and reading solely by the parse's rule leaves
// "1https://u:pw@a.example/" untouched, because a scheme may not begin with a digit.
func authorityStarts(ref string) []int {
	starts := make([]int, 0, 4)
	add := func(i int) {
		for _, seen := range starts {
			if seen == i {
				return
			}
		}
		starts = append(starts, i)
	}
	if m := schemeAtFront.FindString(ref); m != "" {
		add(len(m))
	}
	if strings.HasPrefix(ref, "//") {
		add(2)
	}
	add(0)
	if sep := strings.Index(ref, "://"); sep >= 0 {
		add(sep + 3)
	}
	return starts
}

// splitAuthority splits what follows an authority's start into the authority and
// everything after it. The authority ends at the first delimiter that starts a path,
// query or fragment — the three things a reference can carry beyond it.
func splitAuthority(rest string) (authority, beyond string) {
	if end := strings.IndexAny(rest, "/?#"); end >= 0 {
		return rest[:end], rest[end:]
	}
	return rest, ""
}
