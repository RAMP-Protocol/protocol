package helpers

import (
	"errors"
	"fmt"
	"strings"
)

// The audience check: does a request that arrived here actually name this
// Exchange as its recipient?
//
// Addressed requests carry the recipient's bare domain in a body field. That
// field is the only agent-authenticated statement of intended recipient that
// survives a relay: each hop signs its own @target-uri, so on a Broker path the
// agent's signature covers the BROKER's URL and the Exchange never receives an
// agent signature over its own. The body field rides inside the agent's
// content-digest instead, which a relaying Broker cannot alter without breaking
// the inner signature. It also protects a direct hop whose dial target came
// from a fetched manifest: the request signature covers the URL that was
// dialed, while this field states whom the sender MEANT.
//
// Pure string work over a value the caller already holds — no IO, no state, and
// no lookup — which is why it sits in the IO-free tier and can run before any
// database is touched. That ordering is the point: an opaque, Exchange-scoped
// identifier elsewhere in the message cannot stand in for this check, because
// verifying one requires the very lookup the check is meant to precede.

// ErrAudienceIdentity signals that the recipient's OWN configured identity is
// unusable, so no audience check could run. It is a fault in this deployment,
// never in the request — a caller mapping it onto a status code owes the peer an
// internal error, not a rejection.
var ErrAudienceIdentity = errors.New("helpers: configured Exchange identity is not a bare domain")

// AudienceVerdict is the outcome of checking a request's claimed recipient
// against this Exchange's own identity.
type AudienceVerdict int

const (
	// AudienceNoVerdict is the zero value: the check did not run. It is returned
	// only alongside a non-nil error, and it is first so that a caller who
	// ignores that error reads "no answer" rather than an acceptance.
	AudienceNoVerdict AudienceVerdict = iota

	// AudienceAccepted means every claimed value names this Exchange.
	AudienceAccepted

	// AudienceEmpty means the request claimed no recipient at all — an empty
	// value, or no values. Treating that as "the caller did not claim one, so
	// let it pass" is what makes the check opt-in for whoever is sending, which
	// is the posture this primitive exists to end.
	AudienceEmpty

	// AudienceMalformed means a claimed value is not a bare domain. It is
	// separate from a mismatch because the two say different things to whoever
	// reads the rejection: one is a value in the wrong shape, the other a
	// well-formed value naming somebody else.
	AudienceMalformed

	// AudienceMismatch means a claimed value is a bare domain that names a
	// different Exchange.
	AudienceMismatch
)

// String renders the verdict as the stable token the shared conformance vectors
// record, so a port asserts against the same word rather than a number whose
// meaning depends on declaration order.
func (v AudienceVerdict) String() string {
	switch v {
	case AudienceNoVerdict:
		return "no_verdict"
	case AudienceAccepted:
		return "accepted"
	case AudienceEmpty:
		return "empty"
	case AudienceMalformed:
		return "malformed"
	case AudienceMismatch:
		return "mismatch"
	default:
		return fmt.Sprintf("AudienceVerdict(%d)", int(v))
	}
}

// CheckAudience reports whether every claimed recipient names this Exchange.
//
// self is this Exchange's own bare domain. claimed holds the recipient values
// the request carries — ONE for a message with a single `exchange` field, MANY
// for a message whose audience lives per item (a TransactionRequest states it
// once per item, in each item's signed offer). Every value must name this
// Exchange; the first that does not decides the verdict, and a request carrying
// no values at all is refused rather than waved through.
//
// The comparison is EXACT: a subdomain of this Exchange is a different party and
// does not name it. That is narrower than the endpoint rule, which does allow a
// manifest to advertise its endpoint on a subdomain of the host that served it —
// there the question is which addresses one Exchange may be reached at, here it
// is who the Exchange IS.
//
// Two spellings of the same identity still match: case is folded, and a port of
// 443 written out is the same as leaving it off, since a schemeless domain is
// read as https throughout this SDK. Port 80 is not folded, for the same reason
// it is not folded anywhere else here — it is not the default of the scheme a
// bare domain implies.
//
// The returned error is non-nil only when self is unusable, and it always
// carries AudienceNoVerdict. Everything a request can get wrong is a verdict,
// never an error, so a caller can map the two onto different status codes
// without inspecting the text.
func CheckAudience(self string, claimed ...string) (AudienceVerdict, error) {
	if !IsBareDomain(self) {
		return AudienceNoVerdict, fmt.Errorf("%w: %q", ErrAudienceIdentity, self)
	}
	if len(claimed) == 0 {
		return AudienceEmpty, nil
	}
	want := normalizeDomain(self)
	for _, c := range claimed {
		switch {
		case c == "":
			return AudienceEmpty, nil
		case !IsBareDomain(c):
			return AudienceMalformed, nil
		case normalizeDomain(c) != want:
			return AudienceMismatch, nil
		}
	}
	return AudienceAccepted, nil
}

// normalizeDomain renders the two spellings of one identity as one string. It
// runs only on values IsBareDomain has already accepted, so the input is ASCII
// and holds at most one colon followed by digits — which is what lets it split
// on that colon rather than parse a URL, and is why the ports can reproduce it
// exactly.
func normalizeDomain(v string) string {
	host, port := v, ""
	if i := strings.LastIndex(v, ":"); i >= 0 {
		host, port = v[:i], v[i+1:]
	}
	host = strings.ToLower(host)
	// A schemeless domain is read as https everywhere in this SDK, so 443 spelled
	// out and 443 left implicit are the same port. Any other port is kept, 80
	// included: folding it would be reading a scheme into a value that names none.
	if port == "" || port == "443" {
		return host
	}
	return host + ":" + port
}
