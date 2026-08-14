package helpers

import (
	"errors"
	"fmt"
	"strings"
)

// The audience check: does a request that arrived here actually name this
// Exchange as its recipient?
//
// Addressed requests carry the recipient's bare domain in a body field. The RFC
// 9421 signature does not already establish the recipient: it proves the sender
// signed THE URL IT DIALLED, not that the URL was the right one. That dial target
// is resolved from a fetched, cached /.well-known/ramp.json, so a poisoned or
// stale resolution redirects the request while every signature still verifies.
// The field states whom the sender MEANT, independently of that resolution, and
// the genuine recipient refuses a request that names someone else.
//
// The field is stamped by whoever authors each request — the agent on the
// requests it signs, a Broker on the legs it authors as sender. It is a statement
// BY that sender, not tamper-evidence against it. For transactions the binding
// audience statement is per item — Offer.exchange inside the Exchange-signed
// offer.
//
// It also backstops cross-recipient replay, and for THIS SDK that is not a
// secondary benefit. A recipient that rebuilds @target-uri from its own
// configured identity refuses a replayed capture at signature verification, and
// needs no help here. This SDK rebuilds it from the ARRIVING request instead —
// see reconstructTargetURI, which falls back to the Host header, and the server
// binding takes no expected-host option — so a capture signed for one Exchange
// and replayed at another with a forged Host verifies. This check is what
// refuses it — once a recipient calls it. Nothing in this SDK calls it for you;
// wiring it into a server is the caller's, and it is the reason to.
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
// self is this Exchange's own bare domain — the domain it publishes as its
// IDENTITY, which is the value it stamps into the offers it issues. It is not
// the host the process happens to listen on, and the two are allowed to differ:
// an Exchange at exchange.example may serve its API from api.exchange.example,
// so an operator who configures this from the listening host would refuse every
// request that named them correctly.
//
// claimed holds the recipient values
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
// read as https throughout this SDK. Port 80 is NOT folded here: it is not the
// default of the scheme a bare domain implies. Elsewhere in the package
// canonicalPort does fold it, because there the caller supplies a scheme and 80
// is http's default — a difference between two comparisons, not an inconsistency
// between them.
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
//
// This is the second place in the package that folds a default port; canonicalPort
// is the other, and the two MUST keep agreeing that 443 written out and 443 left
// off are one port. They are not merged deliberately: canonicalPort answers the
// question scheme-relatively for values that may be full URLs, which is why it
// takes a scheme at all, while both operands here are already regex-gated bare
// domains that name no scheme. Reusing it would mean passing a scheme this path
// does not have and cannot learn — a literal "https" invented at the call site to
// satisfy a parameter, which is a worse dependency than the six lines below. On
// the schemeless values this one sees, the two agree exactly, 443 folded and 80
// not, so the split costs no behaviour.
//
// The repo has been bitten by a duplicated host predicate before, so the cost of
// the split is this comment and two separate test surfaces: the shared vectors pin
// the fold here, and TestHostAnchored_ComparesThePort pins canonicalPort's. See
// "The audience match is exact; the endpoint rule is not" in
// docs/design-history.md for why the two rules differ at all.
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
