// Package failure holds the rendering the SDK's two failure taxonomies share.
//
// The client's CallError and the content tier's FetchError are deliberately
// separate types over separate vocabularies — the content tier knows nothing
// about RPCs, and only one of them can decline to send. What is NOT deliberate is
// that they rendered themselves with byte-identical code, down to the reason a
// status with no name prints bare. One copy is what stops the two drifting into
// answering differently for the same failure.
//
// Internal on purpose: error prose is not a protocol concept and has no
// cross-language counterpart to mirror.
package failure

import (
	"fmt"
	"net/http"
)

// Render builds the message both failure types print.
//
// prefix names the tier that failed (the packages differ, and a reader should be
// able to tell from the first word which one produced this); op names what was
// being attempted; kind is the failure class's own token. Status, reason and
// cause are each appended only when present, so a bare classification renders as
// a bare classification rather than as a string of empty parentheses.
func Render(prefix, op, kind string, status int, reason string, cause error) string {
	msg := prefix + ": " + op + ": " + kind
	if status != 0 {
		// StatusText is empty for a code net/http does not know, and a bare
		// "(HTTP 599 )" reads like a truncation. The number alone is the honest
		// render.
		if text := http.StatusText(status); text != "" {
			msg += fmt.Sprintf(" (HTTP %d %s)", status, text)
		} else {
			msg += fmt.Sprintf(" (HTTP %d)", status)
		}
	}
	if reason != "" {
		msg += ": " + reason
	}
	if cause != nil {
		msg += ": " + cause.Error()
	}
	return msg
}

// ReasonOr returns the peer's own token when it sent one, otherwise the failure
// class the SDK assigned. The most specific machine-readable answer available,
// which is what a caller branching on a reason wants.
func ReasonOr(reason, kind string) string {
	if reason != "" {
		return reason
	}
	return kind
}

// Name renders a classification constant, falling back to "unknown" for a value
// outside the set. Both taxonomies are integer enums with a name map, and both
// must answer for a value they do not know rather than print a number.
func Name[K comparable](names map[K]string, k K) string {
	if s, ok := names[k]; ok {
		return s
	}
	return "unknown"
}

// RefuseRedirect builds the http.Client CheckRedirect both credentialed legs
// install: neither an RPC nor a bound fetch is ever legitimately redirected, and
// following one would re-sign for a target the peer chose.
//
// prefix names the tier and why names what may not be redirected, because the two
// legs decline for different reasons and a caller should read the right one. What
// is shared is the part that must NOT drift: the target is redacted rather than
// passed through url.URL.Redacted(), which masks userinfo passwords only and
// would render an attacker-chosen query into a log.
func RefuseRedirect(prefix, why string, redact func(string) string) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, _ []*http.Request) error {
		return fmt.Errorf("%s: refusing redirect to %s: %s", prefix, redact(req.URL.String()), why)
	}
}
