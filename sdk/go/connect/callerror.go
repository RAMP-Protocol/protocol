package connect

import (
	"errors"
	"fmt"
	"net/http"

	connectrpc "connectrpc.com/connect"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

// A refusal and a failure are different things, and a caller handles four
// situations differently. It cannot tell them apart from a message, so the class
// is carried as a value.
//
// The fourth is the one worth naming: WE refused to send. The routing checks that
// precede a call to an offer-derived address can decline before anything leaves
// the process, and folding that into "unreachable" — as a network timeout — hides
// the difference between "the network is bad" and "the address failed a security
// check". They call for opposite responses.

// CallErrorKind classifies why a client call did not produce an answer.
type CallErrorKind int

const (
	// CallUnknown is the zero value; it carries no classification.
	CallUnknown CallErrorKind = iota
	// CallRefused is a server that answered and said no, with a status and,
	// usually, a typed reason.
	CallRefused
	// CallUnreachable is a server that did not answer: dial failure, timeout, or
	// a redirect this SDK refused to follow.
	CallUnreachable
	// CallNotSent is THIS SDK declining to send. The address failed the
	// plain-hostname, same-host or dial-time guard, so nothing left the process
	// and no signature was exposed.
	CallNotSent
	// CallMalformed is a request that could not be built or signed faithfully.
	// Nothing left the process.
	CallMalformed
	// CallTooLarge is a response body past the configured cap.
	CallTooLarge
	// CallNotSignable is a signature or proof that could not be produced —
	// typically custody declining or timing out. Nothing left the process.
	CallNotSignable
)

var callErrorKindNames = map[CallErrorKind]string{
	CallRefused:     "refused",
	CallUnreachable: "unreachable",
	CallNotSent:     "not_sent",
	CallMalformed:   "malformed",
	CallTooLarge:    "too_large",
	CallNotSignable: "not_signable",
}

// String renders the kind for logging and for the reason a caller sees when the
// peer supplied none.
func (k CallErrorKind) String() string {
	if s, ok := callErrorKindNames[k]; ok {
		return s
	}
	return "unknown"
}

// CallError is the client's typed failure for the verbs that are not plain
// Connect round trips — the ones that vet an address before sending, or that
// speak HTTP rather than an RPC.
//
// Detail carries the typed protocol reason when there is one. On an RPC path it
// is the ErrorDetail the peer emitted; on the content path it is SYNTHESIZED
// locally from the edge's refusal token, because the edge answers a small JSON
// object rather than a protobuf. ErrorDetailFrom reads both, so a caller branches
// on one vocabulary either way.
type CallError struct {
	Kind   CallErrorKind
	Op     string
	Status int    // HTTP status when the peer answered; 0 otherwise
	Reason string // the peer's own refusal token when it sent one
	Detail *rampv1.ErrorDetail
	Err    error
}

func (e *CallError) Error() string {
	msg := "connect: " + e.Op + ": " + e.Kind.String()
	if e.Status != 0 {
		if text := http.StatusText(e.Status); text != "" {
			msg += fmt.Sprintf(" (HTTP %d %s)", e.Status, text)
		} else {
			msg += fmt.Sprintf(" (HTTP %d)", e.Status)
		}
	}
	if e.Reason != "" {
		msg += ": " + e.Reason
	}
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

// Unwrap keeps the cause matchable, so errors.Is still reaches a custody or
// resolver sentinel after the failure has been classified here.
func (e *CallError) Unwrap() error { return e.Err }

// ReasonOf returns the most specific machine-readable reason available: the
// peer's own token when it sent one, otherwise the failure class.
func (e *CallError) ReasonOf() string {
	if e.Reason != "" {
		return e.Reason
	}
	return e.Kind.String()
}

// notSent builds the refusal for an address that failed a routing check. It is
// its own constructor because every such refusal must state which check declined
// and must never carry a status: nothing was sent, so there is nothing to report
// a status for.
func notSent(op string, err error) *CallError {
	return &CallError{Kind: CallNotSent, Op: op, Err: err}
}

// malformed builds the refusal for a request that could not be assembled.
func malformed(op string, err error) *CallError {
	return &CallError{Kind: CallMalformed, Op: op, Err: err}
}

// asCallError extracts a *CallError from err's chain.
func asCallError(err error) (*CallError, bool) {
	var cerr *CallError
	if errors.As(err, &cerr) {
		return cerr, true
	}
	return nil, false
}

// sendError classifies a failure the transport returned AFTER the routing checks
// passed, so one verb answers with one error type however it failed.
//
// Without this a single method yields a *CallError when it declines to send and a
// bare transport error when the peer refuses, which makes errors.As(&CallError{})
// a coin flip on the very type callers are told to branch on.
//
// The Connect error is kept in the chain with %w, so errors.As still reaches it
// and ErrorDetailFrom still finds the typed detail the peer attached.
func sendError(op string, err error) error {
	out := &CallError{Kind: CallUnreachable, Op: op, Err: err}
	var cerr *connectrpc.Error
	if !errors.As(err, &cerr) {
		return out
	}
	// A peer that answered is a refusal, whatever it said. Unavailable and the
	// deadline codes are the two Connect reports a transport failure as, so they
	// stay unreachable — the distinction a caller needs is "it said no" versus "it
	// never answered", and only the first is worth surfacing a reason for.
	switch cerr.Code() {
	case connectrpc.CodeUnavailable, connectrpc.CodeDeadlineExceeded:
		out.Kind = CallUnreachable
	case connectrpc.CodeResourceExhausted:
		// The read cap, seen from this side: the peer's answer was larger than the
		// client agreed to read.
		out.Kind = CallTooLarge
	default:
		out.Kind = CallRefused
	}
	out.Reason = cerr.Code().String()
	if detail, ok := errorDetailFromConnect(cerr); ok {
		out.Detail = detail
	}
	return out
}
