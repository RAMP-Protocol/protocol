package connect

import (
	"errors"

	connectrpc "connectrpc.com/connect"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/internal/failure"
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
func (k CallErrorKind) String() string { return failure.Name(callErrorKindNames, k) }

// CallError is the client's typed failure for the verbs that are not plain
// Connect round trips — the ones that vet an address before sending, or that
// speak HTTP rather than an RPC.
//
// Detail carries the typed protocol reason when there is one. On an RPC path it
// is the ErrorDetail the peer emitted; on the content path it is SYNTHESIZED
// locally from the edge's refusal token, because the edge answers a small JSON
// object rather than a protobuf; and on a registration refused by the client's own
// pre-check it is synthesized from the schema failures that pre-check found, which
// are the failures the Exchange would have named had the request been sent.
// ErrorDetailFrom reads all three, so a caller branches on one vocabulary whichever
// side declined.
type CallError struct {
	Kind   CallErrorKind
	Op     string
	Status int    // HTTP status when the peer answered; 0 otherwise
	Reason string // the peer's own refusal token when it sent one
	Detail *rampv1.ErrorDetail
	// PeerMessage is the developer message the peer put on its TYPED reason, when
	// it sent one. Empty otherwise.
	//
	// It is a field rather than something to recover from Error()'s rendering
	// because a reason rendered into prose cannot be read back out without
	// parsing it, and a layer that has to do that is a layer that will get it
	// wrong. It sits BESIDE Reason rather than in it: Reason is the peer's
	// machine token, and putting prose there was a mistake this SDK has already
	// made once and reverted.
	//
	// It is deliberately NOT filled from the transport envelope when there is no
	// typed detail. An answer that did not come from a RAMP service — a draining
	// load balancer, a proxy's own page — carries no message of its own, and the
	// text a transport synthesizes for it is that transport's, not the peer's:
	// connect-go writes "502 Bad Gateway" where a fetch-based client writes
	// nothing, so carrying it would make this field's value a property of the
	// language rather than of the answer. That text is still reachable through
	// the cause, where it reads as what it is.
	//
	// It is equally NOT filled from a detail this SDK BUILT ITSELF — the content
	// leg's refusal sentence, or the registration pre-check's. Those details carry
	// a typed reason, so the envelope rule above would not stop them; what stops
	// them is that the sentence around the reason is ours. A field that exists so a
	// layer can attribute prose to a remote party cannot sometimes hold our words.
	// In Go only the decode site fills this, so the rule holds structurally; the
	// two ports state it where their constructors could otherwise derive it.
	//
	// NON-AUTHORITATIVE, and the contract says so of the field it comes from.
	// Branch on Kind or on the typed reason, never on this text. It is also
	// UNBOUNDED — the contract calls it an easy existence oracle and places the
	// no-secrets duty on the server, so a consumer that renders it to a log line
	// or to an agent bounds it there, where the audience is known. This SDK does
	// not bound it, for the same reason it does not bound Detail.Message:
	// truncating a peer's only account of why a call failed is a decision that
	// belongs to whoever displays it.
	PeerMessage string
	Err         error
}

func (e *CallError) Error() string {
	return failure.Render("connect", e.Op, e.Kind.String(), e.Status, e.Reason, e.Err)
}

// Unwrap keeps the cause matchable, so errors.Is still reaches a custody or
// resolver sentinel after the failure has been classified here.
func (e *CallError) Unwrap() error { return e.Err }

// ReasonOf returns the most specific machine-readable reason available: the
// peer's own token when it sent one, otherwise the failure class.
func (e *CallError) ReasonOf() string { return failure.ReasonOr(e.Reason, e.Kind.String()) }

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
	// A peer that answered is a refusal, whatever it said. The distinction a caller
	// needs is "it said no" versus "it never answered", and only the first is worth
	// surfacing a reason for.
	//
	// Three codes land on the second side. Unavailable is the transport failure
	// proper. The two context codes are LOCAL outcomes wearing a Connect code:
	// connect-go stamps CodeDeadlineExceeded on a context that ran out and
	// CodeCanceled on one the caller cancelled, so neither means the peer reached a
	// verdict. Classifying a caller's own cancellation as CallRefused would tell it
	// the Exchange declined a call the Exchange may never have seen.
	switch cerr.Code() {
	case connectrpc.CodeUnavailable,
		connectrpc.CodeDeadlineExceeded,
		connectrpc.CodeCanceled:
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
		out.PeerMessage = detail.GetMessage()
	}
	return out
}
