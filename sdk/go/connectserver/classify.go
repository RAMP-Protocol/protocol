package connectserver

import (
	"errors"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// RejectReason is the classified cause of a verify-gate rejection — the SDK-owned
// single source of truth for WHY a request was rejected, so every consumer's
// audit log derives the same categories from the same sentinels instead of each
// re-deriving them. The four causes are the meaningful, distinct security
// outcomes an RFC 9421 gate produces.
type RejectReason int

const (
	// ReasonSignature is any signature-authenticity or freshness failure — a bad
	// signature, a missing/malformed Signature-Input, expiry, or future-created.
	// It is the default: an error the gate does not tag with a more specific
	// sentinel is a signature failure.
	ReasonSignature RejectReason = iota
	// ReasonReplay is a nonce the injected ReplayStore reported as already seen.
	ReasonReplay
	// ReasonBrokenChain is a multisig forwarding chain with a gap, reorder, or
	// missing link (a tampered relay chain).
	ReasonBrokenChain
	// ReasonHopBudget is a signature count exceeding the injected hop budget.
	ReasonHopBudget
)

// String returns the stable audit token for the reason. The tokens are stable
// wire values a consumer's audit log / dashboards key on; do not rename them.
func (r RejectReason) String() string {
	switch r {
	case ReasonReplay:
		return "replay"
	case ReasonBrokenChain:
		return "broken_chain"
	case ReasonHopBudget:
		return "hop_budget"
	case ReasonSignature:
		return "signature"
	default:
		return "signature"
	}
}

// ClassifyReject maps a verify-gate rejection error to its RejectReason, keyed
// off the gate's own sentinels (ErrReplayed here, ErrTooManyHops and
// ErrBrokenSignatureChain in helpers). It is the classifier a WithOnReject
// observer uses to audit-log the outcome without re-deriving the mapping. An
// error carrying no known sentinel classifies as ReasonSignature.
//
// One refusal the server binding answers is not an authentication outcome and has
// no value in this enum: a body past the read cap, which RejectCode answers
// resource_exhausted and this classifier reports as ReasonSignature, its default.
// A consumer auditing that refusal names it itself — reporting it as a signature
// failure would send an operator after a key rotation for a caller that sent too
// much.
func ClassifyReject(err error) RejectReason {
	switch {
	case errors.Is(err, helpers.ErrTooManyHops):
		return ReasonHopBudget
	case errors.Is(err, ErrReplayed):
		return ReasonReplay
	case errors.Is(err, helpers.ErrBrokenSignatureChain):
		return ReasonBrokenChain
	default:
		return ReasonSignature
	}
}
