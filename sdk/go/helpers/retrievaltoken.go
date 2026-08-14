package helpers

import (
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

// The delivery edge answers a refused fetch with a small JSON body carrying its
// own refusal token — a string vocabulary, because the edge is a code-capable
// worker with no protobuf runtime. RetrievalAuthFailureReason is the typed
// counterpart, and ramp.proto records the token each value stands for.
//
// Mapping the token back onto the enum is what lets a fetch refusal reach a
// caller through the SAME typed vocabulary an RPC refusal does, instead of a
// string the caller has to substring-match.

// retrievalAuthFailureTokens maps the edge's refusal token to its typed reason.
//
// Two tokens the edge can emit are deliberately ABSENT rather than guessed at:
//
//   - "missing_sig" is emitted by BOTH checkers — the signed-URL check (no sig
//     query parameter) and the proof check (no Signature header) — and the enum
//     has a distinct value for each. The body does not say which ran, so mapping
//     it would attribute the failure to a check that may not have fired.
//   - the edge's parse-level tokens (a malformed signature input, an unsupported
//     alg, a wrong covered set, a created too far in the future) have no enum
//     value at all.
//
// An unmapped token still reaches the caller as the raw refusal string; only the
// typed reason is withheld, which is the honest outcome when the wire cannot say
// which failure occurred.
var retrievalAuthFailureTokens = map[string]rampv1.RetrievalAuthFailureReason{
	// Signed-URL checks.
	"expired":            rampv1.RetrievalAuthFailureReason_RETRIEVAL_AUTH_FAILURE_REASON_URL_EXPIRED,
	"missing_exp":        rampv1.RetrievalAuthFailureReason_RETRIEVAL_AUTH_FAILURE_REASON_URL_EXPIRY_MISSING,
	"signature_mismatch": rampv1.RetrievalAuthFailureReason_RETRIEVAL_AUTH_FAILURE_REASON_URL_SIGNATURE_MISMATCH,
	// Proof-of-possession checks.
	"missing_agent_key":   rampv1.RetrievalAuthFailureReason_RETRIEVAL_AUTH_FAILURE_REASON_AGENT_KEY_MISSING,
	"keyid_mismatch":      rampv1.RetrievalAuthFailureReason_RETRIEVAL_AUTH_FAILURE_REASON_KEYID_MISMATCH,
	"thumbprint_mismatch": rampv1.RetrievalAuthFailureReason_RETRIEVAL_AUTH_FAILURE_REASON_THUMBPRINT_MISMATCH,
	"pop_missing_created": rampv1.RetrievalAuthFailureReason_RETRIEVAL_AUTH_FAILURE_REASON_PROOF_CREATED_MISSING,
	"pop_missing_exp":     rampv1.RetrievalAuthFailureReason_RETRIEVAL_AUTH_FAILURE_REASON_PROOF_EXPIRY_MISSING,
	"pop_expired":         rampv1.RetrievalAuthFailureReason_RETRIEVAL_AUTH_FAILURE_REASON_PROOF_EXPIRED,
	"pop_sig_invalid":     rampv1.RetrievalAuthFailureReason_RETRIEVAL_AUTH_FAILURE_REASON_PROOF_SIGNATURE_INVALID,
}

// RetrievalAuthFailureReasonFromToken resolves a delivery edge's refusal token to
// its typed RetrievalAuthFailureReason. The second result is false for a token
// this SDK does not recognise or cannot attribute unambiguously — the caller then
// falls back to its own failure class, which it owns, rather than promoting a
// value the edge did not actually state.
//
// Fail-closed by construction: the token arrives in a body written by the host
// the fetch just went to, so an unrecognised value is never surfaced as a typed
// protocol reason.
func RetrievalAuthFailureReasonFromToken(token string) (rampv1.RetrievalAuthFailureReason, bool) {
	reason, ok := retrievalAuthFailureTokens[token]
	return reason, ok
}
