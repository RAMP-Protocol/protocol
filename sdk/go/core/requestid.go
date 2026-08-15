package core

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
)

// RequestIDHeader is the correlation header the request-id middleware/interceptor
// mints and propagates on every RPC (the client and server faces share the name).
const RequestIDHeader = "X-Request-ID"

// RequestIDFunc mints a fresh request id when a call carries none. The default is
// a random 128-bit hex token; an application overrides it (e.g. to reuse a trace
// id) via the client/server WithRequestIDFunc option. It is transport-neutral —
// the Connect binding wraps it in a connect.Interceptor, the http-seam server face
// wraps it in RequestIDMiddleware, and both share this one mint type.
type RequestIDFunc func() string

// DefaultRequestID returns a random 128-bit hex request id. It is the default mint
// both faces fall back to when no RequestIDFunc is injected.
func DefaultRequestID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "ramp-req"
	}
	return hex.EncodeToString(b)
}

// maxRequestIDLen is the admin plane's ceiling on a persisted correlation id.
// Counted in bytes here and in CHARACTERS by the wire rule, which is the same
// number for any value this function accepts: every character in the allowed
// range is one ASCII byte.
const maxRequestIDLen = 255

// ValidRequestID reports whether s is a correlation id the RAMP admin plane can
// carry — 1 to 255 printable ASCII characters, the `^[!-~]+$` rule on
// ramp.admin.v1.RequestCorrelation.request_id.
//
// The check exists because that field sits inside a REQUIRED message inside a
// REQUIRED field of GetTransactionEvidenceResponse. A single stored value
// outside this range does not degrade the response, it INVALIDATES it — so a
// caller who gets a hostile header persisted permanently breaks the forensic
// row for their own transaction. Guarding the write path is what keeps that
// impossible.
//
// Exported because the same test is needed twice: here on the way in, and again
// by anything reading a stored correlation back, since rows written before a
// server had this check may hold a value it would refuse today.
//
// A server MAY be stricter — the reference Exchange accepts only
// `^[A-Za-z0-9._-]{1,128}$`, which avoids every log-injection metacharacter.
// This function deliberately is not, because the SDK should not refuse values
// the contract can represent; narrowing is a deployment's decision to make on
// top of it.
func ValidRequestID(s string) bool {
	if len(s) == 0 || len(s) > maxRequestIDLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '!' || s[i] > '~' {
			return false
		}
	}
	return true
}

// RequestID is the correlation id a server settled on for one request, with the
// provenance an evidence writer has to persist beside it.
type RequestID struct {
	// Value always satisfies ValidRequestID.
	Value string
	// Derived reports that the SERVER produced this value rather than a caller:
	// the header was absent, or it was present and did not conform. It maps
	// directly to the evidence store's request_id_minted column and to
	// ramp.admin.v1.RequestCorrelation.minted, both of which mean
	// "server-derived" rather than "the header was absent". False means a
	// caller chose these characters, which is what makes the value
	// attacker-influenceable and the flag worth persisting.
	Derived bool
}

type requestIDCtxKey struct{}

// RequestIDFromContext returns the correlation id RequestIDMiddleware settled on
// for this request. A handler needs both halves to write an evidence row: the
// value alone cannot say whether a caller chose it.
func RequestIDFromContext(ctx context.Context) (RequestID, bool) {
	v, ok := ctx.Value(requestIDCtxKey{}).(RequestID)
	return v, ok
}

// resolveRequestID picks the id for one request and reports whether the server
// derived it.
//
// A received value is propagated only if it conforms; a nonconforming one is
// REPLACED, not passed through and not dropped. Replacing keeps every request
// correlated — which is the reason this middleware exists — while the Derived
// flag preserves the forensic distinction the value itself cannot carry. The
// contract permits dropping the correlation instead; a server that prefers that
// can read the flag and decline to persist the pair.
//
// The minted value is checked too. An application supplies its own mint through
// WithRequestIDFunc (typically to reuse a trace id), and a trace id is exactly
// the kind of value that carries a colon, a brace, or nothing at all. A mint
// that returns something unusable falls back to DefaultRequestID rather than
// letting the trusted side put a value in the store that the untrusted side
// could not.
func resolveRequestID(received string, mint RequestIDFunc) RequestID {
	if ValidRequestID(received) {
		return RequestID{Value: received, Derived: false}
	}
	if minted := mint(); ValidRequestID(minted) {
		return RequestID{Value: minted, Derived: true}
	}
	return RequestID{Value: DefaultRequestID(), Derived: true}
}

// RequestIDMiddleware stamps (or propagates) X-Request-ID on the response BEFORE the
// next handler runs, so a rejected request still returns a correlated id. It is a
// plain net/http middleware — transport-neutral — kept at the http seam so it wraps
// the reject path too. The Connect server face composes it OUTERMOST (a reject
// response must still carry a stamped X-Request-ID); a non-Connect net/http server
// can compose it directly.
//
// The id it settles on is always one the admin plane can persist: a caller's
// header is propagated only when it conforms (see resolveRequestID). Downstream
// handlers read the value and its provenance with RequestIDFromContext.
func RequestIDMiddleware(mint RequestIDFunc, next http.Handler) http.Handler {
	if mint == nil {
		mint = DefaultRequestID
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := resolveRequestID(r.Header.Get(RequestIDHeader), mint)
		w.Header().Set(RequestIDHeader, id.Value)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDCtxKey{}, id)))
	})
}
