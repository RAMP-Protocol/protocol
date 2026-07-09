package core

import (
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

// RequestIDMiddleware stamps (or propagates) X-Request-ID on the response BEFORE the
// next handler runs, so a rejected request still returns a correlated id. It is a
// plain net/http middleware — transport-neutral — kept at the http seam so it wraps
// the reject path too. The Connect server face composes it OUTERMOST (a reject
// response must still carry a stamped X-Request-ID); a non-Connect net/http server
// can compose it directly.
func RequestIDMiddleware(mint RequestIDFunc, next http.Handler) http.Handler {
	if mint == nil {
		mint = DefaultRequestID
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(RequestIDHeader)
		if id == "" {
			id = mint()
		}
		w.Header().Set(RequestIDHeader, id)
		next.ServeHTTP(w, r)
	})
}
