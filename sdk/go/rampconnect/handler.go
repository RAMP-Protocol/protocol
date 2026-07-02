package rampconnect

import (
	"net/http"

	"connectrpc.com/connect"

	"github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/ramp"
)

// requestIDHeader is the correlation header stamped outermost on every response,
// including the reject path — matching the client face's header name.
const requestIDHeader = "X-Request-ID"

// NewExchangeServiceHandler builds the ExchangeService HTTP handler wrapped by the
// SDK server face and returns the mount path and handler. The stack, from OUTERMOST
// in, is:
//
//	request-id  ·  verify (http-seam)  ·  [validate · error-detail  as connect interceptors]  ·  origin
//
// Request-id is OUTERMOST (architect-review amendment): an auth-rejection response
// must still carry the stamped X-Request-ID so reject-path logs correlate — putting
// request-id inner to verify would regress that. verify is an http.Handler wrapper
// (body-bytes reason), NOT a connect.Interceptor; validate and error-detail ARE true
// connect.Interceptors composed onto the generated handler. KeyResolver and
// ReplayStore are injected by the application (ADR-020 §2/§3).
func NewExchangeServiceHandler(svc rampv1connect.ExchangeServiceHandler, opts ...ServerOption) (string, http.Handler) {
	cfg := resolveServerConfig(opts)
	path, connectHandler := rampv1connect.NewExchangeServiceHandler(
		svc, connect.WithInterceptors(handlerInterceptors(cfg)...),
	)
	// verify wraps the connect handler; request-id wraps verify (outermost).
	wrapped := requestIDMiddleware(cfg.requestID, verifyMiddleware(cfg, connectHandler))
	return path, wrapped
}

// handlerInterceptors assembles the true connect.Interceptors composed onto the
// generated handler: bidirectional validate (requests + responses + error details)
// and any application interceptors. verify and request-id are NOT here — they are
// http-seam wrappers.
func handlerInterceptors(cfg serverConfig) []connect.Interceptor {
	var out []connect.Interceptor
	if cfg.validation == ramp.ValidationStrict {
		if v, err := newValidateInterceptor(); err == nil {
			out = append(out, v)
		}
	}
	out = append(out, cfg.extra...)
	return out
}

// requestIDMiddleware stamps (or propagates) X-Request-ID on the response BEFORE the
// verify wrapper runs, so a rejected request still returns a correlated id. It is the
// server mirror of the app's reqctx.RequestIDMiddleware, kept at the http seam so it
// wraps the reject path too.
func requestIDMiddleware(mint ramp.RequestIDFunc, next http.Handler) http.Handler {
	if mint == nil {
		mint = defaultRequestID
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(requestIDHeader)
		if id == "" {
			id = mint()
		}
		w.Header().Set(requestIDHeader, id)
		next.ServeHTTP(w, r)
	})
}
