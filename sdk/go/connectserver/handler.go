package connectserver

import (
	"net/http"

	connectrpc "connectrpc.com/connect"

	"github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	rampconnect "github.com/RAMP-Protocol/protocol/sdk/go/connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/core"
)

// NewExchangeServiceHandler builds the ExchangeService HTTP handler wrapped by the
// SDK server face and returns the mount path and handler. The stack, from OUTERMOST
// in, is:
//
//	request-id  ·  verify (http-seam)  ·  [validate · error-detail  as connect interceptors]  ·  origin
//
// Request-id is OUTERMOST: an auth-rejection response
// must still carry the stamped X-Request-ID so reject-path logs correlate — putting
// request-id inner to verify would regress that. verify is an http.Handler wrapper
// (body-bytes reason), NOT a connect.Interceptor; validate and error-detail ARE true
// connect.Interceptors composed onto the generated handler. KeyResolver and
// ReplayStore are injected by the application (ADR-020 §2/§3).
func NewExchangeServiceHandler(svc rampv1connect.ExchangeServiceHandler, opts ...ServerOption) (string, http.Handler) {
	cfg := resolveServerConfig(opts)
	path, connectHandler := rampv1connect.NewExchangeServiceHandler(svc, cfg.connectHandlerOptions()...)
	// verify wraps the connect handler; request-id wraps verify (outermost).
	wrapped := core.RequestIDMiddleware(cfg.requestID, cfg.boundBody(verifyMiddleware(cfg, connectHandler)))
	return path, wrapped
}

// NewBrokerServiceHandler builds the BrokerService HTTP handler wrapped by the
// SDK server face and returns the mount path and handler. It composes the same
// stack as NewExchangeServiceHandler — request-id outermost, verify at the http
// seam, validate/error-detail as connect interceptors — over the generated
// BrokerService handler. Broker relay routes outside the /ramp. procedure
// prefix are the application's own http surface and never pass through this
// handler; they keep their bespoke verification.
func NewBrokerServiceHandler(svc rampv1connect.BrokerServiceHandler, opts ...ServerOption) (string, http.Handler) {
	cfg := resolveServerConfig(opts)
	path, connectHandler := rampv1connect.NewBrokerServiceHandler(svc, cfg.connectHandlerOptions()...)
	wrapped := core.RequestIDMiddleware(cfg.requestID, cfg.boundBody(verifyMiddleware(cfg, connectHandler)))
	return path, wrapped
}

// NewCatalogServiceHandler builds the CatalogService HTTP handler wrapped by the
// SDK server face and returns the mount path and handler — the exchange-operator
// role's starting point for the publisher-facing RPCs. It composes the same
// stack as NewExchangeServiceHandler over the generated CatalogService handler:
// request-id outermost, verify at the http seam (every /ramp. procedure is
// gated, fail-closed, so an unsigned push never reaches the origin), validate and
// error-detail as connect interceptors.
//
// What the binding gives is transport authentication, wire validation and typed
// error emission. What stays the handler implementation's job is everything the
// contract leaves to the Exchange: that caller_id names the verified signer,
// that the caller is among the publisher's catalog_contributors, that tenant_id
// matches, the ingest-tier term checks (sdk/go/helpers), and the per-entry
// verdicts. An Exchange that resolves a contributor's key by caller_id rather
// than by keyid injects that policy through WithKeyResolver, or narrows the seam
// with WithVerifyGate and verifies inside the handler.
func NewCatalogServiceHandler(svc rampv1connect.CatalogServiceHandler, opts ...ServerOption) (string, http.Handler) {
	cfg := resolveServerConfig(opts)
	path, connectHandler := rampv1connect.NewCatalogServiceHandler(svc, cfg.connectHandlerOptions()...)
	wrapped := core.RequestIDMiddleware(cfg.requestID, cfg.boundBody(verifyMiddleware(cfg, connectHandler)))
	return path, wrapped
}

// connectHandlerOptions assembles the generated handler's options: the
// interceptor stack plus any raw pass-through handler options the app injected
// (WithHandlerOptions — e.g. a custom codec).
func (cfg serverConfig) connectHandlerOptions() []connectrpc.HandlerOption {
	// The caller's options come last so an application can tighten (or widen) a
	// default the SDK chose — the same ordering the client face uses.
	out := []connectrpc.HandlerOption{
		connectrpc.WithInterceptors(handlerInterceptors(cfg)...),
		connectrpc.WithReadMaxBytes(int(cfg.maxRequestBytes)),
	}
	return append(out, cfg.handlerOpts...)
}

// boundBody caps the RAW request body, which is a different quantity from the
// decompressed-message cap connectHandlerOptions sets: Connect's cap protects the
// decode, this one protects the read that precedes it. The verify face must buffer
// the whole body to check an RFC 9421 signature over the exact bytes, and it does
// that BEFORE it knows who the caller is — so an unauthenticated caller can spend
// server memory unless the read is bounded here.
//
// It is composed INSIDE request-id and OUTSIDE verify on purpose. Request-id stays
// outermost so a rejection still carries the stamped X-Request-ID — a 413 that
// cannot be correlated in the reject-path logs would regress exactly the property
// the request-id ordering exists to give. Connect recognises the resulting
// http.MaxBytesError and still answers with a well-formed Connect error.
func (cfg serverConfig) boundBody(next http.Handler) http.Handler {
	return http.MaxBytesHandler(next, cfg.maxRequestBytes)
}

// handlerInterceptors assembles the true connect.Interceptors composed onto the
// generated handler: bidirectional validate (requests + responses + error details)
// and any application interceptors. verify and request-id are NOT here — they are
// http-seam wrappers. The validate interceptor is the shared sdk/go/connect
// definition (one engine for client and server, zero duplication).
func handlerInterceptors(cfg serverConfig) []connectrpc.Interceptor {
	var out []connectrpc.Interceptor
	if cfg.validation == rampconnect.ValidationStrict {
		if v, err := rampconnect.NewValidateInterceptor(); err == nil {
			out = append(out, v)
		}
	}
	out = append(out, cfg.extra...)
	return out
}
