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
// What the binding gives is transport authentication, typed error emission, and —
// WHEN THE APPLICATION ASKS FOR IT with WithValidation(rampconnect.ValidationStrict)
// — the contract's wire tier. That option is not the default (see the package doc):
// the ResourceEntry envelope rules and the terms cap are refused at the boundary
// only on a mount that passes it, which is what the retirement of the terms-limit
// rejection reason assumes.
//
// What stays the handler implementation's job is everything the contract leaves to
// the Exchange: that caller_id names the verified signer, that the caller is among
// the publisher's catalog_contributors, that tenant_id matches, the ingest-tier term
// checks (sdk/go/helpers), and the per-entry verdicts. An Exchange that resolves a
// contributor's key by caller_id narrows the seam with WithVerifyGate and verifies
// inside the handler, where the decoded request is in scope — WithKeyResolver cannot
// carry that policy, because KeyResolver.Resolve is handed the signature's keyid and
// never the message.
//
// Two replay notes specific to this service. Its verbs carry no idempotency_key by
// design — an upsert and a delete are naturally idempotent — so the message-layer
// replay defence the rest of the contract relies on does not apply here, and an
// injected ReplayStore is the only replay control on this path. And RemoveResources
// is destructive, so a stateless-edge deployment acknowledging WithoutReplayStore is
// accepting replay of a delete within its signature window.
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
		// Panic rather than serve unvalidated. An application that passed
		// ValidationStrict asked for the contract's wire tier; silently dropping it
		// would hand back a handler that still serves, with the boundary rules the
		// caller believes are running simply absent. The error is not a
		// misconfiguration a deployment can hit: the validator is built once from the
		// descriptor compiled into the binary, so a failure here is a broken build,
		// and it is caught at construction rather than on the first request. Same
		// posture as the resolver that refuses to be built without a fetcher.
		v, err := rampconnect.NewValidateInterceptor()
		if err != nil {
			panic("connectserver: WithValidation(ValidationStrict) was requested but the validator could not be built: " + err.Error())
		}
		out = append(out, v)
	}
	out = append(out, cfg.extra...)
	return out
}
