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
// ReplayStore are injected by the application.
func NewExchangeServiceHandler(svc rampv1connect.ExchangeServiceHandler, opts ...ServerOption) (string, http.Handler) {
	cfg := resolveServerConfig(opts)
	path, connectHandler := rampv1connect.NewExchangeServiceHandler(svc, cfg.connectHandlerOptions()...)
	// verify wraps the connect handler; request-id wraps verify (outermost).
	wrapped := core.RequestIDMiddleware(cfg.requestID, verifyMiddleware(cfg, connectHandler))
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
	wrapped := core.RequestIDMiddleware(cfg.requestID, verifyMiddleware(cfg, connectHandler))
	return path, wrapped
}

// connectHandlerOptions assembles the generated handler's options: the
// interceptor stack plus any raw pass-through handler options the app injected
// (WithHandlerOptions — e.g. a custom codec).
func (cfg serverConfig) connectHandlerOptions() []connectrpc.HandlerOption {
	out := []connectrpc.HandlerOption{connectrpc.WithInterceptors(handlerInterceptors(cfg)...)}
	return append(out, cfg.handlerOpts...)
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
