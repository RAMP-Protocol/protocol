package connect

import (
	"context"

	connectrpc "connectrpc.com/connect"
	validate "connectrpc.com/validate"

	"github.com/RAMP-Protocol/protocol/sdk/go/core"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// requestIDInterceptor is a true connect.Interceptor (header-level, so it does not
// need the marshaled body): on an outbound unary call it stamps X-Request-ID when
// absent so downstream logs correlate. It mirrors the app's reqctx.RequestIDMiddleware
// minting behavior at the client face; the server face stamps its own via the
// http-seam request-id wrapper (core.RequestIDMiddleware).
type requestIDInterceptor struct {
	mint core.RequestIDFunc
}

func newRequestIDInterceptor(mint core.RequestIDFunc) connectrpc.Interceptor {
	if mint == nil {
		mint = core.DefaultRequestID
	}
	return &requestIDInterceptor{mint: mint}
}

func (i *requestIDInterceptor) WrapUnary(next connectrpc.UnaryFunc) connectrpc.UnaryFunc {
	return func(ctx context.Context, req connectrpc.AnyRequest) (connectrpc.AnyResponse, error) {
		if req.Spec().IsClient && req.Header().Get(core.RequestIDHeader) == "" {
			req.Header().Set(core.RequestIDHeader, i.mint())
		}
		return next(ctx, req)
	}
}

func (i *requestIDInterceptor) WrapStreamingClient(next connectrpc.StreamingClientFunc) connectrpc.StreamingClientFunc {
	return next
}

func (i *requestIDInterceptor) WrapStreamingHandler(next connectrpc.StreamingHandlerFunc) connectrpc.StreamingHandlerFunc {
	return next
}

// Validation selects protovalidate strictness for the SDK validate interceptor.
// Strict wires the vetted connectrpc.com/validate interceptor BIDIRECTIONALLY —
// requests, responses, AND error details are one SDK-validated contract
// (ADR-019). Off omits the interceptor. It is a distinct
// axis from WithVerification (offer authenticity): validation is proto-shape
// conformance, verification is signature authenticity. This enum is SHARED by both
// faces: the server binding (sdk/go/connectserver) references connect.Validation so
// client and server select strictness with one type.
type Validation int

const (
	// ValidationOff omits the protovalidate interceptor (the default). A caller
	// opts into wire-shape enforcement with WithValidation(ValidationStrict).
	ValidationOff Validation = iota
	// ValidationStrict wires the bidirectional protovalidate interceptor.
	ValidationStrict
)

// NewValidateInterceptor returns the bidirectional protovalidate interceptor built
// on the vetted connectrpc.com/validate library. It validates requests, responses,
// AND error details (WithValidateResponses) — the two-way SDK-validated contract of
// ADR-019 — reusing the shared protovalidate engine
// helpers.Validate wraps so the interceptor and the L1 pre-check share one engine
// (zero rule drift). It is the SINGLE definition both the client (this package) and
// the server binding (sdk/go/connectserver, which imports it) compose, so the two
// faces share one validate interceptor with zero duplication.
func NewValidateInterceptor() (connectrpc.Interceptor, error) {
	v, err := helpers.SharedValidator()
	if err != nil {
		return nil, err
	}
	return validate.NewInterceptor(
		validate.WithValidator(v),
		validate.WithValidateResponses(),
	), nil
}
