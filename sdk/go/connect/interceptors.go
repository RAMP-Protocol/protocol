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

// requestIDMint resolves the correlation-id source once, so every leg of a client
// reads the same one.
//
// It is a named function rather than a nil check at each site because the legs do
// not share a mechanism: the RPC legs correlate through the interceptor below, and
// the delivery fetch is a plain GET that never reaches an interceptor and takes its
// own hook. Two nil checks are two places for the default to drift, and the leg
// that would drift silently is the one carrying no id at all.
func requestIDMint(mint core.RequestIDFunc) core.RequestIDFunc {
	if mint == nil {
		return core.DefaultRequestID
	}
	return mint
}

func newRequestIDInterceptor(mint core.RequestIDFunc) connectrpc.Interceptor {
	return &requestIDInterceptor{mint: requestIDMint(mint)}
}

func (i *requestIDInterceptor) WrapUnary(next connectrpc.UnaryFunc) connectrpc.UnaryFunc {
	return func(ctx context.Context, req connectrpc.AnyRequest) (connectrpc.AnyResponse, error) {
		// Stamp only when absent — a caller who set the header meant it, and the
		// client is not the place to police a peer's correlation vocabulary. The
		// MINTED value is checked, because an injected RequestIDFunc usually
		// reuses a trace id and a trace id may carry characters the admin plane
		// cannot persist. Sending one would make the receiving Exchange replace
		// it, silently breaking the correlation this interceptor exists to
		// create.
		if req.Spec().IsClient && req.Header().Get(core.RequestIDHeader) == "" {
			if id := i.mint(); core.ValidRequestID(id) {
				req.Header().Set(core.RequestIDHeader, id)
			} else {
				req.Header().Set(core.RequestIDHeader, core.DefaultRequestID())
			}
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
// requests, responses, AND error details are one SDK-validated contract.
// Off omits the interceptor. It is a distinct
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
// AND error details (WithValidateResponses) — the two-way SDK-validated contract,
// reusing the shared protovalidate engine
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
