package ramp

import (
	"context"
	"crypto/rand"
	"encoding/hex"

	"connectrpc.com/connect"
	validate "connectrpc.com/validate"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// requestIDHeader is the correlation header the request-id interceptor mints and
// propagates on every RPC (client and server faces share the name).
const requestIDHeader = "X-Request-ID"

// RequestIDFunc mints a fresh request id when a call carries none. The default is
// a random 128-bit hex token; an application overrides it (e.g. to reuse a trace
// id) via WithRequestIDFunc.
type RequestIDFunc func() string

// defaultRequestID returns a random 128-bit hex request id.
func defaultRequestID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "ramp-req"
	}
	return hex.EncodeToString(b)
}

// requestIDInterceptor is a true connect.Interceptor (header-level, so it does not
// need the marshaled body): on an outbound unary call it stamps X-Request-ID when
// absent so downstream logs correlate. It mirrors the app's reqctx.RequestIDMiddleware
// minting behavior at the client face; the server face stamps its own via the
// http-seam request-id wrapper (rampconnect).
type requestIDInterceptor struct {
	mint RequestIDFunc
}

func newRequestIDInterceptor(mint RequestIDFunc) connect.Interceptor {
	if mint == nil {
		mint = defaultRequestID
	}
	return &requestIDInterceptor{mint: mint}
}

func (i *requestIDInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		if req.Spec().IsClient && req.Header().Get(requestIDHeader) == "" {
			req.Header().Set(requestIDHeader, i.mint())
		}
		return next(ctx, req)
	}
}

func (i *requestIDInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

func (i *requestIDInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return next
}

// Validation selects protovalidate strictness for the SDK validate interceptor.
// Strict wires the vetted connectrpc.com/validate interceptor BIDIRECTIONALLY —
// requests, responses, AND error details are one SDK-validated contract (ADR-019;
// architect-review amendment MEDIUM-3). Off omits the interceptor. It is a distinct
// axis from WithVerification (offer authenticity): validation is proto-shape
// conformance, verification is signature authenticity.
type Validation int

const (
	// ValidationOff omits the protovalidate interceptor (the default). A caller
	// opts into wire-shape enforcement with WithValidation(ValidationStrict).
	ValidationOff Validation = iota
	// ValidationStrict wires the bidirectional protovalidate interceptor.
	ValidationStrict
)

// newValidateInterceptor returns the bidirectional protovalidate interceptor built
// on the vetted connectrpc.com/validate library. It validates requests, responses,
// AND error details (WithValidateResponses) — the two-way SDK-validated contract of
// ADR-019 / amendment MEDIUM-3 — reusing the shared protovalidate engine
// helpers.Validate wraps so the interceptor and the L1 pre-check share one engine
// (zero rule drift).
func newValidateInterceptor() (connect.Interceptor, error) {
	v, err := helpers.SharedValidator()
	if err != nil {
		return nil, err
	}
	return validate.NewInterceptor(
		validate.WithValidator(v),
		validate.WithValidateResponses(),
	), nil
}
