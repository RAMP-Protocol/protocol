package rampconnect

import (
	"crypto/rand"
	"encoding/hex"

	"connectrpc.com/connect"
	validate "connectrpc.com/validate"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// defaultRequestID mints a random 128-bit hex request id when a call carries none.
func defaultRequestID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "ramp-req"
	}
	return hex.EncodeToString(b)
}

// newValidateInterceptor returns the bidirectional protovalidate interceptor
// (requests + responses + error details are one SDK-validated contract, ADR-019).
// It injects the shared protovalidate engine helpers.Validate wraps, so the server
// validate interceptor and the L1 client pre-check share one engine — zero rule
// drift.
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
