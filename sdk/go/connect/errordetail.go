package connect

import (
	"errors"

	connectrpc "connectrpc.com/connect"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

// ErrorDetailFrom extracts the first RAMP ErrorDetail attached to err's Connect
// error chain. It returns false when err is not a Connect error or carries no
// ErrorDetail. It lives in the CLIENT binding (the read direction: a client READS
// the typed error detail an upstream emitted) because it must unwrap a
// *connect.Error — a Connect-transport concern. The neutral Reason accessor (over an
// already-extracted detail) stays in sdk/go/helpers; the emit direction
// (AsConnectError) lives in the server binding sdk/go/connectserver.
func ErrorDetailFrom(err error) (*rampv1.ErrorDetail, bool) {
	// The SDK's own typed failure is checked first, so ONE accessor serves every
	// verb. On an RPC path the detail below was emitted by the peer; on the
	// content path it was synthesized locally from the edge's refusal token,
	// because a delivery edge answers a small JSON object rather than a protobuf.
	// What a synthesized detail names as its domain, and why, is recorded once on
	// edgeErrorDomain rather than restated here.
	if callErr, ok := asCallError(err); ok && callErr.Detail != nil {
		return callErr.Detail, true
	}
	var cerr *connectrpc.Error
	if !errors.As(err, &cerr) {
		return nil, false
	}
	return errorDetailFromConnect(cerr)
}

// errorDetailFromConnect reads the first RAMP ErrorDetail off an already-unwrapped
// Connect error. Split out so the CallError bridge can reuse the one extraction
// rather than restating it.
func errorDetailFromConnect(cerr *connectrpc.Error) (*rampv1.ErrorDetail, bool) {
	for _, d := range cerr.Details() {
		msg, verr := d.Value()
		if verr != nil {
			continue
		}
		if ed, ok := msg.(*rampv1.ErrorDetail); ok {
			return ed, true
		}
	}
	return nil, false
}
