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
	var cerr *connectrpc.Error
	if !errors.As(err, &cerr) {
		return nil, false
	}
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
