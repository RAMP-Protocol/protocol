package connectserver

import (
	connectrpc "connectrpc.com/connect"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

// AttachErrorDetail builds the ADR-019 ErrorDetail envelope (the
// non-authoritative developer message, the stable service domain, and any
// structured field metadata) and attaches it to an ALREADY-CLASSIFIED
// *connect.Error, returning that same error. It is the SDK-owned realisation of
// the ErrorDetail<->domain envelope build (RAMP-118): every service that maps a
// domain error to a connect.Error and then stamps a generic (no typed reason)
// detail shares this one body instead of copying it.
//
// The attach is best-effort: if the detail cannot be marshalled the bare cerr is
// returned rather than dropping the classified error. metadata is stamped only
// when non-empty, so the emitted proto shape matches a hand-built
// ErrorDetail{Domain, Message} for the metadata-free case (a nil map and an empty
// map are both absent on the wire, but keeping the field nil avoids allocating an
// empty map the caller never populated).
//
// It sits in the SERVER binding — a server EMITS a typed detail — alongside
// AsConnectError, keeping connectrpc out of the transport-neutral L1 helpers. A
// caller needing a typed reason oneof builds the *rampv1.ErrorDetail via the
// helpers.*Detail builders and attaches it with AttachDetail below.
func AttachErrorDetail(
	cerr *connectrpc.Error,
	domain, message string,
	metadata map[string]string,
) error {
	d := &rampv1.ErrorDetail{Domain: domain, Message: message}
	if len(metadata) > 0 {
		d.Metadata = metadata
	}
	return AttachDetail(cerr, d)
}

// AttachDetail attaches the proto ErrorDetail d to cerr and returns it. The
// detail is best-effort: if it cannot be marshalled the bare cerr is returned
// rather than dropping the classified error. It keeps the
// NewErrorDetail/AddDetail dance in exactly one place for callers that build a
// typed-reason detail themselves (via the helpers.*Detail builders) — the shape
// AttachErrorDetail delegates to for the generic case.
func AttachDetail(cerr *connectrpc.Error, d *rampv1.ErrorDetail) error {
	detail, err := connectrpc.NewErrorDetail(d)
	if err != nil {
		return cerr
	}
	cerr.AddDetail(detail)
	return cerr
}
