package connectserver

import (
	"errors"
	"fmt"

	connectrpc "connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// EmitUnpopulatedJSONCodec replaces Connect-Go's default JSON codec so scalar
// fields with their zero value (e.g. a non-optional Cost.amount left as the
// empty decimal string on a subscription-covered offer) appear in the JSON wire
// output. Connect's default protojson.MarshalOptions{} omits zero-valued
// scalars, which loses an observable agents depend on: "the subscription-covered
// offer carries a zero Cost.amount" cannot be asserted when the field is omitted
// entirely from the response. A MESSAGE field is not omitted when unset — protojson
// renders it as `null` under EmitUnpopulated, and so are Struct and map fields, which
// is what a JSON client has to accept from a conformant RAMP server. Only an unpopulated
// ONEOF member and an unset extension field are omitted outright.
//
// Field names are snake_case (UseProtoNames=true) — the RAMP wire is snake_case
// proto-JSON everywhere (proto field names, corpus, generated clients, and this
// Connect codec).
//
// Unmarshal discards unknown fields (a newer client may send fields this
// server's pin does not know) and rejects a zero-length payload.
//
// Emit-unpopulated is a RAMP-platform wire-policy choice, not a Connect
// universal, so the codec is OPT-IN: register it per handler via
// WithEmitUnpopulated (SDK-wrapped mounts) or pass
// connectrpc.WithCodec(EmitUnpopulatedJSONCodec()) directly to a raw generated
// handler. Both `json` and `json; charset=utf-8` content-types route here.
func EmitUnpopulatedJSONCodec() connectrpc.Codec {
	return &emitUnpopulatedJSONCodec{name: "json"}
}

// WithEmitUnpopulated registers EmitUnpopulatedJSONCodec on the handler —
// sugar over WithHandlerOptions(connectrpc.WithCodec(...)) so a service mount
// selects the RAMP JSON wire policy without importing connectrpc.
func WithEmitUnpopulated() ServerOption {
	return func(c *serverConfig) {
		c.handlerOpts = append(c.handlerOpts, connectrpc.WithCodec(EmitUnpopulatedJSONCodec()))
	}
}

type emitUnpopulatedJSONCodec struct{ name string }

func (c *emitUnpopulatedJSONCodec) Name() string { return c.name }

func (c *emitUnpopulatedJSONCodec) Marshal(message any) ([]byte, error) {
	pm, ok := message.(proto.Message)
	if !ok {
		return nil, fmt.Errorf("emit-unpopulated json codec: %T is not proto.Message", message)
	}
	return protojson.MarshalOptions{EmitUnpopulated: true, UseProtoNames: true}.Marshal(pm)
}

func (c *emitUnpopulatedJSONCodec) MarshalAppend(dst []byte, message any) ([]byte, error) {
	pm, ok := message.(proto.Message)
	if !ok {
		return nil, fmt.Errorf("emit-unpopulated json codec: %T is not proto.Message", message)
	}
	return protojson.MarshalOptions{EmitUnpopulated: true, UseProtoNames: true}.MarshalAppend(dst, pm)
}

func (c *emitUnpopulatedJSONCodec) Unmarshal(binary []byte, message any) error {
	pm, ok := message.(proto.Message)
	if !ok {
		return fmt.Errorf("emit-unpopulated json codec: %T is not proto.Message", message)
	}
	if len(binary) == 0 {
		return errors.New("zero-length payload is not a valid JSON object")
	}
	return protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(binary, pm)
}
