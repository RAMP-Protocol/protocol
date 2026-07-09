package helpers

import (
	"fmt"

	"github.com/gowebpki/jcs"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// Canonical signing payload (ADR-020 §4, ramp.proto "canonical signing" note).
//
// Both signed RAMP payloads — the Offer signature and the agent's detached
// offer-acceptance — cover a canonical serialization of a protobuf message. As of
// the JCS switch (user decision, ixs7u.10) that canonical form is:
//
//	signed_payload = JCS( protojson(msg with sig/sig_algorithm cleared) )
//
// i.e. render the message to canonical proto-JSON with a PINNED option set, then
// apply the RFC 8785 JSON Canonicalization Scheme. Deterministic protobuf binary
// marshaling is explicitly NOT canonical across languages/versions (protobuf's own
// caveat), so it cannot be a cross-language signing primitive; JCS over proto-JSON
// CAN be reproduced by any language (Go/TS/Python) without a protobuf binary codec.
// Go keeps protobuf and the wire format unchanged — ONLY the signed bytes change.
//
// PINNED proto-JSON option set (documented in proto/ramp.proto):
//   - enums as NAME strings (protojson default; UseEnumNumbers=false)
//   - int64/uint64/fixed64 as strings (protojson default)
//   - bytes as std base64 (protojson default)
//   - google.protobuf.Timestamp / Duration per proto-JSON WKT rules
//   - OMIT unpopulated fields (EmitUnpopulated=false — protojson default)
//   - field naming: snake_case (UseProtoNames=true — the proto field name, matching
//     the wire, the generated Pydantic/Zod clients, and the committed corpus)
//   - google.protobuf.Struct ext → a plain JSON object; JCS then sorts its keys
//     recursively, so the Struct case needs no special handling.
//
// The Go-emitted golden vector is the arbiter: whatever these options render MUST
// be byte-identical across Go(protojson+jcs) / TS / Python, proven by the shared
// offer-verify and acceptance vectors.

// canonicalSignJSONOptions is the single, pinned protojson marshal option set every
// canonical-signing site uses. Pinned here (not per call site) so the two signed
// payloads cannot drift from each other.
var canonicalSignJSONOptions = protojson.MarshalOptions{
	UseProtoNames:   true,  // snake_case — the naming all three SDK targets share
	UseEnumNumbers:  false, // enums as NAME strings
	EmitUnpopulated: false, // omit unpopulated fields
}

// canonicalSignPayload renders msg to canonical proto-JSON (pinned options) and
// applies RFC 8785 JCS, returning the exact UTF-8 bytes an Ed25519 signature
// covers. Callers clear signature/signature_algorithm on a clone BEFORE calling.
func canonicalSignPayload(msg proto.Message) ([]byte, error) {
	pj, err := canonicalSignJSONOptions.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("helpers: canonical proto-JSON marshal: %w", err)
	}
	canon, err := jcs.Transform(pj)
	if err != nil {
		return nil, fmt.Errorf("helpers: JCS transform: %w", err)
	}
	return canon, nil
}
