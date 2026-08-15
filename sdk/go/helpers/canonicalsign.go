package helpers

import (
	"errors"
	"fmt"

	"github.com/gowebpki/jcs"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// Canonical signing payload (ramp.proto "canonical signing" note).
//
// Both signed RAMP payloads — the Offer signature and the agent's detached
// offer-acceptance — cover a canonical serialization of a protobuf message. As of
// the JCS switch that canonical form is:
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

// ErrUnknownFields refuses a message the canonical form cannot faithfully
// represent. proto-JSON renders only fields the schema defines, so a message
// carrying unknown ones canonicalizes to bytes that silently omit them. Both
// directions of that gap are wrong: a signer built against a newer schema
// covered more than this build can reconstruct, and an on-path party that
// appends unknown fields to an already-signed message would otherwise leave the
// signature verifying over bytes it never saw. Refusing the message is what
// makes the canonical form's coverage total rather than schema-relative.
//
// CanonicalOfferBytes and SignOffer return it directly, so a caller persisting
// evidence can tell this refusal apart from a marshal fault. VerifyOffer wraps it
// alongside ErrOfferSignatureInvalid — a message that arrived carrying extra bytes
// is a tampered offer — so errors.Is matches either sentinel there.
var ErrUnknownFields = errors.New("helpers: message carries unknown fields; canonical bytes cannot represent them")

// hasUnknownFields reports whether msg, or anything reachable from it, carries
// fields this build's schema does not define.
//
// The walk is explicit rather than delegated to a traversal helper: this is a
// signature-coverage guard, so its reachability rules are stated here where they
// can be audited against the message tree. Unknown-field sets are PER MESSAGE —
// a nested message and every element of a repeated or map field owns its own —
// so a top-level check alone would pass a payload whose tampering sits one level
// down.
func hasUnknownFields(msg proto.Message) bool {
	if msg == nil {
		return false
	}
	return messageHasUnknown(msg.ProtoReflect())
}

func messageHasUnknown(m protoreflect.Message) bool {
	if !m.IsValid() {
		return false // a typed nil carries nothing
	}
	if len(m.GetUnknown()) > 0 {
		return true
	}
	found := false
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		switch {
		case fd.IsMap():
			// Map KEYS are scalars; only a message-typed value can nest one. The
			// synthetic ENTRY messages are not visited: protobuf-go discards unknown
			// bytes planted on an entry at unmarshal, so they never reach here (nor
			// the wire again). offer_test.go pins that, and fails loudly if a
			// protobuf upgrade starts retaining them.
			if fd.MapValue().Kind() == protoreflect.MessageKind ||
				fd.MapValue().Kind() == protoreflect.GroupKind {
				v.Map().Range(func(_ protoreflect.MapKey, mv protoreflect.Value) bool {
					if messageHasUnknown(mv.Message()) {
						found = true
					}
					return !found
				})
			}
		case fd.IsList():
			if fd.Kind() == protoreflect.MessageKind || fd.Kind() == protoreflect.GroupKind {
				list := v.List()
				for i := 0; i < list.Len() && !found; i++ {
					if messageHasUnknown(list.Get(i).Message()) {
						found = true
					}
				}
			}
		case fd.Kind() == protoreflect.MessageKind, fd.Kind() == protoreflect.GroupKind:
			if messageHasUnknown(v.Message()) {
				found = true
			}
		}
		return !found // stop the range as soon as one is found
	})
	return found
}

// canonicalSignPayload renders msg to canonical proto-JSON (pinned options) and
// applies RFC 8785 JCS, returning the exact UTF-8 bytes an Ed25519 signature
// covers. Callers clear signature/signature_algorithm on a clone BEFORE calling.
//
// A message carrying unknown fields is refused rather than rendered — see
// ErrUnknownFields.
func canonicalSignPayload(msg proto.Message) ([]byte, error) {
	if hasUnknownFields(msg) {
		return nil, ErrUnknownFields
	}
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
