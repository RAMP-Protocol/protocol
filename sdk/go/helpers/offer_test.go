package helpers_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func sampleOffer() *rampv1.Offer {
	return &rampv1.Offer{
		OfferId: "of_1",
		Pricing: &rampv1.Pricing{
			Model:    rampv1.PricingModel_PRICING_MODEL_PER_UNIT,
			Rate:     "0.05",
			Currency: "USD",
		},
		ExpiresAt: timestamppb.New(time.Unix(1700000300, 0)),
	}
}

func TestSignVerifyOffer_roundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	offer := sampleOffer()
	sig, err := helpers.SignOffer(priv, offer)
	if err != nil {
		t.Fatal(err)
	}
	// The signature field must be ignorable: set it, verification still holds.
	offer.Signature = sig
	offer.SignatureAlgorithm = helpers.OfferSignatureAlgorithm
	if err := helpers.VerifyOffer(offer, sig, pub); err != nil {
		t.Errorf("verify: %v", err)
	}
}

func TestVerifyOffer_tamperedPricing(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	offer := sampleOffer()
	sig, _ := helpers.SignOffer(priv, offer)
	offer.Pricing.Rate = "0.01" // Broker tries to undercut the price
	if err := helpers.VerifyOffer(offer, sig, pub); !errors.Is(err, helpers.ErrOfferSignatureInvalid) {
		t.Errorf("err = %v, want ErrOfferSignatureInvalid", err)
	}
}

func TestVerifyOffer_tamperedExpiry(t *testing.T) {
	// The protocol covers expires_at so a relaying Broker cannot extend the TTL.
	pub, priv, _ := ed25519.GenerateKey(nil)
	offer := sampleOffer()
	sig, _ := helpers.SignOffer(priv, offer)
	offer.ExpiresAt = timestamppb.New(time.Unix(1799999999, 0)) // extend the window
	if err := helpers.VerifyOffer(offer, sig, pub); !errors.Is(err, helpers.ErrOfferSignatureInvalid) {
		t.Errorf("extending expires_at must invalidate; err = %v", err)
	}
}

func TestVerifyOffer_tamperedExchange(t *testing.T) {
	// Offer.exchange is the signature-covered routing target: a
	// relaying Broker must not be able to redirect a signed offer to a different
	// Exchange. This is the anti-redirect property the relay routing depends on.
	pub, priv, _ := ed25519.GenerateKey(nil)
	offer := sampleOffer()
	offer.Exchange = "ex.alpha.example"
	sig, _ := helpers.SignOffer(priv, offer)
	offer.Exchange = "ex.evil.example" // Broker tries to re-point the routing target
	if err := helpers.VerifyOffer(offer, sig, pub); !errors.Is(err, helpers.ErrOfferSignatureInvalid) {
		t.Errorf("re-pointing Offer.exchange must invalidate the signature; err = %v", err)
	}
}

func TestVerifyOffer_wrongKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	other, _, _ := ed25519.GenerateKey(nil)
	offer := sampleOffer()
	sig, _ := helpers.SignOffer(priv, offer)
	if err := helpers.VerifyOffer(offer, sig, other); !errors.Is(err, helpers.ErrOfferSignatureInvalid) {
		t.Errorf("err = %v, want ErrOfferSignatureInvalid", err)
	}
}

func TestVerifyOffer_malformedHex(t *testing.T) {
	// A garbage (non-hex) signature is a verification failure like a forged
	// one: errors.Is-branching callers must land on the same rejected path.
	pub, _, _ := ed25519.GenerateKey(nil)
	if err := helpers.VerifyOffer(sampleOffer(), "not-hex!", pub); !errors.Is(err, helpers.ErrOfferSignatureInvalid) {
		t.Errorf("err = %v, want ErrOfferSignatureInvalid", err)
	}
}

func TestVerifyOffer_nil(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	if err := helpers.VerifyOffer(nil, "00", pub); err == nil {
		t.Error("nil offer should error")
	}
}

func TestCanonicalOfferBytes_matchesSignOffer(t *testing.T) {
	// The bytes CanonicalOfferBytes returns are exactly what SignOffer signed:
	// verifying the SignOffer signature directly over them must hold. This is the
	// property a caller relies on to persist verbatim, re-verifiable offer evidence.
	pub, priv, _ := ed25519.GenerateKey(nil)
	offer := sampleOffer()
	sigHex, err := helpers.SignOffer(priv, offer)
	if err != nil {
		t.Fatal(err)
	}
	canon, err := helpers.CanonicalOfferBytes(offer)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub, canon, sig) {
		t.Error("SignOffer signature must verify over CanonicalOfferBytes")
	}
}

func TestCanonicalOfferBytes_ignoresSignatureFields(t *testing.T) {
	// signature/signature_algorithm are cleared on a clone before canonicalizing,
	// so an already-signed offer yields the same bytes as the unsigned one — the
	// signature cannot cover itself.
	offer := sampleOffer()
	before, err := helpers.CanonicalOfferBytes(offer)
	if err != nil {
		t.Fatal(err)
	}
	offer.Signature = "deadbeef"
	offer.SignatureAlgorithm = helpers.OfferSignatureAlgorithm
	after, err := helpers.CanonicalOfferBytes(offer)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("CanonicalOfferBytes must clear signature/signature_algorithm; bytes differ")
	}
	// The clear happens on a clone: the caller's offer keeps the fields it set.
	if offer.Signature != "deadbeef" || offer.SignatureAlgorithm != helpers.OfferSignatureAlgorithm {
		t.Error("CanonicalOfferBytes must not mutate the caller's offer (clears on a clone)")
	}
}

func TestCanonicalOfferBytes_coversExpiresAt(t *testing.T) {
	// expires_at is inside the signed bytes (only the signature fields are
	// cleared), so changing it changes the canonical output — the property that
	// stops a relaying Broker from re-stretching a signed offer's TTL.
	a := sampleOffer()
	b := sampleOffer()
	b.ExpiresAt = timestamppb.New(time.Unix(1799999999, 0))
	ba, err := helpers.CanonicalOfferBytes(a)
	if err != nil {
		t.Fatal(err)
	}
	bb, err := helpers.CanonicalOfferBytes(b)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ba, bb) {
		t.Error("offers differing only in expires_at must produce different CanonicalOfferBytes")
	}
}

func TestCanonicalOfferBytes_nil(t *testing.T) {
	if _, err := helpers.CanonicalOfferBytes(nil); err == nil {
		t.Error("nil offer should error")
	}
}

// encodeWithUnknownField encodes msg and appends a field number no RAMP message
// defines — what a peer built against a newer schema emits, and equally what an
// on-path party appends to a message it did not author.
func encodeWithUnknownField(t *testing.T, msg proto.Message) []byte {
	t.Helper()
	raw, err := proto.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	raw = protowire.AppendTag(raw, 500, protowire.VarintType)
	return protowire.AppendVarint(raw, 7)
}

// embed appends msg's encoding to host as a length-delimited field, so an
// unknown field can be planted at a chosen depth of the Offer tree.
func embed(t *testing.T, host []byte, field protowire.Number, encoded []byte) []byte {
	t.Helper()
	host = protowire.AppendTag(host, field, protowire.BytesType)
	return protowire.AppendBytes(host, encoded)
}

// unknownFieldCase pairs an Offer with the SAME Offer carrying one unknown field.
// The two differ by nothing a renderer can see, which is the whole point: any
// rejection has to come from the unknown field itself, not from a visible
// difference that would break the signature anyway.
type unknownFieldCase struct {
	clean    *rampv1.Offer
	tampered *rampv1.Offer
}

// unknownFieldCases plants an unknown field at three depths: on the Offer itself,
// inside the nested Pricing message, and inside one element of the repeated
// attestations list. Unknown-field sets are per-message, so a guard that only
// checks the top level passes the first and misses the other two.
func unknownFieldCases(t *testing.T) map[string]unknownFieldCase {
	t.Helper()

	decode := func(raw []byte) *rampv1.Offer {
		var o rampv1.Offer
		if err := proto.Unmarshal(raw, &o); err != nil {
			t.Fatal(err)
		}
		return &o
	}
	encode := func(m proto.Message) []byte {
		raw, err := proto.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}

	out := map[string]unknownFieldCase{}

	out["top level"] = unknownFieldCase{
		clean:    sampleOffer(),
		tampered: decode(encodeWithUnknownField(t, sampleOffer())),
	}

	// Rebuild the offer from a shell plus a hand-encoded Pricing so the unknown
	// field lands inside the nested message. The shell carries every other field,
	// so clean and tampered render identically.
	base := sampleOffer()
	shell := encode(&rampv1.Offer{OfferId: base.OfferId, ExpiresAt: base.ExpiresAt})
	out["nested message"] = unknownFieldCase{
		clean:    decode(embed(t, shell, offerPricingField, encode(base.Pricing))),
		tampered: decode(embed(t, shell, offerPricingField, encodeWithUnknownField(t, base.Pricing))),
	}

	// The attestation must be present in BOTH, or the tampered offer would differ
	// visibly and be rejected on a byte mismatch — passing the test for a reason
	// that has nothing to do with the unknown field.
	full := encode(sampleOffer())
	att := &rampv1.ResourceAttestation{Verifier: "verifier.example.com", Uri: "https://example.com/a"}
	out["repeated element"] = unknownFieldCase{
		clean:    decode(embed(t, full, offerAttestationsField, encode(att))),
		tampered: decode(embed(t, full, offerAttestationsField, encodeWithUnknownField(t, att))),
	}

	return out
}

// Offer field numbers used to plant an unknown field at depth. Kept as named
// constants so a proto renumbering breaks the fixture loudly instead of quietly
// planting the field somewhere else.
const (
	offerPricingField      protowire.Number = 3
	offerAttestationsField protowire.Number = 14
)

func TestCanonicalOfferBytes_refusesUnknownFields(t *testing.T) {
	// proto-JSON renders only what the schema defines, so a message carrying
	// unknown fields would canonicalize to bytes that silently drop them. Producing
	// those bytes is refused outright: they are not the bytes anyone signed, and
	// handing them back as "the canonical form" is what would let an intermediary
	// append content to a signed offer without disturbing its signature.
	for name, c := range unknownFieldCases(t) {
		t.Run(name, func(t *testing.T) {
			if _, err := helpers.CanonicalOfferBytes(c.clean); err != nil {
				t.Fatalf("control: the same offer without the unknown field must canonicalize: %v", err)
			}
			if _, err := helpers.CanonicalOfferBytes(c.tampered); err == nil {
				t.Error("an offer carrying unknown fields must not yield canonical bytes")
			}
		})
	}
}

func TestVerifyOffer_rejectsInjectedUnknownFields(t *testing.T) {
	// The tamper case: a legitimately signed offer picks up unknown fields in
	// transit. The signature still matches the fields this build can render, so
	// only the refusal above stops it from verifying. It must land on the signature
	// sentinel — callers map that to a signature-invalid denial, and an appended
	// payload is a tampered offer, not an internal fault.
	pub, priv, _ := ed25519.GenerateKey(nil)
	for name, c := range unknownFieldCases(t) {
		t.Run(name, func(t *testing.T) {
			// Sign the CLEAN offer, then verify the tampered one. The signature is
			// genuine and the two render identically, so the unknown field is the
			// only thing that can cause a rejection.
			sigHex, err := helpers.SignOffer(priv, c.clean)
			if err != nil {
				t.Fatal(err)
			}
			if err := helpers.VerifyOffer(c.clean, sigHex, pub); err != nil {
				t.Fatalf("control: the clean offer must verify: %v", err)
			}
			if err := helpers.VerifyOffer(c.tampered, sigHex, pub); !errors.Is(err, helpers.ErrOfferSignatureInvalid) {
				t.Errorf("want ErrOfferSignatureInvalid, got %v", err)
			}
		})
	}
}

func TestCanonicalOfferBytes_refusesUnknownFieldsInsideExt(t *testing.T) {
	// ext is a google.protobuf.Struct, whose `fields` is a map with MESSAGE values —
	// the one place the walk's map branch is reachable on this schema, and it guards
	// the sanctioned extension surface. An unknown field planted on a Struct Value
	// sits two levels below the Offer and behind a map, so nothing shallower catches
	// it.
	st, err := structpb.NewStruct(map[string]any{"vendor.key": "v"})
	if err != nil {
		t.Fatal(err)
	}
	clean := sampleOffer()
	clean.Ext = st
	if _, err := helpers.CanonicalOfferBytes(clean); err != nil {
		t.Fatalf("control: an untampered ext must canonicalize: %v", err)
	}

	tamperedVal := new(structpb.Value)
	if err := proto.Unmarshal(encodeWithUnknownField(t, st.Fields["vendor.key"]), tamperedVal); err != nil {
		t.Fatal(err)
	}
	if len(tamperedVal.ProtoReflect().GetUnknown()) == 0 {
		t.Fatal("fixture is inert: the unknown field did not survive unmarshal")
	}
	st.Fields["vendor.key"] = tamperedVal

	if _, err := helpers.CanonicalOfferBytes(clean); !errors.Is(err, helpers.ErrUnknownFields) {
		t.Errorf("want ErrUnknownFields for an unknown field inside ext, got %v", err)
	}
}

func TestCanonicalOfferBytes_mapEntryUnknownsAreDroppedBeforeTheWalk(t *testing.T) {
	// The walk recurses into map VALUES, not into the synthetic entry messages that
	// carry them. That is total only because protobuf-go discards unknown bytes
	// planted on an entry at unmarshal, so they never reach the canonicalizer — and
	// never reach the wire again either. This pins that assumption: if a protobuf
	// upgrade started retaining entry-level unknowns, the walk would need a branch
	// for them and this test is what would say so.
	st, err := structpb.NewStruct(map[string]any{"vendor.key": "v"})
	if err != nil {
		t.Fatal(err)
	}
	valRaw, err := proto.Marshal(st.Fields["vendor.key"])
	if err != nil {
		t.Fatal(err)
	}
	// Struct.fields entry: key(1), value(2), then an undeclared field ON THE ENTRY.
	entry := protowire.AppendTag(nil, 1, protowire.BytesType)
	entry = protowire.AppendBytes(entry, []byte("vendor.key"))
	entry = protowire.AppendTag(entry, 2, protowire.BytesType)
	entry = protowire.AppendBytes(entry, valRaw)
	entry = protowire.AppendTag(entry, 500, protowire.VarintType)
	entry = protowire.AppendVarint(entry, 7)
	structRaw := protowire.AppendTag(nil, 1, protowire.BytesType)
	structRaw = protowire.AppendBytes(structRaw, entry)

	got := new(structpb.Struct)
	if err := proto.Unmarshal(structRaw, got); err != nil {
		t.Fatal(err)
	}
	reEncoded, err := proto.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	clean, err := proto.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if len(reEncoded) != len(clean) {
		t.Fatalf("protobuf-go now RETAINS entry-level unknown bytes (%d vs %d); the walk "+
			"must gain a map-entry branch", len(reEncoded), len(clean))
	}

	offer := sampleOffer()
	offer.Ext = got
	if _, err := helpers.CanonicalOfferBytes(offer); err != nil {
		t.Errorf("entry-level unknowns are dropped before the walk, so this must canonicalize: %v", err)
	}
}

func TestVerifyOffer_rejectsANewerCanonicalFormWhicheverCheckFires(t *testing.T) {
	// The other direction: the peer signed its OWN richer rendering, which includes
	// the field it knows about and this build does not. The signed bytes cannot be
	// reconstructed here at all, so the offer is rejected rather than verified over
	// a reduced form.
	//
	// This pins the OUTCOME, not the mechanism: the rejection also follows from the
	// plain signature mismatch, so the test passes with the unknown-field guard
	// removed. The guard is gated by the injected-unknown tests above, where clean
	// and tampered render identically and only the guard can reject.
	pub, priv, _ := ed25519.GenerateKey(nil)
	base := sampleOffer()
	baseCanon, err := helpers.CanonicalOfferBytes(base)
	if err != nil {
		t.Fatal(err)
	}
	// JCS sorts keys, so a member sorting last is appended before the closing brace.
	peerSigned := append(baseCanon[:len(baseCanon)-1:len(baseCanon)-1], []byte(`,"zz_new_field":"7"}`)...)
	peerSig := hex.EncodeToString(ed25519.Sign(priv, peerSigned))

	var newer rampv1.Offer
	if err := proto.Unmarshal(encodeWithUnknownField(t, base), &newer); err != nil {
		t.Fatal(err)
	}
	if err := helpers.VerifyOffer(&newer, peerSig, pub); !errors.Is(err, helpers.ErrOfferSignatureInvalid) {
		t.Errorf("want ErrOfferSignatureInvalid, got %v", err)
	}
}
