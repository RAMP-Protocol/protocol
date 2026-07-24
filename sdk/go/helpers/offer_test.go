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

func TestCanonicalOfferBytes_unknownFieldsFailClosed(t *testing.T) {
	// An Offer from a peer built against a newer schema carries fields this build's
	// generated types do not know. proto.Unmarshal keeps them as unknown fields, but
	// proto-JSON does not render them — so they are absent from the canonical bytes.
	// The direction that matters is which way the gap fails: the peer's signature
	// covered MORE than we can reconstruct, so it must be rejected, never accepted
	// over the truncated message.
	pub, priv, _ := ed25519.GenerateKey(nil)
	base := sampleOffer()

	wire, err := proto.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	unknown := protowire.AppendTag(nil, 500, protowire.VarintType)
	unknown = protowire.AppendVarint(unknown, 7)
	var newer rampv1.Offer
	if err := proto.Unmarshal(append(wire, unknown...), &newer); err != nil {
		t.Fatal(err)
	}
	if len(newer.ProtoReflect().GetUnknown()) == 0 {
		t.Fatal("fixture is inert: the unknown field did not survive unmarshal")
	}

	baseCanon, err := helpers.CanonicalOfferBytes(base)
	if err != nil {
		t.Fatal(err)
	}
	newerCanon, err := helpers.CanonicalOfferBytes(&newer)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(baseCanon, newerCanon) {
		t.Fatalf("unknown fields must not reach the canonical bytes\n got  %s\n want %s",
			newerCanon, baseCanon)
	}

	// What the newer peer signed: its own canonical rendering, which includes the
	// field it knows about. JCS sorts keys, so a member sorting last is appended
	// before the closing brace.
	peerSigned := append(baseCanon[:len(baseCanon)-1:len(baseCanon)-1], []byte(`,"zz_new_field":"7"}`)...)
	peerSig := hex.EncodeToString(ed25519.Sign(priv, peerSigned))

	if err := helpers.VerifyOffer(&newer, peerSig, pub); !errors.Is(err, helpers.ErrOfferSignatureInvalid) {
		t.Errorf("signature over a newer peer's canonical form must be rejected, got %v", err)
	}
}
