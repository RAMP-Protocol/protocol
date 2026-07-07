package ramphelpers_test

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/ramphelpers"
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
	sig, err := ramphelpers.SignOffer(priv, offer)
	if err != nil {
		t.Fatal(err)
	}
	// The signature field must be ignorable: set it, verification still holds.
	offer.Signature = sig
	offer.SignatureAlgorithm = ramphelpers.OfferSignatureAlgorithm
	if err := ramphelpers.VerifyOffer(offer, sig, pub); err != nil {
		t.Errorf("verify: %v", err)
	}
}

func TestVerifyOffer_tamperedPricing(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	offer := sampleOffer()
	sig, _ := ramphelpers.SignOffer(priv, offer)
	offer.Pricing.Rate = "0.01" // Broker tries to undercut the price
	if err := ramphelpers.VerifyOffer(offer, sig, pub); !errors.Is(err, ramphelpers.ErrOfferSignatureInvalid) {
		t.Errorf("err = %v, want ErrOfferSignatureInvalid", err)
	}
}

func TestVerifyOffer_tamperedExpiry(t *testing.T) {
	// The protocol covers expires_at so a relaying Broker cannot extend the TTL.
	pub, priv, _ := ed25519.GenerateKey(nil)
	offer := sampleOffer()
	sig, _ := ramphelpers.SignOffer(priv, offer)
	offer.ExpiresAt = timestamppb.New(time.Unix(1799999999, 0)) // extend the window
	if err := ramphelpers.VerifyOffer(offer, sig, pub); !errors.Is(err, ramphelpers.ErrOfferSignatureInvalid) {
		t.Errorf("extending expires_at must invalidate; err = %v", err)
	}
}

func TestVerifyOffer_wrongKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	other, _, _ := ed25519.GenerateKey(nil)
	offer := sampleOffer()
	sig, _ := ramphelpers.SignOffer(priv, offer)
	if err := ramphelpers.VerifyOffer(offer, sig, other); !errors.Is(err, ramphelpers.ErrOfferSignatureInvalid) {
		t.Errorf("err = %v, want ErrOfferSignatureInvalid", err)
	}
}

func TestVerifyOffer_nil(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	if err := ramphelpers.VerifyOffer(nil, "00", pub); err == nil {
		t.Error("nil offer should error")
	}
}
