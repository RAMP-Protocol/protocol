package helpers_test

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// Fixed timestamps (no time.Now()). sampleOffer() expires_at is 1700000300.
const (
	tsBeforeExpiry = 1700000200 // now < expires_at -> fresh
	tsAtExpiry     = 1700000300 // now == expires_at -> boundary (valid per Core Invariant)
	tsAfterExpiry  = 1700000400 // now > expires_at -> expired
)

// Core Invariant: an offer is usable only when its Ed25519 signature over the
// canonical Offer (expires_at included) is valid AND its signed expires_at is at
// or after the injected `now`. Signature is checked first; `now` is always a
// parameter (no wall-clock reads).

func TestVerifyPresentedOffer_valid(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	offer := sampleOffer() // ExpiresAt = 1700000300
	sig, err := helpers.SignOffer(priv, offer)
	if err != nil {
		t.Fatal(err)
	}
	offer.Signature = sig
	offer.SignatureAlgorithm = helpers.OfferSignatureAlgorithm

	now := time.Unix(tsBeforeExpiry, 0)
	if err := helpers.VerifyPresentedOffer(offer, pub, now); err != nil {
		t.Errorf("valid signed unexpired offer: err = %v, want nil", err)
	}
}

func TestVerifyPresentedOffer_tamperedPrice(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	offer := sampleOffer()
	sig, _ := helpers.SignOffer(priv, offer)
	offer.Signature = sig
	offer.SignatureAlgorithm = helpers.OfferSignatureAlgorithm
	offer.Pricing.Rate = "0.01" // mutate a signed field after signing

	now := time.Unix(tsBeforeExpiry, 0)
	if err := helpers.VerifyPresentedOffer(offer, pub, now); !errors.Is(err, helpers.ErrOfferSignatureInvalid) {
		t.Errorf("tampered price: err = %v, want ErrOfferSignatureInvalid", err)
	}
}

func TestVerifyPresentedOffer_wrongKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	other, _, _ := ed25519.GenerateKey(nil)
	offer := sampleOffer()
	sig, _ := helpers.SignOffer(priv, offer)
	offer.Signature = sig
	offer.SignatureAlgorithm = helpers.OfferSignatureAlgorithm

	now := time.Unix(tsBeforeExpiry, 0)
	if err := helpers.VerifyPresentedOffer(offer, other, now); !errors.Is(err, helpers.ErrOfferSignatureInvalid) {
		t.Errorf("wrong key: err = %v, want ErrOfferSignatureInvalid", err)
	}
}

func TestVerifyPresentedOffer_expired(t *testing.T) {
	// expires_at is SET before signing (the signature covers it); verify with an
	// injected now strictly after that signed expiry.
	pub, priv, _ := ed25519.GenerateKey(nil)
	offer := sampleOffer() // ExpiresAt = 1700000300
	sig, _ := helpers.SignOffer(priv, offer)
	offer.Signature = sig
	offer.SignatureAlgorithm = helpers.OfferSignatureAlgorithm

	now := time.Unix(tsAfterExpiry, 0) // 1700000400 > 1700000300
	if err := helpers.VerifyPresentedOffer(offer, pub, now); !errors.Is(err, helpers.ErrOfferExpired) {
		t.Errorf("expired offer: err = %v, want ErrOfferExpired", err)
	}
}

func TestVerifyPresentedOffer_absentExpiry_failClosed(t *testing.T) {
	// DECISION (fail-closed): an offer with NO expires_at is treated as expired.
	// A self-contained bearer token with no expiry is a forever-token and unsafe.
	pub, priv, _ := ed25519.GenerateKey(nil)
	offer := sampleOffer()
	offer.ExpiresAt = nil // sign an offer that carries no expiry
	sig, _ := helpers.SignOffer(priv, offer)
	offer.Signature = sig
	offer.SignatureAlgorithm = helpers.OfferSignatureAlgorithm

	now := time.Unix(tsBeforeExpiry, 0)
	if err := helpers.VerifyPresentedOffer(offer, pub, now); !errors.Is(err, helpers.ErrOfferExpired) {
		t.Errorf("absent expires_at must fail closed: err = %v, want ErrOfferExpired", err)
	}
}

func TestVerifyPresentedOffer_boundaryNowEqualsExpiry(t *testing.T) {
	// Core Invariant: usable while expires_at >= now. now == expires_at is the
	// inclusive boundary and is NOT expired (mirrors expiry.Before(now) semantics).
	pub, priv, _ := ed25519.GenerateKey(nil)
	offer := sampleOffer() // ExpiresAt = 1700000300
	sig, _ := helpers.SignOffer(priv, offer)
	offer.Signature = sig
	offer.SignatureAlgorithm = helpers.OfferSignatureAlgorithm

	now := time.Unix(tsAtExpiry, 0) // exactly == signed expires_at
	if err := helpers.VerifyPresentedOffer(offer, pub, now); err != nil {
		t.Errorf("now == expires_at must be valid (inclusive boundary): err = %v, want nil", err)
	}
}
