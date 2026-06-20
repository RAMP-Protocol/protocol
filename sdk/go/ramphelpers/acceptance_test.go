package ramphelpers_test

import (
	"crypto/ed25519"
	"errors"
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/ramphelpers"
)

func acceptanceFixture() (*rampv1.Offer, *rampv1.Requester, string) {
	offer := &rampv1.Offer{OfferId: "of_1", Signature: "ex-offer-sig-hex", SignatureAlgorithm: "EdDSA"}
	requester := &rampv1.Requester{Id: "agent-1", Domain: "agent.example.com"}
	return offer, requester, "idem-1"
}

func TestSignVerifyOfferAcceptance_roundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	offer, requester, idem := acceptanceFixture()

	sig, err := ramphelpers.SignOfferAcceptance(priv, offer, requester, idem)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if sig == "" {
		t.Fatal("empty signature")
	}
	if err := ramphelpers.VerifyOfferAcceptance(offer, requester, idem, sig, pub); err != nil {
		t.Errorf("verify valid acceptance: %v", err)
	}
}

func TestVerifyOfferAcceptance_tamperRejected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	offer, requester, idem := acceptanceFixture()
	sig, err := ramphelpers.SignOfferAcceptance(priv, offer, requester, idem)
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]func(){
		"tampered offer_sig": func() { offer.Signature = "different-offer-sig" },
		"tampered requester": func() { requester.Id = "attacker" },
		"tampered domain":    func() { requester.Domain = "evil.example.com" },
		"tampered idem":      func() { idem = "idem-2" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			o, r, i := acceptanceFixture()
			offer, requester, idem = o, r, i
			mutate()
			if err := ramphelpers.VerifyOfferAcceptance(offer, requester, idem, sig, pub); !errors.Is(err, ramphelpers.ErrAcceptanceSignatureInvalid) {
				t.Errorf("%s: expected ErrAcceptanceSignatureInvalid, got %v", name, err)
			}
		})
	}
}

func TestVerifyOfferAcceptance_wrongKeyRejected(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	otherPub, _, _ := ed25519.GenerateKey(nil)
	offer, requester, idem := acceptanceFixture()
	sig, _ := ramphelpers.SignOfferAcceptance(priv, offer, requester, idem)
	if err := ramphelpers.VerifyOfferAcceptance(offer, requester, idem, sig, otherPub); !errors.Is(err, ramphelpers.ErrAcceptanceSignatureInvalid) {
		t.Errorf("wrong key: expected ErrAcceptanceSignatureInvalid, got %v", err)
	}
}

func TestSignOfferAcceptance_emptyOfferSignatureRejected(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	_, requester, idem := acceptanceFixture()
	unsigned := &rampv1.Offer{OfferId: "of_1"} // no Signature
	if _, err := ramphelpers.SignOfferAcceptance(priv, unsigned, requester, idem); err == nil {
		t.Fatal("expected error signing acceptance over an unsigned offer (empty anchor)")
	}
}
