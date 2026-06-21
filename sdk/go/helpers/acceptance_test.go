package helpers_test

import (
	"crypto/ed25519"
	"errors"
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

func acceptanceFixture() (*rampv1.Offer, *rampv1.Requester, string) {
	offer := &rampv1.Offer{OfferId: "of_1", Signature: "ex-offer-sig-hex", SignatureAlgorithm: "EdDSA"}
	requester := &rampv1.Requester{Id: "agent-1", Domain: "agent.example.com"}
	return offer, requester, "idem-1"
}

func TestSignVerifyOfferAcceptance_roundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	offer, requester, idem := acceptanceFixture()

	sig, err := helpers.SignOfferAcceptance(priv, offer, requester, idem)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if sig == "" {
		t.Fatal("empty signature")
	}
	if err := helpers.VerifyOfferAcceptance(offer, requester, idem, sig, pub); err != nil {
		t.Errorf("verify valid acceptance: %v", err)
	}
}

func TestVerifyOfferAcceptance_tamperRejected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	offer, requester, idem := acceptanceFixture()
	sig, err := helpers.SignOfferAcceptance(priv, offer, requester, idem)
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
			if err := helpers.VerifyOfferAcceptance(offer, requester, idem, sig, pub); !errors.Is(err, helpers.ErrAcceptanceSignatureInvalid) {
				t.Errorf("%s: expected ErrAcceptanceSignatureInvalid, got %v", name, err)
			}
		})
	}
}

func TestVerifyOfferAcceptance_economicsRebound(t *testing.T) {
	// End-to-end economic binding: the acceptance covers the Exchange's offer
	// signature, which covers the offer's economics. An acceptance taken over a
	// $0.05 offer must NOT authorize a re-signed $0.01 offer — a Broker cannot
	// swap the price under a valid acceptance, and the agent is never bound to a
	// price it didn't accept. (The tamper-table above proves this abstractly via
	// offer_sig; this proves the full real-signature chain.)
	exPub, exPriv, _ := ed25519.GenerateKey(nil) // Exchange offer-signing key
	agentPub, agentPriv, _ := ed25519.GenerateKey(nil)
	requester := &rampv1.Requester{Id: "agent-1", Domain: "agent.example.com"}
	const idem = "idem-econ"
	_ = exPub

	offer := sampleOffer() // $0.05
	origSig, err := helpers.SignOffer(exPriv, offer)
	if err != nil {
		t.Fatal(err)
	}
	offer.Signature = origSig
	offer.SignatureAlgorithm = helpers.OfferSignatureAlgorithm

	acc, err := helpers.SignOfferAcceptance(agentPriv, offer, requester, idem)
	if err != nil {
		t.Fatal(err)
	}

	// Re-price to $0.01 and re-sign → a different offer_sig.
	offer.Pricing.Rate = "0.01"
	newSig, err := helpers.SignOffer(exPriv, offer)
	if err != nil {
		t.Fatal(err)
	}
	offer.Signature = newSig

	if err := helpers.VerifyOfferAcceptance(offer, requester, idem, acc, agentPub); !errors.Is(err, helpers.ErrAcceptanceSignatureInvalid) {
		t.Errorf("acceptance over the $0.05 offer must not verify against the re-priced $0.01 offer; err = %v", err)
	}
}

func TestVerifyOfferAcceptance_wrongKeyRejected(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	otherPub, _, _ := ed25519.GenerateKey(nil)
	offer, requester, idem := acceptanceFixture()
	sig, _ := helpers.SignOfferAcceptance(priv, offer, requester, idem)
	if err := helpers.VerifyOfferAcceptance(offer, requester, idem, sig, otherPub); !errors.Is(err, helpers.ErrAcceptanceSignatureInvalid) {
		t.Errorf("wrong key: expected ErrAcceptanceSignatureInvalid, got %v", err)
	}
}

func TestSignOfferAcceptance_emptyOfferSignatureRejected(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	_, requester, idem := acceptanceFixture()
	unsigned := &rampv1.Offer{OfferId: "of_1"} // no Signature
	if _, err := helpers.SignOfferAcceptance(priv, unsigned, requester, idem); err == nil {
		t.Fatal("expected error signing acceptance over an unsigned offer (empty anchor)")
	}
}
