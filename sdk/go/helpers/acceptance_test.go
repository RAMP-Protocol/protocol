package helpers_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"google.golang.org/protobuf/proto"
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

func TestCanonicalAcceptanceBytes_matchesSignOfferAcceptance(t *testing.T) {
	// The bytes CanonicalAcceptanceBytes returns are exactly what
	// SignOfferAcceptance signed: verifying that signature directly over them must
	// hold. This is the property a caller relies on to persist verbatim,
	// re-verifiable acceptance evidence.
	pub, priv, _ := ed25519.GenerateKey(nil)
	offer, requester, idem := acceptanceFixture()
	sigHex, err := helpers.SignOfferAcceptance(priv, offer, requester, idem)
	if err != nil {
		t.Fatal(err)
	}
	canon, err := helpers.CanonicalAcceptanceBytes(offer, requester, idem)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub, canon, sig) {
		t.Error("SignOfferAcceptance signature must verify over CanonicalAcceptanceBytes")
	}
}

// acceptanceCorpus is the cross-language acceptance fixture: the Go-emitted
// golden the TS and Python acceptance faces replay byte-for-byte. Asserting the
// exported accessor against canonical_jcs pins Go/TS/Python to one byte layout
// through the corpus that already gates the other two.
const acceptanceCorpus = "testdata/acceptance-vectors.json"

type acceptanceCorpusFile struct {
	Canonicalization string `json:"canonicalization"`
	Vectors          []struct {
		Name            string `json:"name"`
		OfferSig        string `json:"offer_sig"`
		RequesterID     string `json:"requester_id"`
		RequesterDomain string `json:"requester_domain"`
		IdempotencyKey  string `json:"idempotency_key"`
		CanonicalJCS    string `json:"canonical_jcs"`
	} `json:"vectors"`
}

func TestCanonicalAcceptanceBytes_matchesCorpus(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Clean(acceptanceCorpus))
	if err != nil {
		t.Fatalf("read acceptance corpus: %v", err)
	}
	var corpus acceptanceCorpusFile
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatalf("unmarshal acceptance corpus: %v", err)
	}
	if corpus.Canonicalization != "jcs" {
		t.Fatalf("acceptance corpus canonicalization = %q, want jcs", corpus.Canonicalization)
	}
	if len(corpus.Vectors) == 0 {
		t.Fatal("acceptance corpus has no vectors")
	}
	for _, v := range corpus.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			t.Parallel()
			offer := &rampv1.Offer{Signature: v.OfferSig}
			requester := &rampv1.Requester{Id: v.RequesterID, Domain: v.RequesterDomain}
			got, err := helpers.CanonicalAcceptanceBytes(offer, requester, v.IdempotencyKey)
			if err != nil {
				t.Fatalf("CanonicalAcceptanceBytes: %v", err)
			}
			if string(got) != v.CanonicalJCS {
				t.Errorf("canonical bytes\n got  %s\n want %s", got, v.CanonicalJCS)
			}
		})
	}
}

func TestCanonicalAcceptanceBytes_failsClosed(t *testing.T) {
	offer, requester, idem := acceptanceFixture()
	if _, err := helpers.CanonicalAcceptanceBytes(nil, requester, idem); err == nil {
		t.Error("nil offer should error")
	}
	if _, err := helpers.CanonicalAcceptanceBytes(offer, nil, idem); err == nil {
		t.Error("nil requester should error")
	}
	// An unsigned offer is an empty anchor: the acceptance would float free of any
	// concrete offer, so the bytes are refused rather than produced.
	unsigned := &rampv1.Offer{OfferId: "of_1"}
	if _, err := helpers.CanonicalAcceptanceBytes(unsigned, requester, idem); err == nil {
		t.Error("unsigned offer (empty offer signature) should error")
	}
}

func TestCanonicalAcceptanceBytes_doesNotMutateInputs(t *testing.T) {
	// The payload is built from getters onto a fresh message, so a caller can hand
	// in the live Offer/Requester it is about to persist and get them back
	// untouched. Nothing is cloned on the way in, so the whole message is compared:
	// a future refactor could reach any field, not only the four the canonical form
	// reads.
	offer, requester, idem := acceptanceFixture()
	offerBefore := proto.Clone(offer)
	requesterBefore := proto.Clone(requester)

	if _, err := helpers.CanonicalAcceptanceBytes(offer, requester, idem); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(offer, offerBefore) {
		t.Errorf("CanonicalAcceptanceBytes mutated the caller's offer\n got  %v\n want %v", offer, offerBefore)
	}
	if !proto.Equal(requester, requesterBefore) {
		t.Errorf("CanonicalAcceptanceBytes mutated the caller's requester\n got  %v\n want %v", requester, requesterBefore)
	}
}
