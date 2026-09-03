package helpers

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

type requestAcceptanceVectorItem struct {
	OfferSig string `json:"offer_sig"`
	Exchange string `json:"exchange"`
}

type requestAcceptanceVector struct {
	Name            string                        `json:"name"`
	Items           []requestAcceptanceVectorItem `json:"items"`
	RequesterID     string                        `json:"requester_id"`
	RequesterDomain string                        `json:"requester_domain"`
	IdempotencyKey  string                        `json:"idempotency_key"`
	CanonicalJCS    string                        `json:"canonical_jcs"`
	SignatureHex    string                        `json:"signature_hex"`
	PubkeyB64       string                        `json:"pubkey_b64"`
	SeedHex         string                        `json:"seed_hex"`
}

func TestGenerateRequestAcceptanceVectors(t *testing.T) {
	seed, err := hex.DecodeString(acceptanceSeedHex)
	if err != nil {
		t.Fatal(err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	specs := []requestAcceptanceVector{
		{
			Name: "mixed_exchange_order",
			Items: []requestAcceptanceVectorItem{
				{OfferSig: "sig-a", Exchange: "one.example"},
				{OfferSig: "sig-b", Exchange: "two.example"},
				{OfferSig: "sig-c", Exchange: "one.example"},
			},
			RequesterID: "agent-1", RequesterDomain: "agent.example", IdempotencyKey: "idem-1",
		},
		{
			Name:        "empty_requester_domain",
			Items:       []requestAcceptanceVectorItem{{OfferSig: "sig-z", Exchange: "one.example"}},
			RequesterID: "agent-2", IdempotencyKey: "idem-2",
		},
	}
	for i := range specs {
		v := &specs[i]
		req := &rampv1.TransactionRequest{
			IdempotencyKey: v.IdempotencyKey,
			Requester:      &rampv1.Requester{Id: v.RequesterID, Domain: v.RequesterDomain},
		}
		for _, item := range v.Items {
			req.Items = append(req.Items, &rampv1.TransactionItem{Offer: &rampv1.Offer{
				Signature: item.OfferSig, Exchange: item.Exchange,
			}})
		}
		acceptance, err := SignRequestAcceptance(priv, req)
		if err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		canonical, err := CanonicalRequestAcceptanceBytes(acceptance.GetPayload())
		if err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		v.CanonicalJCS = string(canonical)
		v.SignatureHex = acceptance.GetSignature()
		v.PubkeyB64 = base64.StdEncoding.EncodeToString(pub)
		v.SeedHex = acceptanceSeedHex
	}
	doc := map[string]any{"canonicalization": "jcs", "vectors": specs}
	path := filepath.Join("testdata", "request-acceptance-vectors.json")
	if os.Getenv("RAMP_UPDATE_VECTORS") == "1" {
		writeJSON(t, path, doc)
		return
	}
	assertMatches(t, path, doc)
}
