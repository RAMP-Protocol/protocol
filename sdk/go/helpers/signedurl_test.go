package helpers_test

import (
	"crypto/ed25519"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

func TestSignURL_roundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	exp := time.Unix(1700000300, 0)
	su, err := helpers.SignURLEd25519(priv, "ex.v1", "https://cdn.example/a?doc=1", "", exp)
	if err != nil {
		t.Fatal(err)
	}
	v, err := helpers.VerifyURLEd25519(su.URL, pub, time.Unix(1700000100, 0))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if v.KeyID != "ex.v1" || !v.Expiry.Equal(exp) || v.Bound() {
		t.Errorf("verified = %+v", v)
	}
	if len(su.Hash) != 32 {
		t.Errorf("hash len = %d", len(su.Hash))
	}
}

func TestSignURL_agentBoundPoP(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	agentPub, _, _ := ed25519.GenerateKey(nil)
	agentTP, _ := helpers.Thumbprint(agentPub)

	su, err := helpers.SignURLEd25519(priv, "ex.v1", "https://cdn.example/a", agentTP, time.Unix(1700000300, 0))
	if err != nil {
		t.Fatal(err)
	}
	v, err := helpers.VerifyURLEd25519(su.URL, pub, time.Unix(1700000100, 0))
	if err != nil {
		t.Fatal(err)
	}
	if !v.Bound() || v.AgentID != agentTP {
		t.Fatalf("expected bound URL with agent_id=%s, got %+v", agentTP, v)
	}
	// Correct key passes PoP.
	if err := v.CheckProofOfPossession(agentPub); err != nil {
		t.Errorf("PoP with bound key: %v", err)
	}
	// A different key fails PoP.
	otherPub, _, _ := ed25519.GenerateKey(nil)
	if err := v.CheckProofOfPossession(otherPub); !errors.Is(err, helpers.ErrProofOfPossessionMismatch) {
		t.Errorf("PoP mismatch err = %v", err)
	}
}

func TestVerifyURL_bearerPoP(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	su, _ := helpers.SignURLEd25519(priv, "ex.v1", "https://cdn.example/a", "", time.Unix(1700000300, 0))
	v, _ := helpers.VerifyURLEd25519(su.URL, pub, time.Unix(1700000100, 0))
	somePub, _, _ := ed25519.GenerateKey(nil)
	if err := v.CheckProofOfPossession(somePub); !errors.Is(err, helpers.ErrURLNotAgentBound) {
		t.Errorf("bearer PoP err = %v, want ErrURLNotAgentBound", err)
	}
}

func TestVerifyURL_expired(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	su, _ := helpers.SignURLEd25519(priv, "", "https://cdn.example/a", "", time.Unix(1700000300, 0))
	_, err := helpers.VerifyURLEd25519(su.URL, pub, time.Unix(1700000301, 0))
	if !errors.Is(err, helpers.ErrURLExpired) {
		t.Errorf("err = %v, want ErrURLExpired", err)
	}
}

func TestVerifyURL_tamperedAgentID(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	su, _ := helpers.SignURLEd25519(priv, "", "https://cdn.example/a", "AAAA", time.Unix(1700000300, 0))
	// Tamper the agent_id after signing.
	parsed, _ := url.Parse(su.URL)
	q := parsed.Query()
	q.Set(helpers.AgentIDParam, "BBBB")
	parsed.RawQuery = q.Encode()
	_, err := helpers.VerifyURLEd25519(parsed.String(), pub, time.Unix(1700000100, 0))
	if !errors.Is(err, helpers.ErrURLSignatureInvalid) {
		t.Errorf("err = %v, want ErrURLSignatureInvalid", err)
	}
}

func TestVerifyURL_wrongKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	other, _, _ := ed25519.GenerateKey(nil)
	su, _ := helpers.SignURLEd25519(priv, "", "https://cdn.example/a", "", time.Unix(1700000300, 0))
	if _, err := helpers.VerifyURLEd25519(su.URL, other, time.Unix(1700000100, 0)); !errors.Is(err, helpers.ErrURLSignatureInvalid) {
		t.Errorf("err = %v, want ErrURLSignatureInvalid", err)
	}
}

func TestVerifyURL_missingSig(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	if _, err := helpers.VerifyURLEd25519("https://cdn.example/a?exp=1700000300", pub, time.Unix(1, 0)); !errors.Is(err, helpers.ErrURLMissingSignature) {
		t.Errorf("err = %v, want ErrURLMissingSignature", err)
	}
}
