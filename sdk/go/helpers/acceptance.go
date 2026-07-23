package helpers

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

// Agent offer-acceptance (ramp.proto AgentAcceptance). An agent
// signs a DETACHED, content-bound acceptance over an accepted Offer; the
// Exchange verifies it to bind the agent to the transaction (and binds the
// delivery URL to the agent's key via its RFC 7638 thumbprint). Unlike the
// transport RFC 9421 request signature, the acceptance is topology-independent:
// it stays valid no matter how many brokers relay the request, because it covers
// the offer + requester + idempotency, not the HTTP envelope.
//
// The signed bytes are pinned by the AgentAcceptancePayload proto message so the
// signer (agent) and the verifier (Exchange) derive them identically; both go
// through CanonicalAcceptanceBytes, the single source of the byte layout.

// AcceptanceSignatureAlgorithm is the alg advertised on AgentAcceptance.
// Always EdDSA for Ed25519.
const AcceptanceSignatureAlgorithm = "EdDSA"

// ErrAcceptanceSignatureInvalid signals offer-acceptance verification failure —
// a wrong key, or a tampered binding (offer signature, requester, or
// idempotency key).
var ErrAcceptanceSignatureInvalid = errors.New("helpers: offer-acceptance signature invalid")

// CanonicalAcceptanceBytes returns the exact canonical byte sequence an agent's
// offer acceptance covers: the accepted Offer.signature (which transitively binds
// the offer's pricing, terms, expiry, and issuing Exchange), plus the requester
// identity and the transaction's idempotency key. The returned bytes are
// byte-identical to what SignOfferAcceptance signs and VerifyOfferAcceptance
// verifies over — persist them to re-verify an acceptance verbatim, independent of
// how the canonical form later evolves. Re-verification also needs the persisted
// AgentAcceptance.signature and the signer's trusted public key: these bytes are the
// signed message, necessary but not by themselves sufficient.
//
// The canonical form is RFC 8785 JCS over canonical proto-JSON —
// JCS(protojson(AgentAcceptancePayload)) — via canonicalSignPayload, the same
// primitive the offer signature uses, so any language (Go/TS/Python) reproduces the
// exact signed bytes without a protobuf binary codec. See canonicalsign.go for the
// pinned proto-JSON option set.
//
// Unpopulated fields are OMITTED before JCS, so an empty requester domain is absent
// from the object entirely rather than emitted as "": the bytes for an empty domain
// are not the bytes for any populated one.
//
// Fails closed on a nil offer, a nil requester, or an unsigned offer (empty
// Offer.signature) — an empty anchor would let the acceptance float free of any
// concrete offer.
func CanonicalAcceptanceBytes(offer *rampv1.Offer, requester *rampv1.Requester, idempotencyKey string) ([]byte, error) {
	if offer == nil {
		return nil, errors.New("helpers: offer is nil")
	}
	if requester == nil {
		return nil, errors.New("helpers: requester is nil")
	}
	if offer.GetSignature() == "" {
		return nil, errors.New("helpers: cannot accept an unsigned offer (empty offer signature)")
	}
	payload := &rampv1.AgentAcceptancePayload{
		OfferSig:        offer.GetSignature(),
		RequesterId:     requester.GetId(),
		RequesterDomain: requester.GetDomain(),
		IdempotencyKey:  idempotencyKey,
	}
	return canonicalSignPayload(payload)
}

// SignOfferAcceptance signs the canonical acceptance payload for the accepted
// offer with priv and returns the hex-encoded Ed25519 signature for the
// AgentAcceptance.signature field. requester and idempotencyKey come from the
// enclosing execute request.
func SignOfferAcceptance(priv ed25519.PrivateKey, offer *rampv1.Offer, requester *rampv1.Requester, idempotencyKey string) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("helpers: ed25519 private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(priv))
	}
	payload, err := CanonicalAcceptanceBytes(offer, requester, idempotencyKey)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(ed25519.Sign(priv, payload)), nil
}

// VerifyOfferAcceptance verifies signatureHex (an AgentAcceptance.signature)
// against the canonical acceptance payload for the offer, using pub. It returns
// ErrAcceptanceSignatureInvalid on any mismatch (wrong key or tampered binding).
func VerifyOfferAcceptance(offer *rampv1.Offer, requester *rampv1.Requester, idempotencyKey, signatureHex string, pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("helpers: ed25519 public key must be %d bytes, got %d", ed25519.PublicKeySize, len(pub))
	}
	sig, err := hex.DecodeString(signatureHex)
	if err != nil {
		return fmt.Errorf("helpers: decode acceptance signature: %w", err)
	}
	payload, err := CanonicalAcceptanceBytes(offer, requester, idempotencyKey)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, payload, sig) {
		return ErrAcceptanceSignatureInvalid
	}
	return nil
}
