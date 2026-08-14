package helpers

import (
	"context"
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
// The signed bytes are pinned in two halves, both normative: the
// AgentAcceptancePayload proto message fixes the FIELD SET, and the canonical
// signing form defined on Offer.signature fixes the BYTE LAYOUT. That is what
// lets the signer (agent) and the verifier (Exchange) derive them identically;
// both go through CanonicalAcceptanceBytes, the single implementation of the pair.

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
// identity and idempotency key of the ENCLOSING execute request — in batch mode
// both come from the TransactionRequest, never from the per-item TransactionItem,
// which carries neither. The returned bytes are
// byte-identical to what SignOfferAcceptance signs and VerifyOfferAcceptance
// verifies over — persist them to re-verify an acceptance verbatim, independent of
// how the canonical form later evolves.
//
// Re-verification also needs the persisted AgentAcceptance.signature and the signer's
// trusted public key: these bytes are the signed message, necessary but not by
// themselves sufficient. A passing signature proves only that the key holder signed
// THESE bytes, so a caller weighing them as evidence must also parse them and match
// their content against the transaction in question.
//
// The canonical form is RFC 8785 JCS over canonical proto-JSON —
// JCS(protojson(AgentAcceptancePayload)) — the same definition the offer signature
// uses, stated normatively on Offer.signature in ramp.proto: snake_case proto field
// names, enums as name strings, unpopulated fields omitted. AgentAcceptancePayload
// carries no signature fields, so the clear-then-render step reduces to a plain
// render. Any language (Go/TS/Python) reproduces the exact bytes from that
// definition, without a protobuf binary codec.
//
// The payload is built here from the four scalars rather than taken from the caller,
// so it cannot carry the unknown fields CanonicalOfferBytes has to refuse; only the
// values read off the offer and requester reach the signed bytes.
//
// Unpopulated fields are OMITTED before JCS — EVERY empty string field, not just the
// domain: the bytes for an empty requester id are not the bytes for any populated
// one. A port that assembles this object by hand instead of rendering the proto must
// reproduce that omission per field, or it signs bytes this function never produces.
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

// SignOfferAcceptanceWith signs the canonical acceptance payload through an
// injected Signer, so an application whose key lives in a KMS or an HSM can
// produce an acceptance without ever handing the key over. It is the form the
// SDK's own client uses; SignOfferAcceptance above is the direct-key form for a
// caller that already holds the bytes. Both cover the identical payload from
// CanonicalAcceptanceBytes, so the two are interchangeable on the wire.
//
// The acceptance is signed with the same key that signs the caller's requests:
// its thumbprint becomes the delivery URL's agent_id, which is what the edge
// later requires proof of possession of.
func SignOfferAcceptanceWith(ctx context.Context, signer Signer, offer *rampv1.Offer, requester *rampv1.Requester, idempotencyKey string) (string, error) {
	if signer == nil {
		return "", errors.New("helpers: acceptance signer is nil")
	}
	if signer.Algorithm() != AlgEd25519 {
		return "", fmt.Errorf("%w: offer acceptance requires %q, signer offers %q",
			ErrUnsupportedAlgorithm, AlgEd25519, signer.Algorithm())
	}
	payload, err := CanonicalAcceptanceBytes(offer, requester, idempotencyKey)
	if err != nil {
		return "", err
	}
	sig, err := signer.Sign(ctx, payload)
	if err != nil {
		return "", fmt.Errorf("helpers: sign offer acceptance: %w", err)
	}
	return hex.EncodeToString(sig), nil
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
