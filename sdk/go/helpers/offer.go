package helpers

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"google.golang.org/protobuf/proto"
)

// Offer authenticity (ADR-020 §4, ramp.proto Offer.signature). An Exchange signs
// the canonical serialization of an Offer; an agent SHOULD verify it before
// selecting or executing. Until this SDK no client verified received offers — a
// malicious Broker or MITM could steer selection with doctored terms that only
// fail later at execute. VerifyOffer is the building block the {verified,
// rejected} split (the L2 Discover/Resolve surface) is built on.

// OfferSignatureAlgorithm is the JWS alg advertised on signed offers
// (Offer.signature_algorithm). Always EdDSA for Ed25519.
const OfferSignatureAlgorithm = "EdDSA"

// ErrOfferSignatureInvalid signals offer verification failure (wrong key or a
// tampered payload — price, terms, expiry, …).
var ErrOfferSignatureInvalid = errors.New("helpers: offer signature invalid")

// SignOffer signs the canonical serialization of offer with priv and returns
// the hex-encoded Ed25519 signature for the Offer.signature field.
func SignOffer(priv ed25519.PrivateKey, offer *rampv1.Offer) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("helpers: ed25519 private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(priv))
	}
	payload, err := canonicalOfferPayload(offer)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(ed25519.Sign(priv, payload)), nil
}

// VerifyOffer verifies signatureHex against offer using pub. It checks signature
// integrity only; the expires-at-in-the-past policy ("MUST reject an offer whose
// expires_at is in the past") is enforced by the caller's {verified, rejected}
// selection layer, not here.
func VerifyOffer(offer *rampv1.Offer, signatureHex string, pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("helpers: ed25519 public key must be %d bytes, got %d", ed25519.PublicKeySize, len(pub))
	}
	sig, err := hex.DecodeString(signatureHex)
	if err != nil {
		// Malformed encoding is a signature-verification failure like any
		// other: callers branch on the sentinel (errors.Is), and a garbage
		// signature must land on the same rejected path as a forged one.
		return fmt.Errorf("%w: decode hex: %v", ErrOfferSignatureInvalid, err)
	}
	payload, err := canonicalOfferPayload(offer)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, payload, sig) {
		return ErrOfferSignatureInvalid
	}
	return nil
}

// canonicalOfferPayload is the canonical byte sequence the offer signature
// covers: the ENTIRE Offer (pricing, terms, expires_at, …) with ONLY the
// signature and signature_algorithm fields cleared, per ramp.proto Offer.signature.
//
// The canonical form is RFC 8785 JCS over canonical proto-JSON —
// JCS(protojson(offer with sig cleared)) — via canonicalSignPayload, so any
// language (Go/TS/Python) reproduces the exact signed bytes without a protobuf
// binary codec. See canonicalsign.go for the pinned proto-JSON option set.
//
// NOTE (expires_at reconciliation): the protocol spec covers expires_at so a
// relaying Broker cannot extend/shorten a signed offer's TTL. The pre-SDK
// service-internal signer additionally cleared expires_at (a stateless-reissue
// workaround); this SDK follows the protocol. The platform adopts this behavior
// when it re-pins onto the SDK — see the filed reconciliation task.
func canonicalOfferPayload(offer *rampv1.Offer) ([]byte, error) {
	if offer == nil {
		return nil, errors.New("helpers: offer is nil")
	}
	clone, ok := proto.Clone(offer).(*rampv1.Offer)
	if !ok {
		return nil, errors.New("helpers: offer clone type mismatch")
	}
	clone.Signature = ""
	clone.SignatureAlgorithm = ""
	return canonicalSignPayload(clone)
}
