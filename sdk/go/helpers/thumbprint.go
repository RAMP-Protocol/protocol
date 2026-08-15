package helpers

import (
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"

	jose "github.com/go-jose/go-jose/v4"
)

// RFC 7638 JWK Thumbprint of an Ed25519 public key, base64url-no-pad encoded.
//
// The thumbprint is the RAMP agent-identity value: the
// Exchange embeds it in signed delivery URLs as the agent_id parameter, echoes
// it on TransactionResponse.agent_identity_hash, and a capable delivery edge
// recomputes it from the fetcher's presented key to enforce the binding.
//
// The canonical JWK form is fixed by RFC 7638 §3.2 for OKP keys:
//
//	{"crv":"Ed25519","kty":"OKP","x":"<base64url-nopad(pubkey)>"}
//
// members in lexicographic order (crv, kty, x), no whitespace. The thumbprint is
// base64url-no-pad(SHA-256(canonical JWK)).
//
// This implementation MUST stay byte-identical to the TS edge and Python shim
// implementations; a divergence rejects every bound fetch. All three are pinned
// to the shared vectors in testdata/thumbprint-vectors.json.

// ErrInvalidKeyLength is returned when the supplied public key is not exactly
// ed25519.PublicKeySize (32) bytes.
var ErrInvalidKeyLength = fmt.Errorf("helpers: public key must be %d bytes", ed25519.PublicKeySize)

// Thumbprint returns the RFC 7638 JWK Thumbprint of pub as a base64url-no-pad
// string. It returns ErrInvalidKeyLength when pub is not a 32-byte Ed25519
// public key.
func Thumbprint(pub ed25519.PublicKey) (string, error) {
	sum, err := ThumbprintBytes(pub)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// ThumbprintBytes returns the raw 32-byte SHA-256 digest underlying the
// thumbprint. The digest is what the transaction_log.agent_identity_hash BYTEA
// column stores; base64url-no-pad of it is the wire form.
func ThumbprintBytes(pub ed25519.PublicKey) ([32]byte, error) {
	if len(pub) != ed25519.PublicKeySize {
		return [32]byte{}, fmt.Errorf("%w: got %d", ErrInvalidKeyLength, len(pub))
	}
	// go-jose builds the canonical RFC 7638 OKP JWK (crv, kty, x in lexicographic
	// order, no whitespace) and SHA-256s it. Byte-parity with the prior hand-built
	// form — and with the TS edge and Python shim — is enforced by the
	// shared-vectors test (testdata/thumbprint-vectors.json).
	sum, err := (&jose.JSONWebKey{Key: pub}).Thumbprint(crypto.SHA256)
	if err != nil {
		return [32]byte{}, fmt.Errorf("helpers: jwk thumbprint: %w", err)
	}
	var out [32]byte
	copy(out[:], sum)
	return out, nil
}
