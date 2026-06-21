package helpers

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

// ErrOfferExpired signals that a presented offer is not usable on freshness
// grounds: its signed expires_at is in the past, or it carries no expires_at at
// all (see VerifyPresentedOffer's fail-closed policy). Distinct from
// ErrOfferSignatureInvalid — the signature checked out, the offer is just stale.
var ErrOfferExpired = errors.New("helpers: offer expired")

// VerifyPresentedOffer is the stateless {verified, rejected} primitive for a
// reflected Offer (RAMP-103): the agent presents the WHOLE signed Offer and the
// verifier checks it against its own key over the exact presented bytes — no
// reconstruct-from-catalog. It returns nil only when BOTH hold, in this order:
//
//  1. offer.signature is a valid Ed25519 signature over the canonical Offer
//     (expires_at included) under exchangePub — else ErrOfferSignatureInvalid.
//  2. the signed expires_at is at or after now — else ErrOfferExpired.
//
// Signature is checked first so freshness never leaks for a tampered offer.
// Freshness uses the injected now (never the wall clock); expires_at is
// inclusive, so now == expires_at is still valid. An offer with NO expires_at is
// rejected fail-closed: RAMP offers are minted at discovery as now+TTL, so a
// missing expiry is a forever-token and unsafe to honor.
func VerifyPresentedOffer(offer *rampv1.Offer, exchangePub ed25519.PublicKey, now time.Time) error {
	if offer == nil {
		return errors.New("helpers: offer is nil")
	}
	if err := VerifyOffer(offer, offer.GetSignature(), exchangePub); err != nil {
		return err
	}
	ts := offer.GetExpiresAt()
	if ts == nil {
		return fmt.Errorf("%w: offer carries no expires_at", ErrOfferExpired)
	}
	if expiry := ts.AsTime(); expiry.Before(now) {
		return fmt.Errorf("%w: expires_at %s is before now %s",
			ErrOfferExpired, expiry.Format(time.RFC3339), now.Format(time.RFC3339))
	}
	return nil
}
