package core

import (
	"context"
	"errors"
	"time"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// Mode selects offer-verification strictness. Strict (the default) is fail-closed:
// an offer that does not verify against the exchange's offer-signing key lands in
// Rejected and cannot reach Execute. Off is the single, loud, named opt-out — it
// surfaces every offer as Verified WITHOUT checking a signature.
type Mode int

const (
	// Strict is the fail-closed default: every returned offer is verified and an
	// unverifiable one is rejected, never silently promoted.
	Strict Mode = iota
	// Off disables offer verification entirely — a loud, explicit opt-out. Offers
	// are surfaced as Verified with no signature check. Named so an audit of the
	// call site shows the guarantee was deliberately waived.
	Off
)

// ErrOfferExpired signals an offer whose expires_at is in the past. Verification
// is fail-closed on freshness as well as signature: an expired offer is rejected
// even if its signature is genuine (ADR-020 §4 "verify everything").
var ErrOfferExpired = errors.New("ramp: offer expires_at is in the past")

// VerifiedOffer wraps an Offer that has passed the SDK's fail-closed verification
// (genuine exchange signature, not expired) — OR was surfaced under
// WithVerification(Off) / RejectedOffer.Unsafe(). Its wrapped field is UNEXPORTED
// and it has no exported constructor, so an application cannot forge one with a
// composite literal: the only way to obtain a VerifiedOffer is the SDK verify path
// or the explicit .Unsafe() escape. That is what makes Client.Execute(ctx,
// VerifiedOffer) a real COMPILE guard rather than a runtime check a caller can
// forget (ADR-020 §4, ramp-sdk-api.md compile-time guard).
type VerifiedOffer struct {
	offer *rampv1.Offer
}

// Offer returns the wrapped, verified *rampv1.Offer for read access (id, pricing,
// terms). It is a getter, not a constructor — reading a VerifiedOffer is fine;
// only minting one is gated.
func (v VerifiedOffer) Offer() *rampv1.Offer { return v.offer }

// RejectedOffer is an offer the Verifier could NOT accept: the wrapped Offer plus
// the Reason it failed (signature invalid, expired, no resolvable key). It is
// VISIBLE — the application learns which offers failed and why — but not directly
// executable. Acting on it requires the explicit .Unsafe() escape.
type RejectedOffer struct {
	Offer  *rampv1.Offer
	Reason error
}

// Unsafe converts a RejectedOffer into an executable VerifiedOffer. It is the
// SINGLE, explicit, audit-visible escape hatch: without it, Execute(ctx, rejected)
// does not compile. Named "Unsafe" so a reviewer sees the guarantee was bypassed
// at the exact call site.
func (r RejectedOffer) Unsafe() VerifiedOffer { return VerifiedOffer{offer: r.Offer} }

// Result is the fail-closed {verified, rejected} contract every discover/resolve
// call returns. Neither list is silently dropped: a caller can act on Verified and
// inspect Rejected (count + reason). It is the canonical cross-language shape
// (ramp-sdk-api.md); Go/TS add the VerifiedOffer compile guard on top.
type Result struct {
	Verified []VerifiedOffer
	Rejected []RejectedOffer
}

// Verifier runs the per-offer authenticity + freshness check over the L1
// helpers.VerifyOffer primitive, keyed through the injected KeyResolver (the same
// interface the request-signature face resolves through). It is PURE apart from
// the resolver IO — no state, no clock beyond the injected now. It is transport-
// neutral: a plain net/http or grpc-go caller composes it directly, without any
// Connect binding.
type Verifier struct {
	mode     Mode
	resolver helpers.KeyResolver
	now      func() time.Time
}

// NewVerifier builds a Verifier from the injected verification mode, offer
// KeyResolver, and clock. It is the transport-neutral constructor the Connect
// client composes (and any non-Connect consumer can use directly): the Verifier's
// unexported fields are not composite-literal-constructible across packages, so
// this constructor is the sole way to build one outside package core.
func NewVerifier(mode Mode, resolver helpers.KeyResolver, now func() time.Time) Verifier {
	return Verifier{mode: mode, resolver: resolver, now: now}
}

// Sort splits offers into verified and rejected per the configured mode. Under Off
// every offer is surfaced verified with no check. Under Strict each offer is
// verified against its resolved exchange key and its expiry — a failure of either
// lands it in Rejected with the reason.
func (v Verifier) Sort(ctx context.Context, offers []*rampv1.Offer) Result {
	res := Result{}
	for _, off := range offers {
		if v.mode == Off {
			res.Verified = append(res.Verified, VerifiedOffer{offer: off})
			continue
		}
		if err := v.check(ctx, off); err != nil {
			res.Rejected = append(res.Rejected, RejectedOffer{Offer: off, Reason: err})
			continue
		}
		res.Verified = append(res.Verified, VerifiedOffer{offer: off})
	}
	return res
}

// check verifies a single offer: resolve the exchange offer-signing key, verify the
// signature, and enforce the not-in-the-past expiry. Any step failing rejects the
// offer (fail-closed) — including an unresolvable key, so an offer the client
// cannot key is rejected under Strict rather than trusted.
func (v Verifier) check(ctx context.Context, off *rampv1.Offer) error {
	pub, err := v.resolver.Resolve(ctx, off.GetExchange())
	if err != nil {
		return err
	}
	if err := helpers.VerifyOffer(off, off.GetSignature(), pub); err != nil {
		return err
	}
	if expired(off, v.now()) {
		return ErrOfferExpired
	}
	return nil
}

// expired reports whether off carries an expires_at strictly in the past.
func expired(off *rampv1.Offer, now time.Time) bool {
	ts := off.GetExpiresAt()
	if ts == nil {
		return false
	}
	return ts.AsTime().Before(now)
}
