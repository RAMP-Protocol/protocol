package core

import (
	"context"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

// The shape both discovery verbs return.
//
// A discovery call is per-URI: an agent asks about several resources at once and
// the answer comes back grouped, one group per requested URI, each either
// carrying offers or carrying a typed reason it carries none. A flat list cannot
// express that. It has nowhere to put the reason, and a refused URI vanishes
// entirely — its group holds no offer, so nothing survives to say which resource
// was refused or why.
//
// That distinction is the point of the vocabulary: "not in the catalogue" means
// give up, "scope insufficient" means acquire an entitlement and retry, and
// "content blocked" means never retry. Flattened, all three read as "found
// nothing".
//
// The fail-closed {verified, rejected} split is preserved inside each group,
// through the same Verifier — not a second verification path.

// OfferGroupResult is one requested URI's answer: the verified/rejected split for
// that URI, plus why it is empty when it is.
type OfferGroupResult struct {
	// URI is the resource this group answers for, echoed by the responder.
	URI string
	// AbsenceReason says why this URI yielded no offers. Nil means the responder
	// stated no reason — which is a legitimate answer, not an omission: where the
	// existence of a resource must itself stay hidden, a responder MAY withhold
	// the reason rather than confirm the resource exists. Distinguishing "absent"
	// from the unspecified enum value is why this is a pointer.
	AbsenceReason *rampv1.OfferAbsenceReason
	// DiscoveryMethod is how the responder found this URI, when it said.
	DiscoveryMethod *rampv1.DiscoveryMethod
	// RestrictionFilters names the restriction axes that drove a convenience
	// pre-filter, when the absence reason is a restriction filter. Advisory
	// diagnostics, not an enforcement verdict — but they tell an agent which axis
	// to vary on a retry.
	RestrictionFilters []rampv1.RestrictionKind
	// Result is the fail-closed split for this URI's offers.
	Result
}

// DiscoveryResult is what Discover and Resolve return: one group per requested
// URI, plus the whole-call refusal when the call as a whole yielded nothing.
type DiscoveryResult struct {
	// Groups is one entry per requested URI, in the order the responder returned.
	Groups []OfferGroupResult
	// AbsenceReason says why the CALL as a whole yielded nothing. It is set only
	// on that path — when any group carries offers it stays nil, and the per-URI
	// causes ride on each group instead.
	//
	// Only a Broker resolve can set it: the Exchange's own discovery response has
	// no whole-call reason field, so from Discover this is always nil and the
	// per-URI groups carry everything the responder said.
	AbsenceReason *rampv1.OfferAbsenceReason
	// Exchange is the canonical domain of the responding Exchange. Empty from a
	// Broker resolve, whose response names no single Exchange — each offer carries
	// its own issuing domain.
	Exchange string
	// RateLimit is the caller's rate-limit standing, when the responder reported
	// it, so an agent can throttle before a fan-out meets a hard limit. Nil from a
	// Broker resolve, whose message has no such field.
	RateLimit *rampv1.RateLimitInfo
}

// Verified flattens every verified offer across all groups, for a caller that
// does not care which URI an offer answers.
//
// It is a convenience over Groups, never a substitute. A URI that was REFUSED
// contributes nothing here — it has no offer to contribute — so a caller that
// reads only this cannot tell a refusal from a resource it never asked about.
// That is exactly the information Groups exists to keep.
func (d DiscoveryResult) Verified() []VerifiedOffer {
	var out []VerifiedOffer
	for _, g := range d.Groups {
		out = append(out, g.Result.Verified...)
	}
	return out
}

// Rejected flattens every rejected offer across all groups, with the reason each
// failed. The same caveat as Verified applies: a URI that yielded no offers at
// all is not a rejection and appears only in Groups.
func (d DiscoveryResult) Rejected() []RejectedOffer {
	var out []RejectedOffer
	for _, g := range d.Groups {
		out = append(out, g.Result.Rejected...)
	}
	return out
}

// SortGroups verifies every group's offers through this one Verifier and returns
// the per-URI results, preserving each group's URI and its typed reasons.
//
// One Verifier sorts every group deliberately: it is stateless apart from the
// injected resolver and clock, so a fresh one per group would mean N resolver
// caches and N clock readings for a single logical answer.
func (v Verifier) SortGroups(ctx context.Context, groups []*rampv1.OfferGroup) []OfferGroupResult {
	if len(groups) == 0 {
		return nil
	}
	out := make([]OfferGroupResult, 0, len(groups))
	for _, g := range groups {
		// A nil element is not a group with no offers — it is nothing at all, and
		// surfacing it as an empty URI would invent an answer the responder never
		// gave. Skipped rather than dereferenced, since an in-process caller can
		// build the slice by hand.
		if g == nil {
			continue
		}
		out = append(out, OfferGroupResult{
			URI: g.GetUri(),
			// The raw fields, not the getters: a getter collapses an absent
			// optional enum to its zero value, which would make "the responder
			// said nothing" indistinguishable from "unspecified".
			AbsenceReason:      g.AbsenceReason,
			DiscoveryMethod:    g.DiscoveryMethod,
			RestrictionFilters: g.GetRestrictionFilters(),
			Result:             v.Sort(ctx, g.GetOffers()),
		})
	}
	return out
}
