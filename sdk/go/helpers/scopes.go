package helpers

import (
	"sort"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

// Scopes / entitlements.
// The subscriptions/entitlements a requester holds are a SUPPLIED credential:
// the application hands the SDK what it holds and the SDK plumbs it into the
// request (Requester.scopes / Delegation.scopes). The caller never constructs an
// entitlement proof by hand. Today the Exchange trusts what is supplied; when
// JWT/biscuit issuance lands, only the verification under the surface changes —
// these helpers do not move (the change is additive).
//
// NOTE: the api-doc's WithSubscription has no request-side field in the current
// proto — subscription selection happens by choosing an Offer that carries a
// subscription_id, not by a requester-supplied request field. This is plumbed at
// offer-selection time, not here. Only scope plumbing is an L1 concern today.

// NormalizeScopes returns scopes with empty entries dropped, duplicates removed,
// and a stable (sorted) order — so two callers supplying the same set produce
// identical bytes on the wire.
func NormalizeScopes(scopes []string) []string {
	if len(scopes) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(scopes))
	out := make([]string, 0, len(scopes))
	for _, s := range scopes {
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	return out
}

// ApplyScopes sets the requester's held scopes (normalized). It is how the caller
// supplies the entitlements it holds for a discover/resolve call.
func ApplyScopes(r *rampv1.Requester, scopes ...string) {
	if r == nil {
		return
	}
	r.Scopes = NormalizeScopes(scopes)
}

// ScopesSubset reports whether every scope in sub is present in super. It is the
// delegation-attenuation rule (Delegation.scopes MUST be a subset of the
// principal's granted scopes): use it to validate a delegation before relying on
// it, so an over-broad delegation is caught at the SDK boundary.
func ScopesSubset(sub, super []string) bool {
	set := make(map[string]struct{}, len(super))
	for _, s := range super {
		set[s] = struct{}{}
	}
	for _, s := range sub {
		if _, ok := set[s]; !ok {
			return false
		}
	}
	return true
}
