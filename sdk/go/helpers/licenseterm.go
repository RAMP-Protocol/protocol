package helpers

import (
	"errors"
	"fmt"

	protovalidate "buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/gen/go/vocab/functiontokens"
	"github.com/RAMP-Protocol/protocol/gen/go/vocab/geographytokens"
	"github.com/RAMP-Protocol/protocol/gen/go/vocab/pricingunits"
	"github.com/RAMP-Protocol/protocol/gen/go/vocab/quotametrics"
	"github.com/RAMP-Protocol/protocol/gen/go/vocab/usertypes"
)

// License-term canonicalisation and the ingest-tier checks (ADR-014; the
// CatalogService contract in ramp.proto).
//
// A pushed entry passes two tiers at the Exchange. The wire tier is
// protovalidate — the ResourceEntry envelope rules and the LicenseTerm
// structural and cross-field rules, applied to the request as received. The
// ingest tier runs over the CANONICALISED terms: restriction tokens are folded
// and alias-resolved to their registered form, then a bare Pricing.unit or
// Quota.metric that is not a registered token is rejected, as is a restriction
// whose permitted and prohibited lists name one token once folded, while an
// unregistered restriction token and an OBLIGATION_KIND_OTHER obligation
// without detail are accepted with a warning that reaches
// PushResourcesResponse.warnings.
//
// This file is the ingest tier, lifted out of the reference Exchange so a
// publisher can run the same checks before sending. It passes the L1 inclusion
// test on all three counts: the rules are protocol-defined (the token registry
// and its aliases are authored in the proto and generated into gen/go/vocab),
// every face is a pure function over one message, and the same code has more
// than one consumer — the Exchange at ingest, a publisher pre-checking a feed,
// and the reference catalog CLI. The Exchange's own run of these checks is the
// deciding one; a client-side verdict is advice about what that run will say.
//
// Folding is ASCII-only, and only RFC 8259 whitespace is trimmed. Several
// non-ASCII code points lowercase or NFKC-fold INTO ASCII letters (U+212A KELVIN
// SIGN becomes "k"), so a Unicode fold would turn a homograph into a registered
// token — the same reason the recipient-addressing rule in the proto header
// forbids a Unicode pre-pass. A non-ASCII byte therefore passes through a fold
// unchanged, and a token padded with a non-breaking space is not trimmed. The
// three SDKs are held to one answer by licenseterm-vectors.json.

// Rule ids of the ingest-tier checks. They follow the descriptor's CEL-id
// convention — the owning message in snake_case, then the rule — and never
// collide with a CEL id, which a conformance guard asserts.
const (
	// RulePricingUnitRegistered rejects a bare (non-namespaced) Pricing.unit
	// that is not a registered metering token.
	RulePricingUnitRegistered = "pricing.unit.registered"
	// RuleQuotaMetricRegistered rejects a bare Quota.metric that is not a
	// registered quota token.
	RuleQuotaMetricRegistered = "quota.metric.registered"
	// RuleRestrictionCanonicalDisjoint rejects a restriction whose permitted and
	// prohibited lists name the same token once both are canonicalised. The wire
	// tier's rule compares the tokens AS WRITTEN, so two accepted spellings of one
	// token — an alias beside its registered form, or two spellings differing only
	// in ASCII case — pass it and collide only after the fold. This is that
	// property read on the values the fold produces.
	RuleRestrictionCanonicalDisjoint = "restriction.canonical_disjoint"
	// RuleRestrictionTokenRegistered warns about a bare restriction token that is
	// not registered on its axis. The term is accepted: the restriction
	// vocabulary is open and forward-compatible, and under scope-only projection
	// the Exchange never evaluates restrictions, so an unknown token can only
	// warrant a flag, never gate access.
	RuleRestrictionTokenRegistered = "restriction.token.registered"
	// RuleObligationOtherRequiresDetail warns about an OBLIGATION_KIND_OTHER
	// obligation carrying no detail — descriptive, not fatal.
	RuleObligationOtherRequiresDetail = "obligation.other.requires_detail"
)

// RuleViolation is one reason an entry or a term would be refused. Rule is the
// rule id (an ingest-tier id above, or the protovalidate rule id of a wire-tier
// violation); Path is the snake_case proto-JSON field path relative to the
// message that was checked, e.g. "terms[2].pricing.unit"; Token is the
// offending value when the rule is about one token, else empty; Message is the
// human-readable reason.
//
// Message is identical across the three SDKs for an INGEST-tier violation, which
// is SDK-owned code in each and whose strings are what an Exchange puts in
// warnings[]. It is not, and cannot be, for a wire-tier one: there the reason
// comes from each language's own validator — protovalidate, Zod, Pydantic — three
// engines with three vocabularies. That is why the shared corpus records a
// wire-tier violation as a boolean and an ingest-tier one as a whole finding.
type RuleViolation struct {
	Rule    string
	Path    string
	Token   string
	Message string
}

// Error implements error so ValidateLicenseTerm can return a violation as its
// error while callers still branch on the typed fields via errors.As.
func (v *RuleViolation) Error() string { return v.Message }

// RuleWarning is one non-fatal finding. Its Message is the exact string the
// Exchange puts in PushResourcesResponse.warnings for the same finding.
type RuleWarning struct {
	Rule    string
	Path    string
	Token   string
	Message string
}

// EntryVerdict is what ValidateResourceEntry reports: every reason the entry
// would be refused, wire tier first, then the ingest tier per term, followed by
// the warnings the accepted terms would carry.
type EntryVerdict struct {
	Violations []RuleViolation
	Warnings   []RuleWarning
}

// OK reports whether the entry carries no violation. Warnings do not fail it.
func (v EntryVerdict) OK() bool { return len(v.Violations) == 0 }

// CanonicalRestrictionToken returns the canonical form of a restriction token on
// an axis: RFC 8259 whitespace trimmed, ASCII case folded (lower for FUNCTION and
// USER_TYPE, upper for GEOGRAPHY) and, where the axis authors aliases, the alias
// resolved to its registered token. OTHER and any unknown axis carry custom,
// registry-less tokens and are returned unchanged. Applying it twice is a fixed
// point, which is what makes NormalizeLicenseTerm idempotent.
func CanonicalRestrictionToken(kind rampv1.RestrictionKind, token string) string {
	switch kind {
	case rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION:
		return functiontokens.Canonical(asciiLower(trimJSONWhitespace(token)))
	case rampv1.RestrictionKind_RESTRICTION_KIND_USER_TYPE:
		return usertypes.Canonical(asciiLower(trimJSONWhitespace(token)))
	case rampv1.RestrictionKind_RESTRICTION_KIND_GEOGRAPHY:
		return geographytokens.Canonical(asciiUpper(trimJSONWhitespace(token)))
	default:
		return token
	}
}

// KnownRestrictionToken reports whether an already-canonical token is
// registered on its axis. GEOGRAPHY registers only the non-ISO specials and
// admits any two-uppercase-letter ISO 3166-1 alpha-2 code structurally; OTHER
// and any unknown axis carry no registry and are never known.
func KnownRestrictionToken(kind rampv1.RestrictionKind, token string) bool {
	switch kind {
	case rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION:
		return functiontokens.IsRegistered(token)
	case rampv1.RestrictionKind_RESTRICTION_KIND_USER_TYPE:
		return usertypes.IsRegistered(token)
	case rampv1.RestrictionKind_RESTRICTION_KIND_GEOGRAPHY:
		return geographytokens.IsRegistered(token) || isISOAlpha2(token)
	default:
		return false
	}
}

// NormalizeLicenseTerm rewrites the term's restriction tokens to their canonical
// form in place, on every axis that carries a canonicalisation rule. It touches
// nothing else — Pricing.unit and Quota.metric are exact registry values, scopes
// are matched verbatim — and is nil-safe and idempotent. Run it before
// ValidateLicenseTerm, whose checks read canonical tokens — all but the
// disjointness check, which folds what it compares and so reaches the same
// verdict on either form.
func NormalizeLicenseTerm(term *rampv1.LicenseTerm) {
	for _, r := range term.GetRestrictions() {
		kind := r.GetKind()
		if !hasCanonicalRule(kind) {
			continue
		}
		for i, tok := range r.Permitted {
			r.Permitted[i] = CanonicalRestrictionToken(kind, tok)
		}
		for i, tok := range r.Prohibited {
			r.Prohibited[i] = CanonicalRestrictionToken(kind, tok)
		}
	}
}

// NormalizeResourceEntry applies NormalizeLicenseTerm to every term of the
// entry, in place. Nil-safe.
func NormalizeResourceEntry(entry *rampv1.ResourceEntry) {
	for _, t := range entry.GetTerms() {
		NormalizeLicenseTerm(t)
	}
}

// ValidateLicenseTerm runs the ingest-tier checks over one term. It returns a
// *RuleViolation as the error for a hard reject, in a fixed order: a bare
// Pricing.unit that is not a registered token, then the first offending quota
// metric, then the first restriction whose permitted and prohibited lists name
// one token once canonicalised. When the term is accepted it returns the
// warnings it would carry: one per unregistered bare restriction token, in
// restriction order with permitted before prohibited, then one per
// OBLIGATION_KIND_OTHER obligation without detail. Empty and vendor-namespaced
// (containing ":") tokens are never membership-checked.
//
// Every check but one reads the term as ALREADY CANONICAL, which is what
// NormalizeLicenseTerm produces. The exception is the disjointness check, which
// folds what it compares: it exists because a rule that compares spellings
// answers a question about tokens, so a rule written to close that gap must not
// in turn assume its own caller folded first.
//
// The wire tier is not re-run here: token format, PER_UNIT⇒unit, FREE⇒rate 0,
// one restriction per kind and the presence rules are protovalidate's, and
// ValidateResourceEntry composes the two tiers. Disjointness is the one property
// BOTH tiers assert, over different values — permitted∩prohibited over the tokens
// as written, and the rule below over the tokens the fold produces — so a term
// the first clears can still fail the second, and a term that fails both is
// reported by both.
func ValidateLicenseTerm(term *rampv1.LicenseTerm) ([]RuleWarning, error) {
	if unit := term.GetPricing().GetUnit(); bareUnregistered(unit, pricingunits.IsRegistered) {
		return nil, &RuleViolation{
			Rule:    RulePricingUnitRegistered,
			Path:    "pricing.unit",
			Token:   unit,
			Message: fmt.Sprintf("pricing unit \"%s\" is not a registered metering token", unit),
		}
	}
	for i, q := range term.GetQuotas() {
		if metric := q.GetMetric(); bareUnregistered(metric, quotametrics.IsRegistered) {
			return nil, &RuleViolation{
				Rule:    RuleQuotaMetricRegistered,
				Path:    fmt.Sprintf("quotas[%d].metric", i),
				Token:   metric,
				Message: fmt.Sprintf("quota metric \"%s\" is not a registered quota token", metric),
			}
		}
	}
	for i, r := range term.GetRestrictions() {
		if v := canonicalDisjointViolation(i, r); v != nil {
			return nil, v
		}
	}
	var warnings []RuleWarning
	for i, r := range term.GetRestrictions() {
		kind := r.GetKind()
		for j, tok := range r.GetPermitted() {
			if w, ok := restrictionTokenWarning(kind, tok, fmt.Sprintf("restrictions[%d].permitted[%d]", i, j)); ok {
				warnings = append(warnings, w)
			}
		}
		for j, tok := range r.GetProhibited() {
			if w, ok := restrictionTokenWarning(kind, tok, fmt.Sprintf("restrictions[%d].prohibited[%d]", i, j)); ok {
				warnings = append(warnings, w)
			}
		}
	}
	for i, o := range term.GetObligations() {
		if o.GetKind() == rampv1.ObligationKind_OBLIGATION_KIND_OTHER && o.GetDetail() == "" {
			warnings = append(warnings, RuleWarning{
				Rule:    RuleObligationOtherRequiresDetail,
				Path:    fmt.Sprintf("obligations[%d].detail", i),
				Message: "obligation of kind OTHER has no detail (term accepted)",
			})
		}
	}
	return warnings, nil
}

// ValidateResourceEntry reports the verdict the Exchange reaches for one entry,
// both tiers composed in the Exchange's order: the wire tier over the entry
// exactly as given (protovalidate, which recurses into the terms), then the
// ingest tier over a canonicalised COPY of the terms — the entry passed in is
// never modified. The Exchange stops at the first tier that fails; this face
// reports both so a publisher fixes everything in one round. Paths are relative
// to the entry ("terms[2].pricing.unit").
func ValidateResourceEntry(entry *rampv1.ResourceEntry) EntryVerdict {
	var verdict EntryVerdict
	if entry == nil {
		verdict.Violations = append(verdict.Violations, RuleViolation{Rule: "required", Message: "entry is nil"})
		return verdict
	}
	if err := Validate(entry); err != nil {
		var verr *protovalidate.ValidationError
		if errors.As(err, &verr) {
			for _, vi := range verr.Violations {
				verdict.Violations = append(verdict.Violations, RuleViolation{
					Rule:    vi.Proto.GetRuleId(),
					Path:    protovalidate.FieldPathString(vi.Proto.GetField()),
					Message: vi.Proto.GetMessage(),
				})
			}
		} else {
			verdict.Violations = append(verdict.Violations, RuleViolation{Rule: "validator", Message: err.Error()})
		}
	}
	normalized, ok := proto.Clone(entry).(*rampv1.ResourceEntry)
	if !ok {
		verdict.Violations = append(verdict.Violations, RuleViolation{Rule: "validator", Message: "entry could not be cloned"})
		return verdict
	}
	NormalizeResourceEntry(normalized)
	for i, term := range normalized.GetTerms() {
		prefix := fmt.Sprintf("terms[%d].", i)
		warnings, err := ValidateLicenseTerm(term)
		if err != nil {
			var rv *RuleViolation
			if errors.As(err, &rv) {
				v := *rv
				v.Path = prefix + v.Path
				verdict.Violations = append(verdict.Violations, v)
			}
			continue
		}
		for _, w := range warnings {
			w.Path = prefix + w.Path
			verdict.Warnings = append(verdict.Warnings, w)
		}
	}
	return verdict
}

// canonicalDisjointViolation returns the violation for the first permitted token
// of r whose canonical form is also the canonical form of one of its prohibited
// tokens, or nil when the two lists name no token in common. The permitted list
// decides the order, so a restriction carrying several collisions always answers
// the same way.
//
// It canonicalises what it compares rather than trusting r to have been
// normalised, and it runs on EVERY axis. On an axis with no canonicalisation
// rule the fold returns the token unchanged, so the check degenerates to plain
// equality — which is what it must do on a server that never asked for the wire
// tier, where this is the only tier a pushed term meets.
//
// The finding names the CANONICAL token and not the spellings that produced it.
// Naming the spellings would make the message depend on whether the caller had
// folded first — the Exchange has, a direct caller has not — and the message is
// wire-visible and pinned byte-for-byte across the three SDKs. Path locates the
// permitted element; the prohibited one is the entry that folds to the same token.
//
// The prohibited list is folded once into a set, so the cost is one fold per
// token rather than one per pair: both lists are capped at 64, and a pairwise
// walk would fold four thousand times per restriction.
func canonicalDisjointViolation(i int, r *rampv1.Restriction) *RuleViolation {
	prohibited := r.GetProhibited()
	permitted := r.GetPermitted()
	if len(prohibited) == 0 || len(permitted) == 0 {
		return nil
	}
	kind := r.GetKind()
	banned := make(map[string]struct{}, len(prohibited))
	for _, tok := range prohibited {
		banned[CanonicalRestrictionToken(kind, tok)] = struct{}{}
	}
	for j, tok := range permitted {
		canon := CanonicalRestrictionToken(kind, tok)
		if _, ok := banned[canon]; !ok {
			continue
		}
		return &RuleViolation{
			Rule:    RuleRestrictionCanonicalDisjoint,
			Path:    fmt.Sprintf("restrictions[%d].permitted[%d]", i, j),
			Token:   canon,
			Message: fmt.Sprintf("restriction token \"%s\" is both permitted and prohibited after canonicalisation", canon),
		}
	}
	return nil
}

// restrictionTokenWarning returns the warning for one restriction token, or
// false when the token needs none (empty, vendor-namespaced, or registered).
func restrictionTokenWarning(kind rampv1.RestrictionKind, tok, path string) (RuleWarning, bool) {
	if tok == "" || isNamespacedToken(tok) || KnownRestrictionToken(kind, tok) {
		return RuleWarning{}, false
	}
	return RuleWarning{
		Rule:    RuleRestrictionTokenRegistered,
		Path:    path,
		Token:   tok,
		Message: fmt.Sprintf("unregistered %s restriction token \"%s\" (term accepted)", kind.String(), tok),
	}, true
}

// hasCanonicalRule reports whether an axis carries a canonicalisation rule.
func hasCanonicalRule(kind rampv1.RestrictionKind) bool {
	switch kind {
	case rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION,
		rampv1.RestrictionKind_RESTRICTION_KIND_USER_TYPE,
		rampv1.RestrictionKind_RESTRICTION_KIND_GEOGRAPHY:
		return true
	default:
		return false
	}
}

// bareUnregistered reports whether token is a non-empty, non-namespaced value
// the registry does not recognise. Empty and vendor-namespaced tokens are never
// membership-checked: the former is governed by the wire tier, the latter is a
// deliberate custom value.
func bareUnregistered(token string, registered func(string) bool) bool {
	if token == "" || isNamespacedToken(token) {
		return false
	}
	return !registered(token)
}

// isNamespacedToken reports whether a token is a vendor-namespaced custom value.
func isNamespacedToken(token string) bool {
	for i := 0; i < len(token); i++ {
		if token[i] == ':' {
			return true
		}
	}
	return false
}

// isISOAlpha2 reports whether token is two uppercase ASCII letters — the
// structural shape of an ISO 3166-1 alpha-2 code, which the geography registry
// deliberately does not enumerate.
func isISOAlpha2(token string) bool {
	if len(token) != 2 {
		return false
	}
	return token[0] >= 'A' && token[0] <= 'Z' && token[1] >= 'A' && token[1] <= 'Z'
}

// trimJSONWhitespace trims the four RFC 8259 whitespace bytes — space, tab, LF,
// CR — and nothing else, so a token padded with a non-breaking space stays
// padded, in every language.
func trimJSONWhitespace(s string) string {
	start, end := 0, len(s)
	for start < end && isJSONWhitespace(s[start]) {
		start++
	}
	for end > start && isJSONWhitespace(s[end-1]) {
		end--
	}
	return s[start:end]
}

func isJSONWhitespace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

// asciiLower lowercases the ASCII letters of s and leaves every other byte
// untouched, so a non-ASCII code point can never fold into a registered token.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// asciiUpper is the uppercase twin of asciiLower.
func asciiUpper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - ('a' - 'A')
		}
	}
	return string(b)
}
