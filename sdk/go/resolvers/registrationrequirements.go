package resolvers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// ErrExchangeNotPermitted signals that the deployment's Allow overlay excluded
// this domain. It is raised BEFORE anything is dialled, so it says nothing about
// whether the Exchange exists or answers — only that this deployment declined to
// ask. Distinct from a transport failure because the remedy is a configuration
// change here, not a retry.
var ErrExchangeNotPermitted = errors.New("resolvers: exchange domain not permitted by policy")

// ErrManifestNotExchange signals that the document served at the domain's
// well-known path describes some other role. Registration requirements are an
// Exchange's to publish, so a manifest claiming to be an agent, a broker or a
// publisher is refused rather than read for members it has no business carrying.
// A manifest naming no role at all is refused the same way: the field is required
// by the contract, and treating an absent role as "probably an Exchange" would
// make the check advisory.
var ErrManifestNotExchange = errors.New("resolvers: well-known manifest does not describe an exchange")

// RegistrationRequirements is what one Exchange asks of a registration: the terms
// revision that submitting one accepts, and the schema its registration_data must
// match.
//
// Both members are optional in the contract, and their absence is a normal answer
// rather than a failure — an Exchange that publishes neither accepts registration
// data uninspected and records no terms acceptance.
type RegistrationRequirements struct {
	// TermsDigest is the manifest's terms_digest, nil when the Exchange publishes
	// none. Copy it onto RegisterRequest.terms_digest unchanged: the request
	// signature covers the echo, and that echo is the durable record of which
	// terms revision the operator accepted.
	//
	// A pointer rather than a string because absent and empty are different
	// answers on the wire, and only the pointer can carry the difference.
	TermsDigest *string

	// Schema validates registration_data before anything is signed. It is nil in
	// TWO cases — the Exchange publishes none, and the Exchange publishes one this
	// SDK refuses — and Verdict is what tells them apart. Both are deliberately
	// the same VALUE, because a nil *helpers.RegistrationSchema reports no
	// failures and that is the behaviour the contract requires of a client in both
	// cases: a local check that cannot run must not become a local veto.
	Schema *helpers.RegistrationSchema

	// Verdict is the SDK's answer for the published schema. SchemaNotPublished is
	// the ordinary absent case; SchemaAccepted means Schema is usable; anything
	// else names why a published schema was refused, which is worth logging and is
	// never worth refusing the registration over.
	Verdict helpers.SchemaVerdict
}

// RegistrationRequirementsReader reads an Exchange's published registration
// requirements. It is an interface so the client package can accept one without
// depending on this constructor, and so a test can drive registration without
// standing up a manifest server.
type RegistrationRequirementsReader interface {
	ResolveRegistrationRequirements(ctx context.Context, exchange string) (RegistrationRequirements, error)
}

// WellKnownRequirementsReader reads registration requirements out of an
// Exchange's own /.well-known/ramp.json.
//
// # Every read is a fresh fetch, and that is the whole design
//
// The protocol requires it in as many words: a registering client MUST read the
// terms digest from a freshly fetched manifest rather than a cached copy. A
// cached ENDPOINT is fine — a wrong one fails loudly — but a cached DIGEST is
// not, because a client cannot detect staleness locally, so a warm cache would
// make it echo a value the Exchange has already stopped accepting and retry the
// same refusal until the cache expired.
//
// That is why this is a SEPARATE reader rather than a third face on
// WellKnownEndpointResolver. That resolver is built out of exactly the mechanism
// this value may not touch — a per-host LRU with a TTL, and single-flight
// coalescing on top of it — and it exposes no bypass. Adding a member to the
// document it decodes would satisfy the rule's letter at the one point it fails
// in practice: the first caller to reuse the SDK's own manifest path would be
// handed a digest minutes old with nothing in the API to warn them. A reader that
// holds no document cache leaves no cache slot to reuse, which is the same
// structural argument the report leg makes about configuration — the rule holds
// because there is nowhere for the wrong answer to come from, not because callers
// remember.
//
// Reading the schema out of the same fresh bytes then costs nothing extra and
// removes a failure mode of its own: a stale local schema cannot refuse a payload
// the Exchange would have taken, because there is no stale local schema.
//
// # What is deliberately NOT held
//
// Not even the compiled validator. Compiling an attacker-authored schema is
// bounded but not free, and an application registering repeatedly at the same
// Exchange may reasonably want to pay that once — but memoising it is a cache,
// which this tier does not do by default, and the useful key for it (the digest
// of the served bytes) is a property of a deployment's threat model rather than
// of the protocol. An application that wants it wraps this reader.
type WellKnownRequirementsReader struct {
	http   *http.Client
	scheme string
	allow  func(domain string) bool
}

// NewWellKnownRequirementsReader returns a reader over WellKnownOptions. Zero-value
// options are safe defaults: https scheme and the SSRF-GUARDED client.
//
// The domain is CALLER-NAMED — an agent registers at whichever Exchange it means
// to transact with, and that domain routinely arrives at runtime rather than from
// configuration — so this is the same threat shape as the endpoint resolver's
// fetch and takes the same guarded default, NOT http.DefaultClient. A deployment
// that must reach a private or loopback Exchange injects its own client via
// opts.HTTP or opts out through the SKIP_SSRF / ALLOW_INSECURE env flags.
//
// opts.TTL and opts.Now are accepted and ignored: this reader caches nothing, so
// it has no freshness to compute. They are not errors, so one WellKnownOptions
// value can build every face in this package.
func NewWellKnownRequirementsReader(opts WellKnownOptions) *WellKnownRequirementsReader {
	client := opts.HTTP
	if client == nil {
		client = NewGuardedClientFromEnv()
	}
	scheme := opts.Scheme
	if scheme == "" {
		scheme = "https"
	}
	return &WellKnownRequirementsReader{http: client, scheme: scheme, allow: opts.Allow}
}

// ResolveRegistrationRequirements fetches exchange's manifest and reports what it
// asks of a registration. The answer is never served from a cache; see the type
// doc for why that is the point rather than an omission.
//
// Two refusals come before anything is dialled, and both are here rather than at
// the call site for the reason the endpoint resolver gives for its own: they are
// properties of building this URL and of this deployment's policy, not of any one
// caller's plans, and a second caller — or one that forgot — would otherwise fetch
// whatever domain an authenticated agent named.
//
// The SHAPE predicate is IsBareDomain, the contract's rule, and not the routing
// tier's IsBareHost. The two are kept apart deliberately and this leg is where the
// difference bites: nothing upstream of here has run the contract's rule, and the
// URL below is built by concatenation, so a value carrying a path or userinfo
// would choose WHAT is fetched rather than merely where from. A trailing root dot,
// a leading or trailing hyphen, an underscore and a bracketed IPv6 literal are all
// usable hosts that the wire rule refuses.
//
// A refused schema is never an error. The verdict is returned alongside a nil
// Schema, because the contract requires a client that cannot check locally to send
// anyway and let the Exchange decide.
func (r *WellKnownRequirementsReader) ResolveRegistrationRequirements(
	ctx context.Context, exchange string,
) (RegistrationRequirements, error) {
	if !helpers.IsBareDomain(exchange) {
		return RegistrationRequirements{}, fmt.Errorf(
			"resolvers: registration requirements: %w: %q is not a bare domain",
			helpers.ErrInvalidHost, exchange)
	}
	if r.allow != nil && !r.allow(exchange) {
		return RegistrationRequirements{}, fmt.Errorf("%w: %q", ErrExchangeNotPermitted, exchange)
	}
	// Bounded whatever client was injected: WellKnownOptions.HTTP admits one with
	// no timeout at all, and a caller may hold no deadline of its own. The ceiling
	// is the endpoint resolver's, so both manifest fetches wait the same.
	fetchCtx, cancel := context.WithTimeout(ctx, maxManifestFetch)
	defer cancel()
	url := r.scheme + "://" + exchange + "/.well-known/ramp.json"
	doc, err := fetchWellKnownDoc(fetchCtx, r.http, url)
	if err != nil {
		return RegistrationRequirements{}, fmt.Errorf(
			"resolvers: registration requirements for %q: %w", exchange, err)
	}
	if !doc.describesExchange() {
		return RegistrationRequirements{}, fmt.Errorf("%w: host=%q", ErrManifestNotExchange, exchange)
	}
	reqs := RegistrationRequirements{TermsDigest: doc.TermsDigest, Verdict: helpers.SchemaNotPublished}
	// The schema is compiled from the bytes AS SERVED, because every cap the rules
	// state is defined over those bytes. json.RawMessage is the sub-document the
	// decoder saw, so nothing has re-encoded it on the way here.
	if raw := doc.registrationSchemaBytes(); len(raw) > 0 {
		reqs.Schema, reqs.Verdict = helpers.CompileRegistrationSchema(raw)
	}
	return reqs, nil
}

// roleExchange is the proto-JSON rendering of Role.ROLE_EXCHANGE. A manifest may
// also carry the enum's number, which proto-JSON permits, so both are accepted.
const roleExchange = "ROLE_EXCHANGE"

// roleExchangeNumber is Role.ROLE_EXCHANGE's field number, accepted because
// proto-JSON allows an enum to travel as its number.
const roleExchangeNumber = "2"

// describesExchange reports whether the manifest names the Exchange role. An
// absent or unparsable role is not an Exchange: the contract makes the field
// required, and reading silence as assent would leave the check advisory.
func (d *wellKnownDoc) describesExchange() bool {
	var s string
	if err := json.Unmarshal(d.Role, &s); err == nil {
		return s == roleExchange
	}
	var n json.Number
	if err := json.Unmarshal(d.Role, &n); err == nil {
		return n.String() == roleExchangeNumber
	}
	return false
}

// registrationSchemaBytes returns the published data_schema exactly as served, or
// nil when the block or the member is absent. Absent and blank are the same answer
// to the caller — CompileRegistrationSchema reads either as "publishes none" — but
// the two are distinguished here anyway so a blank member reaches the rule that
// defines blankness rather than a rule invented at this layer.
func (d *wellKnownDoc) registrationSchemaBytes() []byte {
	if d.AccountRegistration == nil {
		return nil
	}
	return d.AccountRegistration.DataSchema
}
