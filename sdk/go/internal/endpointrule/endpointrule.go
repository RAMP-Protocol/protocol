// Package endpointrule holds the one predicate that decides whether an endpoint a
// well-known manifest advertises may be used at all.
//
// The rule is normative — WellKnownManifest.endpoint states it as a MUST — and it
// is checked in two places for two different reasons: the resolver refuses to hand
// such an endpoint back, and the client refuses to send a signed call to one even
// when a caller injected its own resolver. Two call sites, two error vocabularies,
// but there must only ever be ONE predicate. Written twice it drifts, and this
// repo has watched a duplicated host predicate drift inside a single commit.
//
// Internal because Python and TypeScript will grow their own implementations
// rather than binding to a Go export, and the shared public surface belongs with
// that work.
package endpointrule

import (
	"fmt"
	"net/url"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// Vet reports whether endpoint may be used for host — the host that served the
// manifest advertising it — returning nil when it may and a describing error when
// it may not.
//
// Two conditions refuse. The endpoint must be on host or a subdomain of it: the
// manifest is only as trustworthy as the host that served it, so an endpoint
// naming an unrelated host would let whoever answers for that document redirect a
// signed call to a party the offer's signature never covered. A dial-time address
// guard has no objection to an unrelated PUBLIC host, so nothing below this
// catches it.
//
// And the endpoint must carry no userinfo. The host comparison reads the
// authority's host and ignores any user:password before it, so credentials would
// otherwise pass the first check and then have net/http stamp an Authorization
// header the SDK never chose — on a leg that already carries the agent's own
// signature.
//
// The caller supplies the vocabulary: the errors here describe what was wrong, and
// each call site wraps them in whatever sentinel its own tier classifies on.
func Vet(host, endpoint string) error {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("host=%q endpoint=%q is not a URL: %w", host, endpoint, err)
	}
	if parsed.User != nil {
		// Deliberately does not echo the endpoint: it carries the credential.
		return fmt.Errorf("host=%q advertises an endpoint carrying userinfo", host)
	}
	anchored, err := helpers.HostAnchored(host, endpoint)
	if err != nil {
		return fmt.Errorf("host=%q endpoint=%q: %w", host, endpoint, err)
	}
	if !anchored {
		return fmt.Errorf("host=%q advertises endpoint %q on a different host", host, endpoint)
	}
	return nil
}
