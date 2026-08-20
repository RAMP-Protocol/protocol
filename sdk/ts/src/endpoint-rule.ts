// The endpoint rule: whether an endpoint may be sent a signed call, given the host that
// named it. Pure — no IO — so both the resolver that reads it out of a manifest and the
// client that re-checks an injected resolver's answer share one statement of it.
//
// Deliberately not exported from the package manifest: it is the SDK's own rule, not a
// face a consumer composes.

import { anchoredParsed, parseRef } from "./host-ref.ts";

/** Why an endpoint a manifest advertises may not be handed back, or undefined
 * when it may.
 *
 * The manifest that named this endpoint is served by the very host the call is
 * bound for, so the endpoint is only as trustworthy as that host. An Exchange may
 * advertise itself or a subdomain of itself, on the same port, and nothing else —
 * a dial-time address guard has no objection to an unrelated PUBLIC host, so
 * nothing below this catches one.
 *
 * Userinfo is refused for a different reason with the same shape: the host
 * comparison reads the authority's host and ignores any user:password before it,
 * so an endpoint carrying credentials would pass the host check and then have the
 * HTTP client stamp an Authorization header the SDK never chose, on a leg that
 * already carries the caller's own signature.
 *
 * It lives in ONE place because it has two callers, and they check the same value
 * for different reasons. The resolver checks what a manifest advertised, because
 * that is a property of reading an endpoint out of a manifest. The client re-checks
 * whatever its endpoint resolver handed back, because that resolver is an
 * injectable seam and this SDK cannot make a signed call conditional on a
 * stranger's implementation having remembered the rule. Stated twice it drifts, and
 * a half-mirrored version of this rule is how a signed call ends up carrying
 * credentials the SDK never chose. The Go oracle keeps it in a shared internal
 * package for exactly this reason.
 *
 * Both halves are decided over ONE reading of the reference, by the shared parse
 * in src/host-ref.ts. That is not tidiness: a value naming no scheme is a URL to
 * one parser and a path to another, and the two answers put a credential on
 * opposite sides of the check — "u:p@exchange.example" is where they part. */
export function endpointRefusal(host: string, endpoint: string): string | undefined {
  let advertised: ReturnType<typeof parseRef>;
  try {
    advertised = parseRef(endpoint);
  } catch (err) {
    // The error already names the reference, with any credential redacted. Echoing
    // the raw endpoint alongside it would put the credential straight back — which
    // is what happened when this branch moved ahead of the userinfo refusal below.
    return `host=${JSON.stringify(host)}: ${String(err)}`;
  }
  if (advertised.hasUserinfo) {
    // Deliberately does not echo the endpoint: it carries the credential.
    return `host=${JSON.stringify(host)} advertises an endpoint carrying userinfo`;
  }
  let served: ReturnType<typeof parseRef>;
  try {
    served = parseRef(host);
  } catch (err) {
    return `the serving host is unusable: ${String(err)}`;
  }
  if (!anchoredParsed(served, advertised)) {
    return `host=${JSON.stringify(host)} advertises endpoint ${JSON.stringify(endpoint)} on a different host`;
  }
  return undefined;
}
