// Routing a call to the Exchange that ISSUED an offer. TS port of sdk/go/connect/route.go.
//
// There are three kinds of destination, and the difference decides how much checking a
// call needs. The Broker and the home Exchange come from the client's own configuration
// and are trusted as far as that configuration is. The Exchange a usage report goes to is
// named inside an OFFER, which arrived over the network — so an actor who can influence
// an offer can influence that address.
//
// A signature covers the DOMAIN; it says nothing about where that domain's endpoint
// lives, or where its DNS points. That is why the address is resolved from the Exchange's
// own manifest and then checked, rather than taken on trust or, worse, read from
// configuration.

import { EndpointRefused, NoEndpoint } from "./../resolvers/errors.ts";
import { endpointRefusal } from "../src/endpoint-rule.ts";
import { isBareHost } from "../src/hosts.ts";
import { redactUserinfo } from "../src/host-ref.ts";
import { RampCallError, notSent } from "./errors.ts";

/**
 * EndpointResolver turns a signed exchange domain into the origin that Exchange
 * advertises for itself. It is an interface so a test can drive reporting without
 * standing up a manifest server — and, more to the point, so this module has no way to
 * accept a report endpoint from configuration.
 *
 * An implementation's FAILURE decides how a caller is told to react, so it is part of the
 * contract rather than an implementation detail. A failure that is a VERDICT — the host
 * is unusable, the host is not allowed, the manifest advertises no endpoint, or it
 * advertises one that must not be used — MUST throw the resolver tier's NoEndpoint or
 * EndpointRefused, or the invalid-host error isBareHost raises; those surface as
 * `not_sent`, which tells the caller not to retry. Anything else is read as a transport
 * failure and reported as `unreachable`, i.e. worth retrying. An implementation that
 * throws a bare error for a refusal therefore has its final answer retried indefinitely.
 */
export interface EndpointResolver {
	resolveEndpoint(host: string): Promise<string>;
}

/**
 * vetExchangeEndpoint resolves an exchange domain to an origin a signed call may be sent
 * to, or refuses — naming the check that declined, and classifying it by CAUSE. "The
 * Exchange said no", "we could not reach it" and "we refused to dial it" are three
 * different outcomes calling for three different responses, and only the class tells them
 * apart: a verdict is final, a transport failure is worth retrying.
 *
 * It is one function so the vetting reads in one place: the checks are the part that
 * grows, and seeing them together is what makes it evident that no branch falls through
 * to the send.
 */
export async function vetExchangeEndpoint(
	resolver: EndpointResolver | undefined,
	exchangeDomain: string,
	op: string,
): Promise<string> {
	if (resolver === undefined) {
		throw notSent(op, new Error("no endpoint resolver configured"));
	}
	if (exchangeDomain === "") {
		throw notSent(
			op,
			new Error("no exchange domain to route to; it comes from the signed offer"),
		);
	}
	// A plain hostname, checked here even if the caller checked it. The resolver builds
	// its URL by concatenating this value, so a path or query smuggled through would
	// choose what gets fetched; this module owns the call and cannot rely on every present
	// and future caller having vetted it.
	let bare: boolean;
	try {
		bare = isBareHost(exchangeDomain);
	} catch (cause) {
		throw notSent(
			op,
			new Error(
				`exchange ${redactUserinfo(exchangeDomain)} is not a usable domain: ${
					cause instanceof Error ? cause.message : String(cause)
				}`,
			),
		);
	}
	if (!bare) {
		throw notSent(
			op,
			new Error(
				`exchange ${redactUserinfo(exchangeDomain)} is not a bare domain, refusing to resolve it`,
			),
		);
	}

	let endpoint: string;
	try {
		endpoint = await resolver.resolveEndpoint(exchangeDomain);
	} catch (cause) {
		// Classified by CAUSE, not by position. Reaching the manifest is a network
		// operation, and a DNS blip or a 500 from an otherwise healthy Exchange is
		// TRANSIENT — reporting it as a refusal would tell a caller "we declined to send
		// this, do not retry" and permanently drop a usage report over a momentary outage.
		// Only a verdict is a refusal: the value was not a usable host, the host was not
		// allowed, the manifest was read and advertises no endpoint at all, or it
		// advertises one the resolver will not hand back.
		throw new RampCallError({
			kind: isVerdict(cause) ? "not_sent" : "unreachable",
			op,
			cause: new Error(
				`resolve exchange ${exchangeDomain}: ${
					cause instanceof Error ? cause.message : String(cause)
				}`,
			),
		});
	}

	// Re-checked here even though the SDK's own resolver already refuses such an endpoint.
	// The resolver is an injectable seam — its own docs offer it so a caller can drive
	// reporting without a manifest server — and this module cannot make a SIGNED call
	// conditional on a stranger's implementation having remembered the rule. The cost is
	// string work on a path that just did a network fetch.
	//
	// The SAME predicate both times, deliberately. Stated twice it drifts, and a
	// half-mirrored version of this rule is how a signed call ends up carrying credentials
	// the SDK never chose.
	const refusal = endpointRefusal(exchangeDomain, endpoint);
	if (refusal !== undefined) {
		throw notSent(
			op,
			new Error(
				`refusing to send a signed call to the endpoint exchange ${redactUserinfo(
					exchangeDomain,
				)} advertises: ${refusal}`,
			),
		);
	}
	return endpoint;
}

/** Whether a cause is the invalid-host refusal.
 *
 * Matched on its wording rather than its type. The host helpers are L1 and deliberately
 * raise a bare error for it — a typed InvalidHost would cross the helpers-versus-resolvers
 * sentinel split the SDK documents — so the shared prefix is what there is to match.
 *
 * Exported because TWO injectable readers can raise it, the endpoint resolver and the
 * registration-requirements reader, and both have to call it final for the same reason. A
 * second copy of the prefix is exactly how the two would come to disagree. */
export function isInvalidHostRefusal(cause: unknown): boolean {
	return (
		cause instanceof Error &&
		cause.message.startsWith("hosts: reference is not a usable host")
	);
}

// isVerdict tells the resolver's final answers from its transient ones. The invalid-host
// error is in the set because the resolver checks the host itself too, and a value that
// is not a host will not become one on a later attempt. This module checks it before
// resolving, so the SDK's own resolver never reaches here that way — an injected one can.
function isVerdict(cause: unknown): boolean {
	if (cause instanceof NoEndpoint || cause instanceof EndpointRefused) return true;
	return isInvalidHostRefusal(cause);
}
