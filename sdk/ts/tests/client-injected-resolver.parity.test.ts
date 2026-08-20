// The client re-checks whatever an injected EndpointResolver hands back — replay of the
// shared endpoint-vet corpus, driven through the CLIENT rather than through the resolver.
//
// Mirrors sdk/python/tests/test_client_injected_resolver_parity.py and the Go leg
// sdk/go/connect/route_injected_resolver_test.go.
//
// The corpus already pins WHAT the endpoint rule decides; every language replays it
// against the resolver. What it did not pin is that the client applies the rule at all to
// a resolver it did not write — and EndpointResolver is a documented, encouraged seam, so
// "a caller supplied one" is the ordinary case, not an exotic one. Without the re-check a
// signed usage report or dispute goes to whatever that implementation returned: an
// off-host endpoint, or one carrying userinfo the HTTP client then turns into an
// Authorization header the SDK never chose.
//
// A refusal must be not_sent, not unreachable: it is a verdict, and reporting it as a
// transport failure would tell a caller to retry something that can never succeed.
import { describe, expect, it } from "vitest";

import { vetExchangeEndpoint } from "../client/route.ts";
import { RampCallError } from "../client/errors.ts";
import vectorsFile from "../../go/resolvers/testdata/endpoint-vet-vectors.json";

type EndpointVetVector = {
	name: string;
	host: string;
	endpoint: string;
	refused: boolean;
};
const vectors = (vectorsFile as { endpoint_vet: EndpointVetVector[] }).endpoint_vet;

/** An injected resolver that answers exactly what a vector says, checking nothing. */
const answering = (endpoint: string) => ({
	resolveEndpoint: async (): Promise<string> => endpoint,
});

describe("an injected endpoint resolver does not get to skip the rule", () => {
	it("endpoint-vet vector set is non-empty", () => {
		expect(vectors.length).toBeGreaterThan(0);
		expect(vectors.some((v) => v.refused)).toBe(true);
	});

	for (const v of vectors) {
		// A vector whose serving host is not a usable host is refused before the resolver
		// is reached, by the bare-host check; that path is covered by the resolver replay.
		if (v.host === "") continue;

		it(`${v.refused ? "refuses" : "accepts"}: ${v.name}`, async () => {
			const call = vetExchangeEndpoint(answering(v.endpoint), v.host, "report usage");
			if (!v.refused) {
				await expect(call).resolves.toBe(v.endpoint);
				return;
			}
			const err = (await call.catch((e: unknown) => e)) as RampCallError;
			expect(err).toBeInstanceOf(RampCallError);
			expect(err.kind, `${v.name} must be a verdict, not a transport failure`).toBe(
				"not_sent",
			);
			// The refusal reaches a log; an endpoint carrying userinfo must not.
			expect(String(err.cause ?? "")).not.toContain("pass@");
		});
	}
});
