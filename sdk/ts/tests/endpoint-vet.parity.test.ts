// Endpoint-rule parity (TypeScript side): which endpoint a well-known manifest is
// allowed to advertise, against the Go oracle
// (sdk/go/internal/endpointrule + resolvers/endpointresolver.go).
//
// Mirrors the Python sibling sdk/python/tests/test_endpoint_vet_parity.py.
//
// The rule is not the sum of its parts, which is why it has a corpus of its own
// beside host-rule-vectors.json: an endpoint can be perfectly anchored and still
// be one no consumer may dial. The credential cases are the reason. A consumer
// that refuses only the spelled-out https://user:pass@host form has refused a
// spelling, not a credential — the same value with no scheme is what a plain URL
// parse reads as something other than an authority, and it reaches the anchor
// check as the very host it claims to be.
//
// Driven through the RESOLVER rather than a private predicate, because that is
// where the rule runs and what a consumer actually calls. The fetch is stubbed to
// a manifest carrying the vector's endpoint, so each case exercises the bare-host
// check, the decode and the vet, and nothing else.
import { describe, expect, it } from "vitest";
import { createWellKnownEndpointResolver } from "../resolvers/index.ts";
import type { FetchLike } from "../resolvers/http.ts";
import vectorsFile from "../../go/resolvers/testdata/endpoint-vet-vectors.json";

type EndpointVetVector = { name: string; host: string; endpoint: string; refused: boolean };
type EndpointVetVectorsFile = { endpoint_vet: EndpointVetVector[] };

const doc = vectorsFile as EndpointVetVectorsFile;

/** A manifest server that always answers with the endpoint under test. */
function servingManifest(endpoint: string): FetchLike {
	return async () => ({
		status: 200,
		text: async () => JSON.stringify({ role: "ROLE_EXCHANGE", endpoint }),
	});
}

const refused = doc.endpoint_vet.filter((v) => v.refused);
const accepted = doc.endpoint_vet.filter((v) => !v.refused);

describe("sdk/ts endpoint rule matches the sdk/go oracle vectors", () => {
	it("both partitions of the corpus are non-empty", () => {
		expect(refused.length).toBeGreaterThan(0);
		expect(accepted.length).toBeGreaterThan(0);
	});

	for (const v of accepted) {
		it(`endpointVet ${v.name} is handed back`, async () => {
			const r = createWellKnownEndpointResolver({ fetch: servingManifest(v.endpoint) });
			expect(await r.resolveEndpoint(v.host)).toBe(v.endpoint);
		});
	}

	// The class is not pinned here on purpose. The corpus records the RULE's
	// verdict, and two different faults reach it: an unusable serving host is the
	// caller's own value (an invalid-host throw, before any fetch), while an
	// unusable advertised endpoint is a verdict on the Exchange's answer
	// (EndpointRefused). Which is which is pinned in the integration suite; what
	// this file holds is that all three languages refuse the same set.
	for (const v of refused) {
		it(`endpointVet ${v.name} is refused`, async () => {
			const r = createWellKnownEndpointResolver({ fetch: servingManifest(v.endpoint) });
			await expect(r.resolveEndpoint(v.host)).rejects.toThrow();
		});
	}
});
