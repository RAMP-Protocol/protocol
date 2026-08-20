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
import { createWellKnownEndpointResolver, EndpointRefused } from "../resolvers/index.ts";
import { isBareHost } from "../src/hosts.ts";
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

/** Whether a vector's SERVING host is a value a caller could legitimately pass. */
function servingHostIsUsable(host: string): boolean {
	try {
		return isBareHost(host);
	} catch {
		return false;
	}
}

// The two faults a refused vector can carry, split by DATA rather than by name. An
// unusable serving host is the caller's own argument, refused before any fetch; every
// other refusal is a verdict on what the Exchange advertised.
const refusedByTheRule = refused.filter((v) => servingHostIsUsable(v.host));
const refusedBeforeTheFetch = refused.filter((v) => !servingHostIsUsable(v.host));

describe("sdk/ts endpoint rule matches the sdk/go oracle vectors", () => {
	it("both partitions of the corpus are non-empty", () => {
		expect(refused.length).toBeGreaterThan(0);
		expect(accepted.length).toBeGreaterThan(0);
	});

	// One vector carries an unusable serving host, and the split below is only honest
	// while that stays true. A second one arriving silently would move a verdict on
	// the Exchange's answer into the branch that does not require EndpointRefused,
	// which is the assertion this file exists to make.
	it("the caller-fault partition stays the exception it is written as", () => {
		expect(refusedBeforeTheFetch).toHaveLength(1);
		expect(refusedByTheRule).toHaveLength(refused.length - 1);
	});

	for (const v of accepted) {
		it(`endpointVet ${v.name} is handed back`, async () => {
			const r = createWellKnownEndpointResolver({ fetch: servingManifest(v.endpoint) });
			expect(await r.resolveEndpoint(v.host)).toBe(v.endpoint);
		});
	}

	// The exact class IS pinned, positively. Excluding two wrong classes cannot
	// preserve the verdict this branch adds: EndpointRefused is FINAL, distinct from
	// "no endpoint advertised" and from a transport failure precisely so a caller
	// classifying retryability reads it as a decision. A test that accepts anything
	// else would stay green while that distinction was erased — and, here, would
	// count a TypeError from a crash as a refusal.
	for (const v of refusedByTheRule) {
		it(`endpointVet ${v.name} is refused by the rule`, async () => {
			const r = createWellKnownEndpointResolver({ fetch: servingManifest(v.endpoint) });
			const err = await r.resolveEndpoint(v.host).then(
				() => undefined,
				(e: unknown) => e,
			);
			expect(err).toBeInstanceOf(EndpointRefused);
		});
	}

	// The one fault that is NOT a verdict on the Exchange: the caller's own argument
	// is not a host, so nothing was fetched and there is nothing to have a verdict
	// on. It is the plain invalid-host throw isBareHost itself raises, and it must
	// not be dressed up as a refusal of the manifest.
	for (const v of refusedBeforeTheFetch) {
		it(`endpointVet ${v.name} is the caller's fault, not the Exchange's`, async () => {
			const r = createWellKnownEndpointResolver({ fetch: servingManifest(v.endpoint) });
			const err = await r.resolveEndpoint(v.host).then(
				() => undefined,
				(e: unknown) => e,
			);
			expect(err).toBeInstanceOf(Error);
			expect(err).not.toBeInstanceOf(EndpointRefused);
			expect((err as Error).message).toMatch(/not a usable host/);
		});
	}
});
