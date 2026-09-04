// Replay of the shared manifest-version corpus, driven two ways.
//
// The pure rule (manifestVersionRefusal) is replayed row by row against the Go
// emitter's verdicts. Then the same rows are driven through the REAL endpoint
// resolver against a stub manifest server, so the test proves the resolver
// applies the rule before it reads the endpoint — a refused document's endpoint
// is a perfectly usable one, so the refusal can only be the version gate.
//
// `present` is its own column because an absent member is not a string: the
// resolver reads `doc.ver` and gets undefined, which is the path the `absent`
// row must exercise. Pinned to manifest-version-vectors.json.

import { describe, expect, it } from "vitest";
import vectorsFile from "../../go/helpers/testdata/manifest-version-vectors.json";
import { ManifestVersionRefused, createWellKnownEndpointResolver } from "../resolvers/index.ts";
import type { FetchLike } from "../resolvers/http.ts";
import { WellKnownManifestVersion, manifestVersionRefusal } from "../src/wire.ts";
import { manifestJson } from "./resolvers-harness.ts";

type ManifestVersionVector = { name: string; ver: string; present: boolean; accepted: boolean };
type ManifestVersionVectorsFile = { manifest_version: ManifestVersionVector[] };

const doc = vectorsFile as ManifestVersionVectorsFile;
const vectors = doc.manifest_version;
const accepted = vectors.filter((v) => v.accepted);
const refused = vectors.filter((v) => !v.accepted);
const absent = vectors.filter((v) => !v.present);

const HOST = "exchange.example";
const ENDPOINT = `https://${HOST}/ramp.v1.ExchangeService`;

/** The value the resolver sees: the string when present, undefined when absent. */
const verOf = (v: ManifestVersionVector): string | undefined => (v.present ? v.ver : undefined);

/** A manifest server that answers with a fixed body. */
function serving(body: string): FetchLike {
	return async () => ({ status: 200, text: async () => body });
}

/** The vector's manifest with a usable endpoint; an absent row omits `ver`. */
const manifestFor = (v: ManifestVersionVector): string => manifestJson(ENDPOINT, verOf(v) ?? null);

const resolverOver = (fetchFn: FetchLike) =>
	createWellKnownEndpointResolver({ fetch: fetchFn, ttlMs: 3_600_000, scheme: "https" });

describe("manifest-version corpus", () => {
	it("every partition is non-empty", () => {
		expect(accepted.length).toBeGreaterThan(0);
		expect(refused.length).toBeGreaterThan(0);
		expect(absent.length).toBeGreaterThan(0);
	});

	it("the current constant is in the accepted partition", () => {
		expect(accepted.some((v) => v.present && v.ver === WellKnownManifestVersion)).toBe(true);
	});

	for (const v of vectors) {
		it(`pure rule: ${v.name} → accepted=${v.accepted}`, () => {
			const refusal = manifestVersionRefusal(verOf(v));
			expect(refusal === undefined, refusal).toBe(v.accepted);
		});
	}

	for (const v of accepted) {
		it(`resolver accepts and reads the endpoint: ${v.name}`, async () => {
			await expect(resolverOver(serving(manifestFor(v))).resolveEndpoint(HOST)).resolves.toBe(
				ENDPOINT,
			);
		});
	}

	for (const v of refused) {
		it(`resolver refuses with the version verdict: ${v.name}`, async () => {
			// A refused document's endpoint is usable, so the refusal can only be the
			// version gate — and ManifestVersionRefused is its own class, not a
			// subclass of any other verdict, so the instance check is the whole assertion.
			await expect(resolverOver(serving(manifestFor(v))).resolveEndpoint(HOST)).rejects.toBeInstanceOf(
				ManifestVersionRefused,
			);
		});
	}

	it("the version gate precedes the endpoint gate", async () => {
		const r = resolverOver(serving(manifestJson(undefined, "2.0")));
		await expect(r.resolveEndpoint(HOST)).rejects.toBeInstanceOf(ManifestVersionRefused);
	});

	it("a refusal is not cached", async () => {
		let served = "2.0";
		let hits = 0;
		const fetchFn: FetchLike = async () => {
			hits += 1;
			return { status: 200, text: async () => manifestJson(ENDPOINT, served) };
		};
		const r = resolverOver(fetchFn);
		await expect(r.resolveEndpoint(HOST)).rejects.toBeInstanceOf(ManifestVersionRefused);
		served = WellKnownManifestVersion;
		await expect(r.resolveEndpoint(HOST)).resolves.toBe(ENDPOINT);
		expect(hits).toBe(2);
	});
});
