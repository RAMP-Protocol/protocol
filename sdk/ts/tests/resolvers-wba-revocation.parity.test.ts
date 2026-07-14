// Cross-language revocation-set-membership parity (TypeScript side).
//
// sdk/ts `revoked()` MUST reproduce the sdk/go oracle's verdict for every case
// in sdk/go/resolvers/testdata/revocation-membership-vectors.json. The vector
// carries a served WBA directory (keys + windows), a served revocation snapshot
// (as_of + revoked thumbprints), a prime thumbprint (a directory-listed key
// resolved to populate the snapshot), and labelled cases with the expected
// verdict. This test serves those docs against a REAL origin (the shared
// harness), resolves the prime thumbprint to prime the snapshot, then asserts
// `revoked(tp)` matches the oracle for EVERY case — including the load-bearing
// directory-absent-but-revoked → true, which is the whole point of the accessor.
import { afterEach, describe, expect, it } from "vitest";
import vector from "../../go/resolvers/testdata/revocation-membership-vectors.json";
import { createWBAKeyResolver } from "../resolvers/index.ts";
import {
	type Origin,
	revocationJson,
	startOrigin,
	wbaFileJson,
	wbaJwk,
	loopbackFetch,
} from "./resolvers-harness.ts";

interface RevMembershipCase {
	label: string;
	thumbprint: string;
	expected_revoked: boolean;
}
interface RevMembershipVector {
	as_of: string;
	directory_keys: { x: string; not_before: string; not_after: string }[];
	revoked: string[];
	prime_thumbprint: string;
	cases: RevMembershipCase[];
}

const vec = vector as RevMembershipVector;

describe("sdk/ts revoked() matches the sdk/go revocation-membership oracle", () => {
	let origin: Origin | undefined;
	afterEach(async () => {
		await origin?.close();
		origin = undefined;
	});

	it("has a non-empty case corpus", () => {
		expect(vec.cases.length).toBeGreaterThan(0);
	});

	it("reproduces the oracle verdict for every labelled case", async () => {
		origin = await startOrigin();
		const keys = vec.directory_keys.map((k) =>
			wbaJwk(k.x, k.not_before, k.not_after),
		);
		origin.setWBA(wbaFileJson(keys, origin.revocationURL()));
		origin.setRevocation(revocationJson(vec.as_of, vec.revoked));

		const r = createWBAKeyResolver({
			scheme: "http", fetch: loopbackFetch,
			now: () => Date.parse(vec.as_of),
		});
		// Prime the revocation snapshot by resolving the directory-listed key.
		await r.resolve(vec.prime_thumbprint, origin.url);

		for (const c of vec.cases) {
			expect(r.revoked(c.thumbprint), c.label).toBe(c.expected_revoked);
		}
		// Empty keyID is never revoked (parity with the Go accessor guard).
		expect(r.revoked("")).toBe(false);
	});
});
