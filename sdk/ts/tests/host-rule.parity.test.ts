// Host-rule parity (TypeScript side): hostOf, isBareHost and hostAnchored mirror
// the Go oracle (helpers/hosts.go).
//
// Mirrors the Python sibling sdk/python/tests/test_host_rule_parity.py.
//
// These three decide where a signed call is allowed to go, from values a network
// party supplied, so they are corpus-locked rather than asserted three times. The
// corpus is doing more work here than a port might expect: the platform URL
// parsers disagree about what a reference even IS before any of this code runs.
// WHATWG's `new URL` folds a scheme's default port away at parse time — earlier
// than the rule decides which scheme is in play — and strips control characters
// the oracle refuses outright. A port built on it passes the ordinary cases and
// fails the crossings, which is exactly what the crossings are here for.
//
// A reference the oracle cannot read is an ERROR there and a THROW here, so every
// case carries `error` alongside its value and this suite branches on it. Without
// that field a port could answer "not anchored" where the oracle says "not a
// reference" and still look green.
import { describe, expect, it } from "vitest";
import { hostAnchored, hostOf, isBareHost } from "../src/hosts.ts";
import vectorsFile from "../../go/helpers/testdata/host-rule-vectors.json";

type HostOfVector = { name: string; ref: string; host: string; error: boolean };
type IsBareHostVector = { name: string; ref: string; bare: boolean; error: boolean };
type HostAnchoredVector = {
	name: string;
	anchor: string;
	candidate: string;
	anchored: boolean;
	error: boolean;
};
type HostRuleVectorsFile = {
	host_of: HostOfVector[];
	is_bare_host: IsBareHostVector[];
	host_anchored: HostAnchoredVector[];
};

const doc = vectorsFile as HostRuleVectorsFile;

// Partitioned the way the Python sibling partitions it. The partitions matter on
// their own: each loop picks a throw assertion or a value assertion per case, so a
// corpus that lost every unreadable-reference case would register zero throw
// assertions and this file would report green with the throw contract untested.
const hostOfFaults = doc.host_of.filter((v) => v.error);
const hostOfValues = doc.host_of.filter((v) => !v.error);
const bareHostFaults = doc.is_bare_host.filter((v) => v.error);
const bareHostValues = doc.is_bare_host.filter((v) => !v.error);
const anchorFaults = doc.host_anchored.filter((v) => v.error);
const anchorValues = doc.host_anchored.filter((v) => !v.error);

describe("sdk/ts host predicates match the sdk/go oracle vectors", () => {
	it("every partition of the corpus is non-empty", () => {
		expect(hostOfFaults.length).toBeGreaterThan(0);
		expect(hostOfValues.length).toBeGreaterThan(0);
		expect(bareHostFaults.length).toBeGreaterThan(0);
		expect(bareHostValues.length).toBeGreaterThan(0);
		expect(anchorFaults.length).toBeGreaterThan(0);
		expect(anchorValues.length).toBeGreaterThan(0);
	});

	for (const v of hostOfValues) {
		it(`hostOf ${v.name}`, () => {
			expect(hostOf(v.ref)).toBe(v.host);
		});
	}
	for (const v of hostOfFaults) {
		it(`hostOf ${v.name} is not a usable host`, () => {
			expect(() => hostOf(v.ref)).toThrow(/not a usable host/);
		});
	}

	for (const v of bareHostValues) {
		it(`isBareHost ${v.name} -> ${v.bare}`, () => {
			expect(isBareHost(v.ref)).toBe(v.bare);
		});
	}
	for (const v of bareHostFaults) {
		it(`isBareHost ${v.name} is not a usable host`, () => {
			expect(() => isBareHost(v.ref)).toThrow(/not a usable host/);
		});
	}

	for (const v of anchorValues) {
		it(`hostAnchored ${v.name} -> ${v.anchored}`, () => {
			expect(hostAnchored(v.anchor, v.candidate)).toBe(v.anchored);
		});
	}
	for (const v of anchorFaults) {
		it(`hostAnchored ${v.name} is not a usable host`, () => {
			expect(() => hostAnchored(v.anchor, v.candidate)).toThrow(/not a usable host/);
		});
	}
});
