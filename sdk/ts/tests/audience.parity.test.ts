// Audience parity (TypeScript side): isBareDomain and checkAudience mirror the
// Go oracle (helpers/hosts.go, helpers/audience.go).
//
// Mirrors the Python sibling sdk/python/tests/test_audience_parity.py.
//
// The shared vectors at sdk/go/helpers/testdata/audience-vectors.json carry the
// bare-domain rule ITSELF (pattern + length bound) beside the case lists, so
// this suite asserts the constants too: a port that quietly kept its own copy of
// the pattern would otherwise pass every case that copy happens to agree on.
//
// The identity fault is a THROW here and a (verdict, error) pair in Go, so the
// vectors carry `identity_error` alongside the token and this suite branches on
// it. Without that field a port could collapse a deployment fault into a request
// rejection and still look green.
import { describe, it, expect } from "vitest";
import {
	bareDomainPattern,
	checkAudience,
	isBareDomain,
	maxBareDomainLen,
} from "../src/hosts.ts";
import vectorsFile from "../../go/helpers/testdata/audience-vectors.json";

type BareDomainVector = { name: string; value: string; valid: boolean };
type AudienceVector = {
	name: string;
	self: string;
	claimed: string[];
	expected_verdict: string;
	identity_error: boolean;
};
type AudienceVectorsFile = {
	bare_domain_pattern: string;
	bare_domain_max_len: number;
	bare_domain: BareDomainVector[];
	audience: AudienceVector[];
};

const doc = vectorsFile as AudienceVectorsFile;

// Partitioned the way the Python sibling partitions it, so both suites guard the
// same four things. The two partitions matter on their own: the loop below picks a
// throw assertion or a value assertion per case, so a corpus that lost every
// identity-fault case would register zero throw assertions and this file would
// report green with the throw contract untested.
const identityFaults = doc.audience.filter((v) => v.identity_error);
const requestCases = doc.audience.filter((v) => !v.identity_error);

describe("sdk/ts bare-domain + audience faces match the sdk/go oracle vectors", () => {
	it("audience vector sets are non-empty", () => {
		expect(doc.bare_domain.length).toBeGreaterThan(0);
		expect(doc.audience.length).toBeGreaterThan(0);
		expect(identityFaults.length).toBeGreaterThan(0);
		expect(requestCases.length).toBeGreaterThan(0);
	});

	// The rule is one definition or it is nothing.
	it("carries the same bare-domain rule as the oracle", () => {
		expect(bareDomainPattern).toBe(doc.bare_domain_pattern);
		expect(maxBareDomainLen).toBe(doc.bare_domain_max_len);
	});

	for (const v of doc.bare_domain) {
		it(`isBareDomain ${v.name}`, () => {
			expect(isBareDomain(v.value)).toBe(v.valid);
		});
	}

	for (const v of doc.audience) {
		if (v.identity_error) {
			it(`checkAudience ${v.name} refuses the configured identity`, () => {
				expect(() => checkAudience(v.self, ...v.claimed)).toThrow();
			});
		} else {
			it(`checkAudience ${v.name} -> ${v.expected_verdict}`, () => {
				expect(checkAudience(v.self, ...v.claimed)).toBe(v.expected_verdict);
			});
		}
	}
});
