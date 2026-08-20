// The per-URI discovery shape (TypeScript side) — mirror of sdk/go core.SortGroups.
//
// Mirrors the sdk/python sibling test_core_sort_groups.py.
//
// A discovery call is per-URI, and the answer has to stay that way. A URI that was
// REFUSED carries no offer, so a flat list erases it: nothing survives to say which
// resource was refused or why, and "not in the catalogue" (give up), "scope
// insufficient" (acquire an entitlement and retry) and "content blocked" (never retry)
// all read alike as "found nothing". These assert the grouping keeps that difference,
// and that the offers inside each group go through the SAME Verifier — the fail-closed
// split is not re-implemented per group, which is what "no second verification path"
// means.
import { describe, expect, it } from "vitest";
import {
	createVerifier,
	type DiscoveryResult,
	type Mode,
	rejectedOffers,
	verifiedOffers,
} from "../core/verifier.ts";

const NOW = 1_700_000_000_000;

// An EMPTY key map: under "strict" nothing resolves, so every offer is rejected
// fail-closed. That is what makes "the group's offers went through the Verifier"
// observable without any key material.
const verifier = (mode: Mode) =>
	createVerifier(mode, { resolve: async () => undefined, now: () => NOW });

const group = (uri: string, rest: Record<string, unknown> = {}) => ({ uri, ...rest });

describe("sdk/ts Verifier.sortGroups keeps the per-URI answer", () => {
	it("every requested URI keeps its group and its reason", async () => {
		const groups = await verifier("off").sortGroups([
			group("https://site.test/a", { offers: [{ offer_id: "one" }] }),
			group("https://site.test/b", {
				absence_reason: "OFFER_ABSENCE_REASON_SCOPE_INSUFFICIENT",
			}),
			group("https://site.test/c", {
				absence_reason: "OFFER_ABSENCE_REASON_RESTRICTION_FILTERED",
				restriction_filters: ["RESTRICTION_KIND_GEOGRAPHY"],
			}),
		]);

		expect(groups.map((g) => g.uri)).toEqual([
			"https://site.test/a",
			"https://site.test/b",
			"https://site.test/c",
		]);
		expect(groups[0]?.result.verified).toHaveLength(1);
		// The refusal is an ANSWER: the agent can tell "acquire an entitlement and
		// retry" from "give up" only because the reason survived.
		expect(groups[1]?.absenceReason).toBe(
			"OFFER_ABSENCE_REASON_SCOPE_INSUFFICIENT",
		);
		expect(groups[1]?.result.verified).toEqual([]);
		expect(groups[2]?.restrictionFilters).toEqual(["RESTRICTION_KIND_GEOGRAPHY"]);
	});

	it("a responder that stated no reason says nothing rather than unspecified", async () => {
		const [g] = await verifier("off").sortGroups([group("https://site.test/a")]);
		expect(g).toBeDefined();
		expect(g && "absenceReason" in g).toBe(false);
		expect(g && "discoveryMethod" in g).toBe(false);
		expect(g?.restrictionFilters).toEqual([]);
	});

	it("group offers run through the same fail-closed Verifier", async () => {
		const groups = await verifier("strict").sortGroups([
			group("https://site.test/a", {
				offers: [{ exchange: "exchange.test", signature: "00" }],
			}),
		]);
		expect(groups[0]?.result.verified).toEqual([]);
		expect(groups[0]?.result.rejected).toHaveLength(1);
		expect(groups[0]?.result.rejected[0]?.reason).toContain(
			"no offer-signing key",
		);
	});

	it("a non-group element is skipped rather than given an empty URI", async () => {
		const groups = await verifier("off").sortGroups([
			null,
			"not a group",
			7,
			["also not a group"],
			group("https://site.test/a"),
		]);
		expect(groups.map((g) => g.uri)).toEqual(["https://site.test/a"]);
	});

	it("no groups yields no groups", async () => {
		expect(await verifier("off").sortGroups([])).toEqual([]);
	});

	it("the flatteners span groups and ignore the ones that carry nothing", async () => {
		const result: DiscoveryResult = {
			groups: await verifier("off").sortGroups([
				group("https://site.test/a", { offers: [{ offer_id: "one" }] }),
				group("https://site.test/b", {
					absence_reason: "OFFER_ABSENCE_REASON_NOT_IN_CATALOG",
				}),
				group("https://site.test/c", { offers: [{ offer_id: "two" }] }),
			]),
			exchange: "exchange.test",
		};

		expect(
			verifiedOffers(result).map(
				(v) => (v.offer as { offer_id: string }).offer_id,
			),
		).toEqual(["one", "two"]);
		expect(rejectedOffers(result)).toEqual([]);
		// The refused URI contributes nothing to the flattened view, which is exactly
		// why the flatteners are a convenience over `groups` and never a substitute.
		expect(result.groups).toHaveLength(3);
	});
});
