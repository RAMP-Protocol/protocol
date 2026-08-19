// Identity-document DIFFERENTIAL SWEEP replay (TypeScript side).
//
// Mirrors the Python sibling sdk/python/tests/test_identity_document_sweep_parity.py.
//
// Replays sdk/go/helpers/testdata/identity-document-sweep-vectors.json, which is
// thousands of machine-generated base/reference pairs recorded from the real Go
// face. Its emitter header explains why it exists; the short version is that a
// hand-written corpus holds only the inputs someone thought of, and three review
// rounds of those passed in all three languages while the ports still answered
// differently for an apostrophe in a query, a second hash in a fragment, a dot
// segment in the manifest URL, and a second colon in an authority.
//
// This file is what makes the sweep a permanent gate rather than a script someone
// has to remember to run after the next Node upgrade changes the WHATWG URL
// parser.
//
// ONE test rather than one per case, unlike the intent corpus beside it: the
// cases are positionally named because there is nothing to name, so a per-case
// test id would carry no information, and 2789 of them would be noise in every
// run. The failure message lists the first mismatches with both inputs, which is
// what a person actually needs.
import { describe, it, expect } from "vitest";
import { resolveIdentityDocument } from "../src/hosts.ts";
import sweepFile from "../../go/helpers/testdata/identity-document-sweep-vectors.json";

type SweepVector = {
	name: string;
	manifest_url: string;
	ref: string;
	accepted: boolean;
	resolved: string;
};

const vectors = (sweepFile as { identity_document_sweep: SweepVector[] }).identity_document_sweep;

describe("sdk/ts resolveIdentityDocument matches the sdk/go oracle across the sweep", () => {
	it("the sweep corpus is populated", () => {
		// A corpus that lost its cases would pass the loop below in silence.
		expect(vectors.length).toBeGreaterThan(1000);
		expect(vectors.some((v) => v.accepted)).toBe(true);
		expect(vectors.some((v) => !v.accepted)).toBe(true);
	});

	it("every sweep case answers as the oracle does", () => {
		const mismatches: string[] = [];
		for (const v of vectors) {
			let got: string | null;
			try {
				got = resolveIdentityDocument(v.manifest_url, v.ref);
			} catch {
				got = null;
			}
			const want = v.accepted ? v.resolved : null;
			if (got !== want) {
				mismatches.push(
					`${v.name}: base=${JSON.stringify(v.manifest_url)} ref=${JSON.stringify(v.ref)} ` +
						`oracle=${JSON.stringify(want)} ts=${JSON.stringify(got)}`,
				);
			}
		}
		expect(
			mismatches.slice(0, 20),
			`${mismatches.length} of ${vectors.length} sweep cases disagree with the Go oracle`,
		).toEqual([]);
	});
});
