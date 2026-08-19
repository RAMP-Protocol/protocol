// Identity-document resolution parity (TypeScript side): resolveIdentityDocument
// mirrors the Go oracle (helpers/identitydocs.go).
//
// Mirrors the Python sibling sdk/python/tests/test_identity_document_parity.py.
//
// The shared vectors at sdk/go/helpers/testdata/identity-document-vectors.json
// carry both halves of each answer — whether the reference was accepted AND the
// exact canonical URL it resolved to — because a port that accepted the right
// references and returned a different URL would be just as wrong as one that
// accepted the wrong references.
//
// The refusal is a THROW here and an `error` in Go, so this suite branches on
// the `accepted` flag rather than comparing message text: the three languages
// word their refusals differently on purpose, and pinning the wording would gate
// a port on English rather than on behaviour.
import { describe, it, expect } from "vitest";
import { resolveIdentityDocument } from "../src/hosts.ts";
import vectorsFile from "../../go/helpers/testdata/identity-document-vectors.json";

type IdentityDocumentVector = {
	name: string;
	manifest_url: string;
	ref: string;
	accepted: boolean;
	resolved: string;
};
type IdentityDocumentVectorsFile = { identity_document: IdentityDocumentVector[] };

const doc = vectorsFile as IdentityDocumentVectorsFile;
const accepted = doc.identity_document.filter((v) => v.accepted);
const refused = doc.identity_document.filter((v) => !v.accepted);

describe("sdk/ts resolveIdentityDocument matches the sdk/go oracle vectors", () => {
	// Both partitions matter on their own: a corpus that lost every refused case
	// would leave the whole same-origin rule untested and still report green.
	it("identity-document vector sets are non-empty", () => {
		expect(accepted.length).toBeGreaterThan(0);
		expect(refused.length).toBeGreaterThan(0);
	});

	for (const v of accepted) {
		it(`resolves ${v.name} as the oracle does`, () => {
			expect(resolveIdentityDocument(v.manifest_url, v.ref)).toBe(v.resolved);
		});
	}

	for (const v of refused) {
		it(`refuses ${v.name}`, () => {
			expect(() => resolveIdentityDocument(v.manifest_url, v.ref)).toThrow();
		});
	}

	// The corpus records a verdict, not a message, so this half is per-language. A
	// refusal that names the very userinfo it is refusing puts the credential
	// wherever the caller logs its errors.
	it("a refusal does not echo the credential", () => {
		const secret = "s3cr3t";
		const cases: [string, string][] = [
			["https://a.example/.well-known/ramp.json", `https://u:${secret}@a.example/x`],
			[`https://u:${secret}@a.example/ramp.json`, "/x"],
		];
		for (const [manifestUrl, ref] of cases) {
			expect(() => resolveIdentityDocument(manifestUrl, ref)).toThrow();
			try {
				resolveIdentityDocument(manifestUrl, ref);
			} catch (err) {
				expect(String(err)).not.toContain(secret);
			}
		}
	});
});
