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
// a port on English rather than on behaviour. Two things about the message ARE
// pinned, and neither is wording — see `refusalMessage` below.
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

// The one refusal this port can produce WITHOUT any rule having fired: the
// try/catch around the URL constructor. It rewrites a TypeError into the
// documented error family, which is right for a caller and wrong for this
// suite — a vector refused only because the parser threw looks exactly like one
// refused by a rule, and the corpus records verdicts, not messages, so nothing
// else can tell them apart. A rule ported as a comment would still show green.
const BACKSTOP_MESSAGE = "identity document: reference cannot be resolved against the manifest URL";

// Runs a refusal and hands back its message, so an assertion can be made about
// the message instead of only about the fact that something was thrown. Fails
// when the call RESOLVES, which is the half a bare toThrow() was there for.
function refusalMessage(manifestUrl: string, ref: string): string {
	let resolvedTo: string;
	try {
		resolvedTo = resolveIdentityDocument(manifestUrl, ref);
	} catch (err) {
		return err instanceof Error ? err.message : String(err);
	}
	throw new Error(`expected a refusal, got ${resolvedTo}`);
}

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
			const message = refusalMessage(v.manifest_url, v.ref);
			// The documented error family, not the wording. This is what keeps a
			// stray TypeError from a rule path counting as a refusal if the
			// backstop is ever narrowed or removed.
			expect(message).toMatch(/^identity document: /);
			// And the refusal came from a RULE. True for every vector today; it
			// starts failing the moment one is refused by the parser instead.
			expect(message).not.toBe(BACKSTOP_MESSAGE);
		});
	}

	// The corpus records a verdict, not a message, so this half is per-language. A
	// refusal that names the very userinfo it is refusing puts the credential
	// wherever the caller logs its errors.
	//
	// The cases reach DIFFERENT refusals on purpose. Five of them carry the
	// credential somewhere no parser reads as userinfo — a reference that does not
	// parse at all, and opaque forms with no authority component — so the userinfo
	// checks never fire and the string travels on to a much later refusal. The last
	// two put it on the BASE, which is the only way to reach two of the refusals at
	// all. This is the same set the Go oracle covers.
	it("a refusal does not echo the credential", () => {
		const secret = "s3cr3t";
		const cases: [string, string][] = [
			["https://a.example/.well-known/ramp.json", `https://u:${secret}@a.example/x`],
			[`https://u:${secret}@a.example/ramp.json`, "/x"],
			["https://a.example/.well-known/ramp.json", `https://u:${secret}@a.example/%zz`],
			["https://a.example/.well-known/ramp.json", `https:u:${secret}@a.example/x`],
			["https://a.example/.well-known/ramp.json", `u:${secret}@a.example/x`],
			[`https:u:${secret}@a.example/ramp.json`, "/x"],
			[`u:${secret}@a.example/ramp.json`, "/x"],
		];
		for (const [manifestUrl, ref] of cases) {
			expect(refusalMessage(manifestUrl, ref)).not.toContain(secret);
		}
	});
});
