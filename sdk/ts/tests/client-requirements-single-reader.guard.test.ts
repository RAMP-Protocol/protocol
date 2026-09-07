import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

// The default requirements reader is built ONCE per client, never once per call.
//
// The reader's default transport is the SSRF-guarded one, and guardedFetchFromEnv()
// constructs a dispatcher on every invocation. So `?? createWellKnownRequirementsReader()`
// written at the call site opens one connection pool per registration and closes none —
// the guard fix and this one are the same change, and splitting them would trade an
// unguarded dial for a socket leak.
//
// It is resolved in resolve(), beside the verifier and the two sends, which is the tier
// Go resolves the same default at (connect.NewClient) and where every other per-client
// dependency already lives.
//
// Structural rather than behavioral, per the same exception resolvers-wba-path-dedup
// takes: what went wrong was WHERE the constructor was called, and a leaked dispatcher
// has no observable it reports. Counting sockets would pin Node's pooling rather than
// this decision. The detector is whitespace-tolerant so a formatter reflow cannot let a
// revert slip; the meta-tests below exercise that.

const clientPath = fileURLToPath(new URL("../client/index.ts", import.meta.url));

function readClient(): string {
	return readFileSync(clientPath, "utf8");
}

/** Every construction of the default reader, wherever it appears. */
const CONSTRUCTS = /createWellKnownRequirementsReader\s*\(/g;

/** The one construction that is allowed: the field on the resolved-once record. */
const IN_RESOLVED =
	/requirements\s*:\s*\n?\s*opts\.registrationRequirements\s*\?\?\s*\n?\s*createWellKnownRequirementsReader\s*\(\s*\)/;

/** The shape this replaced, and the one a revert would reintroduce: the reader built
 * inside the verb's own helper, where it runs per registration. */
const AT_THE_CALL_SITE =
	/const\s+reader\s*=\s*\n?\s*r?\.?opts\.registrationRequirements\s*\?\?\s*\n?\s*createWellKnownRequirementsReader\s*\(\s*\)/;

describe("the default requirements reader is constructed once per client", () => {
	it("is constructed in exactly one place", () => {
		expect(readClient().match(CONSTRUCTS)).toHaveLength(1);
	});

	it("constructs it on the resolved-once record, with the transports", () => {
		expect(IN_RESOLVED.test(readClient())).toBe(true);
	});

	it("does not construct it at the call site", () => {
		expect(AT_THE_CALL_SITE.test(readClient())).toBe(false);
	});

	// Meta-tests: the detectors match the shapes they claim to, reflowed as a
	// formatter would leave them. Without these a typo in a regex reads as a pass.
	it("detects the call-site shape it exists to forbid", () => {
		expect(
			AT_THE_CALL_SITE.test(
				"const reader =\n\t\tr.opts.registrationRequirements ?? createWellKnownRequirementsReader();",
			),
		).toBe(true);
	});

	it("detects the resolved-once shape across a line break", () => {
		expect(
			IN_RESOLVED.test(
				"requirements:\n\t\t\topts.registrationRequirements ?? createWellKnownRequirementsReader(),",
			),
		).toBe(true);
	});
});
