// Wire-constants parity (TypeScript side): wire.ts exposes the six wire constants
// with the exact values the Go oracle carries.
//
// sdk/ts `wire.ts` MUST expose the six wire constants with the EXACT values the
// sdk/go oracle carries. The shared vectors at
// sdk/go/helpers/testdata/wire-constants-vectors.json carry {name, value},
// referenced from the real Go exported constants (never hand-typed). The Go
// layer splits RequestIDHeader across helpers/constants.go and core/requestid.go;
// the single TS wire module exposes all six once.
//
// RED now purely because sdk/ts/src/wire.ts does not exist yet.
import { describe, it, expect } from "vitest";
// RED: sdk/ts/src/wire.ts does not exist yet (TDD red — missing face).
import * as wire from "../src/wire.ts";
import vectorsFile from "../../go/helpers/testdata/wire-constants-vectors.json";

type WireVector = { name: string; value: string };
type WireVectorsFile = { vectors: WireVector[] };

const vectors = (vectorsFile as WireVectorsFile).vectors;

// The Go identifier → the TS export name (same PascalCase→SCREAMING or camel
// choice is the implementer's; here we assert the VALUE is present under a
// matching export). Map by Go name to the TS symbol the port must export.
const exportFor: Record<string, keyof typeof wire> = {
	ContentTypeProto: "ContentTypeProto",
	ContentTypeJSON: "ContentTypeJSON",
	ConnectProtocolVersionHeader: "ConnectProtocolVersionHeader",
	ConnectProtocolVersion: "ConnectProtocolVersion",
	RequestIDHeader: "RequestIDHeader",
	SignatureAgentHeader: "SignatureAgentHeader",
};

describe("sdk/ts wire constants match the sdk/go oracle vectors", () => {
	it("wire-constants vector set is non-empty", () => {
		expect(vectors.length).toBeGreaterThan(0);
	});

	for (const v of vectors) {
		it(`wire.${v.name} === ${JSON.stringify(v.value)}`, () => {
			const sym = exportFor[v.name];
			expect(sym).toBeDefined();
			expect((wire as Record<string, unknown>)[sym as string]).toBe(v.value);
		});
	}
});
