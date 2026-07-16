// Cross-language WBA-directory URL-builder parity (TypeScript side).
//
// sdk/ts wbaDirectoryURL MUST reproduce the sdk/go WBADirectoryURL oracle's built
// URL for EVERY vector in sdk/go/resolvers/testdata/wba-url-vectors.json. Each
// vector is {label, scheme, host, expected_url}: scheme/host are the two explicit
// builder args (scheme empty->https, host arrives ALREADY-JOINED), expected_url is
// the string the REAL Go builder emitted.
//
// The builder is a PURE string function: `${scheme}://${host}` + the single shared
// /.well-known/http-message-signatures-directory path constant, with empty scheme
// defaulting to https and NO env read / NO port-join / NO scheme-in-host detection
// (those stay consumer glue). Replaying the corpus proves the TS builder agrees
// with the Go/Python builders byte-for-byte across: https-default (empty scheme),
// explicit-http, host-with-port, and IPv6 pass-through of an already-bracketed host.
//
// TDD-red: wbaDirectoryURL is not exported from the resolvers barrel yet, and
// sdk/go/resolvers/testdata/wba-url-vectors.json is not emitted yet — so both the
// import and the corpus import fail until the builder + corpus land.
import { describe, expect, it } from "vitest";

// RED: corpus not emitted yet (Go emitter lands it in the implement step).
import corpus from "../../go/resolvers/testdata/wba-url-vectors.json";
// RED: wbaDirectoryURL is not exported from the resolvers barrel yet.
import { wbaDirectoryURL } from "../resolvers/index.ts";

interface WbaUrlVector {
	label: string;
	scheme: string;
	host: string;
	expected_url: string;
}
interface WbaUrlCorpus {
	note: string;
	vectors: WbaUrlVector[];
}

const c = corpus as WbaUrlCorpus;

// The corpus MUST cover exactly these behaviors (stated here as the contract so a
// thinner corpus fails this suite, not just the completeness gate).
const REQUIRED_LABELS = [
	"https-default",
	"explicit-http",
	"host-with-port",
	"ipv6-passthrough",
];

describe("sdk/ts wbaDirectoryURL matches the sdk/go WBADirectoryURL oracle", () => {
	it("has a non-empty vector corpus", () => {
		expect(c.vectors.length).toBeGreaterThan(0);
	});

	it("covers the required behaviors", () => {
		const labels = new Set(c.vectors.map((v) => v.label));
		const missing = REQUIRED_LABELS.filter((l) => !labels.has(l));
		expect(missing).toEqual([]);
	});

	for (const v of c.vectors) {
		it(v.label, () => {
			expect(wbaDirectoryURL(v.scheme, v.host)).toBe(v.expected_url);
		});
	}
});
