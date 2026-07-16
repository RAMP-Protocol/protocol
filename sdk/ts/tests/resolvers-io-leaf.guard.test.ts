import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

// Structural guard for the resolver IO-leaf invariant (bsh8k).
//
// The resolver faces (sdk/ts/resolvers/) are the SDK's ONLY IO-bearing tree: they
// fetch JWKS / WBA directories / ramp.json over an injected transport (default a
// maintained undici client with the SSRF guard). The pure L1/L2 tree (sdk/ts/core
// + sdk/ts/src) is transport-neutral by contract — it owns no keys, opens no
// sockets, and MUST NOT depend on the IO tree. Dependency flows one way only:
// resolvers/ -> {core,src} (it reuses thumbprint + base64url), never the reverse.
// A pure-tree file that imports from resolvers/ OR pulls in the undici client
// directly would drag IO into the transport-neutral core — the undici dependency
// is scoped to the IO tree — and is exactly the regression this guard bans.
//
// This complements the existing core transport-neutrality guard (which bans
// framework imports); here we ban the IO module from leaking UP into the pure tree.
//
// Whitespace-tolerant regex on purpose; the meta-tests exercise the detector.

const dirPath = (name: string): string =>
	fileURLToPath(new URL(`../${name}`, import.meta.url));

const PURE_DIRS = ["core", "src"];
const RESOLVERS_IMPORT = /from\s+["'][^"']*\/resolvers\//;
// The maintained HTTP client AND node's own dialing modules are scoped to the IO
// tree; a pure-tree file importing any of them is the same IO leak as importing
// resolvers/. Parity with the Python io-leaf guard, which bans httpx/httpcore/urllib
// in the pure core — here we ban undici plus node:http / node:https / node:net (the
// node dial surface, which a naive undici-only ban would let slip). The optional
// "node:" prefix is matched so `import http from "http"` is caught too.
const DIAL_MODULE_IMPORT =
	/from\s+["'](?:undici|(?:node:)?https?|(?:node:)?net|(?:node:)?dns(?:\/promises)?)["']/;

// tsFilesUnder walks `dir` RECURSIVELY (a nested pure-tree subdir must not become a
// blind spot the way a non-recursive scan would leave one — parity with the Python
// guard's tree walk).
function tsFilesUnder(dir: string): string[] {
	const out: string[] = [];
	for (const e of readdirSync(dirPath(dir), { withFileTypes: true })) {
		if (e.isDirectory()) {
			out.push(...tsFilesUnder(`${dir}/${e.name}`));
		} else if (
			e.isFile() &&
			e.name.endsWith(".ts") &&
			!e.name.endsWith(".test.ts")
		) {
			out.push(`${dir}/${e.name}`);
		}
	}
	return out;
}

// importsIo is the pure predicate (extracted so meta-tests can exercise it): a
// pure-tree file leaks IO if it imports the resolvers module OR any dialing module
// (undici / node:http / node:https / node:net / node:dns).
function importsIo(source: string): boolean {
	return RESOLVERS_IMPORT.test(source) || DIAL_MODULE_IMPORT.test(source);
}

describe("resolver IO-leaf structural guard", () => {
	it("no file in the pure IO-free tree (core/src) imports the IO resolvers module or undici", () => {
		const offenders: string[] = [];
		for (const dir of PURE_DIRS) {
			for (const rel of tsFilesUnder(dir)) {
				if (importsIo(readFileSync(dirPath(rel), "utf8"))) offenders.push(rel);
			}
		}
		expect(offenders).toEqual([]);
	});

	it("the resolvers reuse the pure-tree primitives (one-directional dependency)", () => {
		const wba = readFileSync(dirPath("resolvers/wba.ts"), "utf8");
		expect(/from\s+["'][^"']*\/src\/thumbprint/.test(wba)).toBe(true);
		const jwks = readFileSync(dirPath("resolvers/jwks.ts"), "utf8");
		expect(/from\s+["'][^"']*\/src\/base64url/.test(jwks)).toBe(true);
	});

	// --- meta-tests: exercise the detector against synthetic source ------------
	it("[meta positive] catches a pure-tree file importing resolvers", () => {
		expect(
			importsIo('import { createWBAKeyResolver } from "../resolvers/index.ts";'),
		).toBe(true);
	});

	it("[meta positive] catches a pure-tree file importing the undici client", () => {
		expect(importsIo('import { fetch } from "undici";')).toBe(true);
	});

	it("[meta positive] catches the node dial modules (http/https/net/dns), prefixed or not", () => {
		expect(importsIo('import http from "node:http";')).toBe(true);
		expect(importsIo('import https from "https";')).toBe(true);
		expect(importsIo('import net from "node:net";')).toBe(true);
		expect(importsIo('import { connect } from "net";')).toBe(true);
		expect(importsIo('import { lookup } from "node:dns/promises";')).toBe(true);
	});

	it("[meta negative] passes a pure-tree file importing only pure primitives", () => {
		expect(
			importsIo('import { thumbprint } from "../src/thumbprint.ts";'),
		).toBe(false);
	});

	it("[meta would-be-missed] catches a reformatted import a naive substring would slip", () => {
		const reformatted =
			'import {\n  createWBAKeyResolver,\n}\n  from   "../resolvers/wba.ts";';
		expect(importsIo(reformatted)).toBe(true);
	});
});
