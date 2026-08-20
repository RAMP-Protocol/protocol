import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

// Structural guard for the IO-leaf invariant.
//
// Two trees bear IO: the resolver faces (sdk/ts/resolvers/), which fetch JWKS / WBA
// directories / ramp.json, and the client (sdk/ts/client/), which speaks the RAMP
// RPCs and the delivery fetch. Both dial over an injected transport whose default is
// a maintained undici client with the SSRF guard. The pure L1/L2 tree (sdk/ts/core
// + sdk/ts/src) is transport-neutral by contract — it owns no keys, opens no
// sockets, and MUST NOT depend on either. Dependency flows one way only:
// {resolvers,client}/ -> {core,src} (they reuse thumbprint, base64url, the signing
// and verifying faces), never the reverse. A pure-tree file that imports from
// resolvers/ or client/ OR pulls in the undici client directly would drag IO into
// the transport-neutral core — the undici dependency is scoped to the IO trees —
// and is exactly the regression this guard bans.
//
// This complements the existing core transport-neutrality guard (which bans
// framework imports); here we ban the IO module from leaking UP into the pure tree.
//
// Whitespace-tolerant regex on purpose; the meta-tests exercise the detector.

const dirPath = (name: string): string =>
	fileURLToPath(new URL(`../${name}`, import.meta.url));

const PURE_DIRS = ["core", "src"];
// The trailing separator is OPTIONAL, and that is the whole fix: `from "../client/x.ts"`
// was caught while `from "../client"` — the extensionless directory spelling, which is
// exactly what the package export map publishes — sailed past, as did `from
// "../resolvers"`. A guard that misses the spelling a consumer is told to use is worse
// than no guard, because it reports zero offenders either way.
const RESOLVERS_IMPORT = /from\s+["'][^"']*\/(resolvers|client)(\/|["'])/;
// The maintained HTTP client AND node's own dialing modules are scoped to the IO
// tree; a pure-tree file importing any of them is the same IO leak as importing
// resolvers/. Parity with the Python io-leaf guard, which bans httpx/httpcore/urllib
// in the pure core — here we ban undici plus node:http / node:https / node:net (the
// node dial surface, which a naive undici-only ban would let slip). The optional
// "node:" prefix is matched so `import http from "http"` is caught too.
// `import "undici"` (no `from`) and `await import("undici")` reach the same module by a
// spelling the from-clause pattern cannot see, so the module name is matched wherever it
// is quoted rather than only after `from`.
const DIAL_MODULE =
	String.raw`(?:undici|(?:node:)?https?|(?:node:)?net|(?:node:)?dns(?:\/promises)?)`;
const DIAL_MODULE_IMPORT = new RegExp(
	String.raw`(?:from|import\s*\(?|require\s*\()\s*\(?\s*["']${DIAL_MODULE}["']`,
);

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

	// The spellings the guard used to miss. Each reaches the same module; a detector that
	// sees only one of them reports zero offenders while the leak is right there — and the
	// extensionless directory form is the one the package export map publishes, so it is
	// the spelling a consumer is told to use.
	it("[meta positive] catches the extensionless directory spelling", () => {
		expect(importsIo('import { createClient } from "../client";')).toBe(true);
		expect(importsIo('import { ssrfGuard } from "../resolvers";')).toBe(true);
	});

	it("[meta positive] catches a side-effect import and a dynamic one", () => {
		expect(importsIo('import "undici";')).toBe(true);
		expect(importsIo('const { request } = await import("undici");')).toBe(true);
		expect(importsIo('const net = require("node:net");')).toBe(true);
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
