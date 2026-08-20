// No refusal message carries a credential.
//
// Mirrors the Python sibling sdk/python/tests/test_hosts_credential_redaction.py.
//
// The endpoint rule refuses a credential and says so WITHOUT naming the value,
// because the value is the credential. That intent only holds if it survives every
// other way the same reference can be refused: a control character, a backslash in
// the userinfo, a malformed escape. Each of those is a parse failure, and a parse
// failure that named the reference put the credential back into the message — into
// the logs of every consumer resolving a manifest whose operator mistyped one.
//
// The redaction lives in the parse's error constructor rather than in the rule, so
// it also covers hostOf and hostAnchored, which this SDK exports.
//
// Message text is deliberately per-language — the shared corpus records a verdict
// and never a message — so this is a behavioural test in each port rather than a
// vector. The Go oracle still echoes here; that divergence is intentional and is
// not a parity break.
import { describe, expect, it } from "vitest";
import { hostAnchored, hostOf } from "../src/hosts.ts";
import { createWellKnownEndpointResolver } from "../resolvers/index.ts";
import type { FetchLike } from "../resolvers/http.ts";

const SECRET = "s3cr3t";

// Every shape that refuses a credential-bearing reference. The first parses and is
// refused BY THE RULE; the rest fail to parse, which is the path that leaked.
const credentialRefs = [
	`https://u:${SECRET}@exchange.example/v1`,
	`https://u:${SECRET}@exchange.example\n/v1`,
	`https://u:${SECRET}\\@evil.example/v1`,
	`https://u%zz:${SECRET}@exchange.example/v1`,
	`u:${SECRET}@exchange.example`,
	`https://u:${SECRET}@`,
	// Every shape above carries a well-formed prefix, so none of them can reach a
	// redactor that disagrees with the parse about where the authority starts. These
	// are that class: a "://" that is not a scheme separator, and an authority opened
	// by a bare "//" with no "://" in the reference at all.
	`u:${SECRET}@evil.example/x://a.example`,
	`ftp:${SECRET}@a.example://x`,
	`u:${SECRET}@a.example?q=x://y`,
	`u:${SECRET}@a.example#f://y`,
	`//u:${SECRET}@a.example`,
	// A scheme may not begin with a digit, so the parse refuses this outright — but
	// the credential still sits behind a "://" that a laxer reader would take for a
	// separator. Pinned because a redactor that reads ONLY by the parse's rule
	// leaves it untouched.
	`1https://u:${SECRET}@a.example/`,
];

const serving = (endpoint: string): FetchLike => async () => ({
	status: 200,
	text: async () => JSON.stringify({ role: "ROLE_EXCHANGE", endpoint }),
});

/** The message of whatever `call` throws, or undefined when it does not. */
function refusalOf(call: () => unknown): string | undefined {
	try {
		call();
	} catch (err) {
		return String(err);
	}
	return undefined;
}

describe("a refusal never names a credential", () => {
	for (const ref of credentialRefs) {
		it(`the endpoint rule keeps ${JSON.stringify(ref)} out of its message`, async () => {
			const r = createWellKnownEndpointResolver({ fetch: serving(ref) });
			const message = await r.resolveEndpoint("exchange.example").then(
				() => undefined,
				(e: unknown) => String(e),
			);
			expect(message).toBeDefined();
			expect(message).not.toContain(SECRET);
		});

		// The rule is not the only caller: these are public faces of this SDK.
		it(`the exported predicates keep ${JSON.stringify(ref)} out of theirs`, () => {
			expect(refusalOf(() => hostOf(ref)) ?? "").not.toContain(SECRET);
			expect(refusalOf(() => hostAnchored("exchange.example", ref)) ?? "").not.toContain(SECRET);
		});
	}

	// Redaction must not flatten every refusal into one shape. A value that PARSES
	// and carries userinfo is refused by the rule, and its message names the reason
	// rather than the reference — which is what it did before, and what the
	// parse-failure path was quietly bypassing.
	it("a well-formed credential still gets the rule's own message", async () => {
		const r = createWellKnownEndpointResolver({
			fetch: serving(`https://u:${SECRET}@exchange.example/v1`),
		});
		const message = await r.resolveEndpoint("exchange.example").then(
			() => undefined,
			(e: unknown) => (e as Error).message,
		);
		expect(message).toBe('host="exchange.example" advertises an endpoint carrying userinfo');
	});

	// The SERVING HOST, not the advertised endpoint. Every case above feeds the
	// credential in as the endpoint, and no arrangement of them reaches this branch:
	// a host carrying userinfo PARSES, so isBareHost answers false instead of
	// throwing, and the refusal that names it is the resolver's own. That value is
	// network-supplied in the real flow — it is the exchange domain an offer named.
	for (const host of [`user:${SECRET}@exchange.example`, `u:${SECRET}@exchange.example:8443`]) {
		it(`keeps a credential in the serving host ${JSON.stringify(host)} out of the refusal`, async () => {
			const r = createWellKnownEndpointResolver({
				fetch: async () => {
					throw new Error("refused before the network, so the fetch is never reached");
				},
			});
			const message = await r.resolveEndpoint(host).then(
				() => undefined,
				(e: unknown) => (e as Error).message,
			);
			expect(message).toBeDefined();
			expect(message).not.toContain(SECRET);
			expect(message).toContain("not a bare host");
		});
	}

	// The redaction is conservative, not indiscriminate: a path is not a credential.
	it("leaves an @ outside the authority alone", () => {
		expect(refusalOf(() => hostOf("https://exchange.example/p%zz@x"))).toContain("p%zz@x");
	});
});
