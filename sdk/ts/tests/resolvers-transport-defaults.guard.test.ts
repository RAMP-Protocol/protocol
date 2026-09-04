import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
	createWellKnownEndpointResolver,
	createWellKnownKeyResolver,
	createWellKnownRequirementsReader,
} from "../resolvers/index.ts";

// Which transport each resolver takes when the caller injects none.
//
// # Why this is a test and not a sentence
//
// The rule is that a resolver's default follows its URL's PROVENANCE: a fixed,
// operator-chosen address takes the plain transport, a host another party named
// takes the guarded one. That rule is written down in three places — the Go
// oracle's WellKnownOptions.HTTP comment, docs/design-history.md, and the
// published threat model, which states it per language in a table.
//
// It has now drifted from the code twice. The scheme guard was added to the dial
// and not walked back through its callers, so a doc sentence beginning "every
// fetch" stayed standing after it stopped being true; and these ports mirrored
// the oracle's options struct without mirroring the rule, then explained the
// result in a docstring that had also stopped being true. Prose cannot detect
// either. A socket can.
//
// SO: CHANGING ANY ROW BELOW OBLIGES AN EDIT TO THE PUBLISHED THREAT MODEL
// (website/src/content/docs/security/threat-model.mdx), which names these
// postures per language. That is the whole point of the gate — the failure is
// the reminder.
//
// # One row records a gap, not a decision
//
// `endpoint resolver` REACHES here and REFUSES in Go. That is not a considered
// divergence: the host is an Offer.exchange domain, so by the rule above it
// belongs on the guarded transport in every language, and this port has not
// caught up. It is tracked separately, and the threat model names it. Do not
// read this row as endorsement — read it as the thing that will fail, loudly and
// on purpose, in the change that fixes it.
//
// # What is not here
//
// The WBA directory resolver's guarded default is pinned already, by
// resolvers-ssrf.test.ts and its Go and Python counterparts; its guard is
// additionally not opt-outable, which those cover and this would not. Asserting
// it twice would be one behaviour with two owners.
//
// This is deliberately NOT a shared corpus. A *-vectors.json has to be replayed
// by all three languages against the same expectations, and the expectations
// here legitimately DIFFER per language — that difference is the subject.

const TOUCHED = ["SKIP_SSRF", "ALLOW_INSECURE", "HTTP_PROXY", "HTTPS_PROXY"];
let saved: Record<string, string | undefined>;

// Both guards are env-driven, so the flags are cleared rather than inherited from
// whatever shell ran the suite: without this a developer with SKIP_SSRF set sees
// the guarded rows fail for a reason that has nothing to do with the defaults.
beforeEach(() => {
	saved = {};
	for (const k of TOUCHED) {
		saved[k] = process.env[k];
		delete process.env[k];
	}
});

afterEach(() => {
	for (const k of TOUCHED) {
		if (saved[k] === undefined) delete process.env[k];
		else process.env[k] = saved[k];
	}
});

/** Whether a resolver reached the loopback origin. A guarded default refuses the
 * reserved address before the request leaves the process, so "the handler ran" is
 * the observable that separates the two transports. */
async function dialObserved(
	exercise: (host: string) => Promise<unknown>,
): Promise<boolean> {
	let reached = false;
	const server: Server = createServer((req, res) => {
		reached = true;
		res.writeHead(200, { "content-type": "application/json" });
		// Anchored to the host that served it, so the endpoint face's own same-host
		// rule cannot be what refuses.
		res.end(
			JSON.stringify({
				role: "ROLE_EXCHANGE",
				endpoint: `https://${req.headers.host}`,
				keys: [],
			}),
		);
	});
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const { port } = server.address() as AddressInfo;
	try {
		// The rejection is deliberately swallowed: a guarded refusal and a happy
		// answer are both expected outcomes, and `reached` is what says which.
		await exercise(`127.0.0.1:${port}`).catch(() => undefined);
	} finally {
		await new Promise<void>((resolve) => server.close(() => resolve()));
	}
	return reached;
}

// `reaches: true` means the default is the PLAIN transport.
const ROWS: {
	name: string;
	reaches: boolean;
	why: string;
	exercise: (host: string) => Promise<unknown>;
}[] = [
	{
		name: "key resolver dials plain",
		reaches: true,
		why:
			"its URL is a fixed, operator-chosen JWKS address — nobody else can point it, " +
			"and an on-prem directory may legitimately be private",
		exercise: (host) =>
			createWellKnownKeyResolver(`http://${host}/.well-known/ramp.json`, {}).resolve("ex.v1"),
	},
	{
		name: "endpoint resolver dials plain — a tracked gap, not a decision",
		reaches: true,
		why:
			"its host is an Offer.exchange domain, so another party chose the address and " +
			"the rule says guarded. Go already refuses here; this port has not caught up",
		exercise: (host) =>
			createWellKnownEndpointResolver({ scheme: "http" }).resolveEndpoint(host),
	},
	{
		name: "requirements reader dials guarded",
		reaches: false,
		why: "its host is a RegisterRequest.exchange domain, named by the caller per call",
		exercise: (host) =>
			createWellKnownRequirementsReader({ scheme: "http" }).resolveRegistrationRequirements(host),
	},
];

describe("resolver transport defaults", () => {
	for (const row of ROWS) {
		it(row.name, async () => {
			const got = await dialObserved(row.exercise);
			const verb = (v: boolean) => (v ? "reached" : "refused");
			expect(
				got,
				`default transport ${verb(got)} the loopback origin, want ${verb(row.reaches)} — ${row.why}. ` +
					"If this change is intended, the per-language table in the published threat model has to change with it.",
			).toBe(row.reaches);
		});
	}
});
