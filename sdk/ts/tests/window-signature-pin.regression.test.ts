// Window-refactor signature regression pin (TypeScript side) — djeue M3/R3.
//
// The djeue refactor sources signInbound's (created, expires) from an injected
// Window (default clockWindow(()=>Date.now()/1000, ttlSec)) instead of the
// inline `nowSec = Math.floor(now()/1000)` mint. R3: clockWindow MUST FLOOR so
// the produced @signature-params bytes stay byte-identical. This pin captures
// the CURRENT (pre-refactor) behaviour and MUST STAY GREEN after the refactor:
//   - given a fractional now, created = floor(now/1000), expires = created+ttl,
//     emitted verbatim in the Signature-Input inner list;
//   - signInbound is byte-deterministic for a fixed key + fixed now (Ed25519).
//
// GREEN NOW by design (characterization guard, not a missing-face red). It
// imports only shipped modules; if the refactor drops the flooring or changes
// the window, the exact-string assertion below fails.
import { describe, it, expect } from "vitest";
import { signInbound } from "../core/sign.ts";
import { thumbprint } from "../src/thumbprint.ts";

async function fixedAgentKey(): Promise<CryptoKeyPair> {
	return crypto.subtle.generateKey({ name: "Ed25519" }, true, [
		"sign",
		"verify",
	]) as Promise<CryptoKeyPair>;
}

const TARGET = "https://edge.example/ramp.v1/resource";
// A fractional-millisecond now: floor(1_700_000_000_500 / 1000) = 1_700_000_000.
const NOW_MS = 1_700_000_000_500;
const TTL_SEC = 600;
const EXPECT_CREATED = 1_700_000_000;
const EXPECT_EXPIRES = 1_700_000_600;

describe("signInbound signature window survives the Window refactor byte-identically (R3)", () => {
	it("floors created and stamps created/expires verbatim in Signature-Input", async () => {
		const kp = await fixedAgentKey();
		const rawPub = new Uint8Array(
			await crypto.subtle.exportKey("raw", kp.publicKey),
		);
		const agentId = await thumbprint(rawPub);

		const req = await signInbound(kp, TARGET, {
			now: () => NOW_MS,
			ttlSec: TTL_SEC,
		});
		const sigInput = req.headers.get("signature-input");
		expect(sigInput).toBe(
			`sig1=("@method" "@target-uri");keyid="${agentId}";alg="ed25519";created=${EXPECT_CREATED};expires=${EXPECT_EXPIRES}`,
		);
	});

	it("is byte-deterministic for a fixed key + fixed now (identical signature)", async () => {
		const kp = await fixedAgentKey();
		const a = await signInbound(kp, TARGET, { now: () => NOW_MS, ttlSec: TTL_SEC });
		const b = await signInbound(kp, TARGET, { now: () => NOW_MS, ttlSec: TTL_SEC });
		expect(a.headers.get("signature-input")).toBe(b.headers.get("signature-input"));
		expect(a.headers.get("signature")).toBe(b.headers.get("signature"));
	});
});
