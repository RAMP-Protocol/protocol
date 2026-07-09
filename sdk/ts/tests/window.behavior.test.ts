// Window behaviour (TypeScript side) — TDD red for djeue.
//
// The signature Window (Go core/sigwindow.go) carries a clock → NOT vector-
// gated. Two faces:
//   - clockWindow(now, ttlSec): created = floor(now()), expires = created+ttl
//     (R3: MUST floor — Go .Unix() floors; current signInbound uses
//      Math.floor(now()); an un-floored default would change signature bytes).
//   - monotonicWindow(now, ttlSec): expires strictly increases across a burst
//     within one wall-clock second, so no two back-to-back signatures share an
//     expires cutoff (relay replay-store uniqueness).
//
// RED now purely because sdk/ts/core/window.ts does not exist yet.
import { describe, it, expect } from "vitest";
// RED: sdk/ts/core/window.ts does not exist yet (TDD red — missing face).
import { clockWindow, monotonicWindow } from "../core/window.ts";

describe("sdk/ts clockWindow floors created and adds ttl to expires (R3)", () => {
	it("created = floor(now), expires = floor(now)+ttl for a fractional now", () => {
		// A fractional-second now (seconds domain, matching Go's now().Unix()).
		const now = () => 1_700_000_000.987;
		const w = clockWindow(now, 600);
		const [created, expires] = w();
		expect(created).toBe(1_700_000_000); // floored, not 1700000000.987
		expect(expires).toBe(1_700_000_600); // created + 600, integer
		expect(Number.isInteger(created)).toBe(true);
		expect(Number.isInteger(expires)).toBe(true);
	});

	it("reads the clock on every invocation", () => {
		let t = 1_000.0;
		const w = clockWindow(() => t, 60);
		expect(w()).toEqual([1_000, 1_060]);
		t = 2_000.5;
		expect(w()).toEqual([2_000, 2_060]);
	});
});

describe("sdk/ts monotonicWindow strictly increases expires within one second", () => {
	it("bumps expires by 1 per call across a same-second burst", () => {
		const now = () => 1_700_000_000; // frozen wall-clock second
		const w = monotonicWindow(now, 600);
		const first = w();
		const second = w();
		const third = w();
		// created tracks now(); expires is strictly increasing.
		expect(first[0]).toBe(1_700_000_000);
		expect(second[1]).toBeGreaterThan(first[1]);
		expect(third[1]).toBeGreaterThan(second[1]);
	});

	it("never repeats an expires cutoff across a large same-second burst", () => {
		const w = monotonicWindow(() => 1_700_000_000, 600);
		const seen = new Set<number>();
		for (let i = 0; i < 100; i += 1) {
			const [, expires] = w();
			seen.add(expires);
		}
		expect(seen.size).toBe(100);
	});
});
