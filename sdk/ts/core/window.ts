// Signature Window (sdk/ts/core) — TS port of the sdk/go oracle
// (core/sigwindow.go). A Window returns the RFC 9421 (created, expires) cutoffs
// (unix seconds) to stamp on the next outbound signature; it is invoked once per
// signed request. Both values derive from a single now() reading so a
// deterministic-clock test stays inside the verifier's freshness window.
//
// The clock is in the SECONDS domain (matching Go's now().Unix()); both faces
// FLOOR to integer seconds via Math.floor so the produced @signature-params
// bytes stay byte-identical to the sign-site's historical inline mint (R3).

/** A Window yields the [created, expires] unix-second cutoffs for one signature. */
export type Window = () => [created: number, expires: number];

/**
 * clockWindow returns the plain production Window: it stamps each signature with
 * clock-derived created = floor(now()) and expires = created + ttlSec. `now`
 * reads seconds (fractional allowed); the floor reproduces Go's .Unix().
 */
export function clockWindow(now: () => number, ttlSec: number): Window {
	return () => {
		const created = Math.floor(now());
		return [created, created + ttlSec];
	};
}

/**
 * monotonicWindow returns a Window whose expires cutoff strictly increases
 * across calls: it tracks floor(now()) + ttlSec but, when a burst of requests
 * lands in the same wall-clock second, bumps expires by one second per call so
 * no two back-to-back signatures share an (keyid, expires) pair — keeping
 * identical relay requests from colliding in the server's replay store. created
 * tracks floor(now()), so the pair stays clock-consistent.
 */
export function monotonicWindow(now: () => number, ttlSec: number): Window {
	let lastExpires = 0;
	return () => {
		const created = Math.floor(now());
		const floor = created + ttlSec;
		const next = lastExpires >= floor ? lastExpires + 1 : floor;
		lastExpires = next;
		return [created, next];
	};
}
