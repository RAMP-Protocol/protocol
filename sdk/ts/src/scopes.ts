// Scopes / entitlements — TS port of the sdk/go oracle
// (helpers/scopes.go). The subscriptions/entitlements a requester holds are a
// SUPPLIED credential: the application hands the SDK what it holds and the SDK
// plumbs it into the request. NormalizeScopes/ScopesSubset are pure, byte-
// deterministic string ops pinned to the shared scopes-vectors.json.

/**
 * normalizeScopes returns scopes with empty entries dropped, duplicates removed
 * (first-seen), and a stable (lexicographic) order — so two callers supplying
 * the same set produce identical bytes on the wire. No casing change, no
 * trimming. The sdk/go oracle returns nil for empty/all-empty input (JSON
 * null); the TS face returns `[]` (the parity comparator treats null == []).
 */
export function normalizeScopes(scopes: string[]): string[] {
	const seen = new Set<string>();
	const out: string[] = [];
	for (const s of scopes) {
		if (s === "" || seen.has(s)) continue;
		seen.add(s);
		out.push(s);
	}
	out.sort();
	return out;
}

/**
 * scopesSubset reports whether every scope in `sub` is present in `sup`. It is
 * the delegation-attenuation rule (Delegation.scopes MUST be a subset of the
 * principal's granted scopes). An empty `sub` is always a subset.
 */
export function scopesSubset(sub: string[], sup: string[]): boolean {
	const set = new Set(sup);
	for (const s of sub) {
		if (!set.has(s)) return false;
	}
	return true;
}

/**
 * applyScopes is the functional analogue of the Go ApplyScopes (which mutates a
 * proto Requester). The TS port has no generated Requester mutation face, so it
 * returns the normalized scopes array the caller stamps onto its own request.
 */
export function applyScopes(scopes: string[]): string[] {
	return normalizeScopes(scopes);
}
