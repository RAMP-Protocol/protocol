// Idempotency — TS port of the sdk/go oracle (helpers/idempotency.go).
// idempotency_key is a required, persisted, settlement-bound field on the
// mutating RPCs: the server dedupes on it so a replay returns the original
// result and cannot double-charge. The SDK mints a fresh key per call by
// default; to make a call a deliberate replay the application reuses a stored
// key. The SDK never tracks keys — the server owns the dedup store.

import { encodeBase64Url } from "./base64url.ts";

// idempotencyKeyBytes is the entropy per key (128 bits -> 22 base64url chars).
const idempotencyKeyBytes = 16;

/**
 * generateIdempotencyKey returns a fresh cryptographically-random, URL-safe
 * idempotency key (16 random bytes -> base64url, 22 chars, no padding). Use it
 * once per logical operation; reuse a stored key only to deliberately replay.
 */
export function generateIdempotencyKey(): string {
	const b = crypto.getRandomValues(new Uint8Array(idempotencyKeyBytes));
	return encodeBase64Url(b);
}

/**
 * validateIdempotencyKey enforces the protocol's min_len=1 constraint, so the
 * SDK rejects an empty key before the server does.
 */
export function validateIdempotencyKey(key: string): void {
	if (key === "") {
		throw new Error("idempotency: idempotency_key must be non-empty");
	}
}
