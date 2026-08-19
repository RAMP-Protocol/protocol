// The WBA identity-directory key resolver + revocation poller. Ports
// sdk/go/helpers/wbakeyresolver.go 1:1: resolve a thumbprint (the RFC 9421 keyid,
// NEVER a kid) against a WBA directory, enforcing the key's [not_before,
// not_after) window and the host's revocation snapshot. The directory host that
// Go threads through ctx (Signature-Agent) is passed EXPLICITLY as the second
// resolve argument. The gen Zod schemas decode the WBA docs (thumbprint-keyed,
// need no kid); thumbprint reuses the byte-parity-pinned primitive.
//
// The monotonic revocation guard + far-future as_of clamp + revocation priming
// live in the SHARED refresh routine (refreshRevocationFor), invoked by BOTH the
// sync directory-fetch path AND the Run poller — never poller-only.

import {
	KeyRevocationListSchema,
	WBAFileSchema,
} from "../../../gen/ts/wire/schemas.ts";
import { decodeBase64UrlStrict } from "../src/base64url.ts";
import { hostAnchored } from "../src/hosts.ts";
import { thumbprint } from "../src/thumbprint.ts";
import {
	DirectoryUnavailable,
	KeyExpired,
	KeyRevoked,
	RevocationUnevaluated,
} from "./errors.ts";
import {
	type FetchLike,
	fetchSoft,
	fetchStrict,
	guardedFetch,
} from "./http.ts";

/** The single public well-known path a WBA identity directory is served at (Web
 * Bot Auth; the identity half of the identity/commercial split — the commercial
 * overlay stays in /.well-known/ramp.json). The one shared copy across the whole SDK. */
export const WBA_DIRECTORY_PATH =
	"/.well-known/http-message-signatures-directory";

/** Build the full WBA identity-directory URL from a scheme and an already-joined
 * host: `${scheme}://${host}` + {@link WBA_DIRECTORY_PATH}. An empty scheme
 * defaults to https. A PURE string function — the host arrives ALREADY-JOINED (any
 * port-join / IPv6 bracketing is the caller's concern), there is NO env read and NO
 * scheme-in-host detection (those stay consumer glue). It mirrors the sdk/go
 * WBADirectoryURL oracle byte-for-byte, locked by the tri-replayed
 * wba-url-vectors.json corpus. */
export function wbaDirectoryURL(scheme: string, host: string): string {
	const s = scheme === "" ? "https" : scheme;
	return `${s}://${host}${WBA_DIRECTORY_PATH}`;
}
const DEFAULT_TTL_MS = 3_600_000; // 1 hour
const DEFAULT_POLL_MS = 300_000; // 300 s
const DEFAULT_SYNC_DEBOUNCE_MS = 5_000; // unknown-thumbprint force-refresh throttle
const AS_OF_SKEW_MS = 300_000; // far-future as_of clamp ceiling
const ED25519_PUBLIC_KEY_BYTES = 32;

type WBAFile = ReturnType<typeof WBAFileSchema.parse>;
type WBAJwk = NonNullable<WBAFile["keys"]>[number];

/** Options for the WBA resolver. Zero values are safe defaults; tests inject the
 * clock (`now`), the poll timer (`after`), and the armed/cycle seams. */
export interface WBAKeyResolverOptions {
	scheme?: string;
	ttlMs?: number;
	pollIntervalMs?: number;
	/** Throttle for the unknown-thumbprint force-refresh, per directory host (≤0 →
	 * 5000). The resolver runs BEFORE the ed25519 check and the host is the
	 * caller-supplied Signature-Agent, so this caps the outbound directory GETs an
	 * unauthenticated caller can drive by presenting unknown thumbprints. The
	 * TTL-cache refresh path is NOT gated by it. */
	syncDebounceMs?: number;
	/** When set, `resolve` fails closed with RevocationUnevaluated for a key whose
	 * directory declares a revocation_url but no snapshot has been fetched
	 * (unreachable or not host-anchored) — i.e. revocation could not be evaluated.
	 * Default false keeps the best-effort behavior (a declared-but-unreachable
	 * revocation channel does not block resolution). Set it where a revoked key
	 * must never resolve even if the revocation channel is down. */
	requireRevocation?: boolean;
	now?: () => number;
	after?: (ms: number) => Promise<void>;
	onPollArmed?: () => void;
	onPollCycle?: () => void;
	fetch?: FetchLike;
}

/** The WBA key face. `resolve` returns the raw Ed25519 public key, `undefined`
 * for an unknown/absent thumbprint (fall-through), and throws KeyRevoked /
 * KeyExpired / DirectoryUnavailable for the distinct fail-closed verdicts. */
export interface WBAKeyResolver {
	resolve(
		thumbprint: string,
		directory: string,
	): Promise<Uint8Array | undefined>;
	run(signal: AbortSignal): Promise<void>;
	/** Whether `keyId` (a thumbprint) is in ANY host's fetched revocation snapshot,
	 * INDEPENDENT of WBA directory membership. `resolve` gates a key only when the
	 * directory lists it (removal is not revocation), so a key resolved from another
	 * source — e.g. a static bootstrap file — is invisible to that path; `revoked`
	 * is the fail-closed hook a composite consults to reject a broker-revoked,
	 * directory-absent thumbprint. False when no snapshot has been fetched. */
	revoked(keyId: string): boolean;
}

/** Construct a WBA resolver with defaults applied. */
export function createWBAKeyResolver(
	opts: WBAKeyResolverOptions = {},
): WBAKeyResolver {
	return new WBAResolverImpl(opts);
}

interface DirEntry {
	file: WBAFile;
	exp: number;
}

interface RevSet {
	thumbprints: Set<string>;
	asOf: number;
}

class WBAResolverImpl implements WBAKeyResolver {
	private readonly scheme: string;
	private readonly ttlMs: number;
	private readonly pollMs: number;
	private readonly syncDebounceMs: number;
	private readonly requireRevocation: boolean;
	private readonly now: () => number;
	private readonly after: (ms: number) => Promise<void>;
	private readonly onPollArmed: (() => void) | undefined;
	private readonly onPollCycle: (() => void) | undefined;
	private readonly fetchFn: FetchLike;
	private readonly dirCache = new Map<string, DirEntry>();
	private readonly revSnapshots = new Map<string, RevSet>();
	// lastSync throttles the unknown-thumbprint force-refresh to one per debounce
	// window per host (anti-amplification); inflight coalesces a concurrent burst
	// of directory fetches for one host to a single in-flight GET (singleflight).
	private readonly lastSync = new Map<string, number>();
	private readonly inflight = new Map<string, Promise<WBAFile>>();

	constructor(opts: WBAKeyResolverOptions) {
		this.scheme = opts.scheme && opts.scheme !== "" ? opts.scheme : "https";
		this.ttlMs = opts.ttlMs && opts.ttlMs > 0 ? opts.ttlMs : DEFAULT_TTL_MS;
		this.pollMs =
			opts.pollIntervalMs && opts.pollIntervalMs > 0
				? opts.pollIntervalMs
				: DEFAULT_POLL_MS;
		this.syncDebounceMs =
			opts.syncDebounceMs && opts.syncDebounceMs > 0
				? opts.syncDebounceMs
				: DEFAULT_SYNC_DEBOUNCE_MS;
		this.requireRevocation = opts.requireRevocation ?? false;
		this.now = opts.now ?? Date.now;
		this.after =
			opts.after ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
		this.onPollArmed = opts.onPollArmed;
		this.onPollCycle = opts.onPollCycle;
		// The WBA directory host comes from the request-supplied Signature-Agent and
		// is fetched pre-auth, so the default is SSRF-guarded (matches the Go oracle).
		this.fetchFn = opts.fetch ?? guardedFetch;
	}

	async resolve(
		keyID: string,
		directory: string,
	): Promise<Uint8Array | undefined> {
		if (directory === "" || keyID === "") return undefined;
		const parsed = directoryBase(directory, this.scheme);
		// A malformed Signature-Agent cannot name a directory: fall-through
		// (undefined), NOT a fail-closed DirectoryUnavailable halt.
		if (!parsed) return undefined;
		const { base, host } = parsed;
		let file = await this.wbaFile(base, host);
		let key = await keyByThumbprint(file, keyID);
		if (!key) {
			// The self-heal force-refresh below bypasses the TTL cache — the lever an
			// unauthenticated caller pulls once per unknown thumbprint. Gate it to one
			// fetch per debounce window per host: outside the window the thumbprint is
			// reported unknown WITHOUT a fetch (removal-vs-rotation self-heal still
			// works — the first unknown lookup in each window refetches).
			if (!this.beginSync(host)) return undefined;
			file = await this.syncRefresh(base, host);
			key = await keyByThumbprint(file, keyID);
			if (!key) return undefined; // removal is fall-through, never revocation
		}
		if (this.isRevoked(host, keyID)) throw new KeyRevoked(`keyid=${keyID}`);
		// Fail closed on unevaluated revocation: the directory advertises a
		// revocation channel but we hold no snapshot for it, so we cannot assert the
		// key is un-revoked. Only enforced when the caller opted into
		// requireRevocation — a present-but-empty snapshot (revocation evaluated,
		// nothing revoked) is DISTINCT from an absent one and passes.
		if (
			this.requireRevocation &&
			file.revocation_url &&
			!this.revocationSnapshotPresent(host)
		) {
			throw new RevocationUnevaluated(`keyid=${keyID} host=${host}`);
		}
		if (!keyActiveAt(key, this.now())) throw new KeyExpired(`keyid=${keyID}`);
		return publicKeyOf(key);
	}

	async run(signal: AbortSignal): Promise<void> {
		while (!signal.aborted) {
			const timer = this.after(this.jitteredInterval());
			notify(this.onPollArmed);
			await Promise.race([timer, whenAborted(signal)]);
			if (signal.aborted) return;
			await this.refreshAllRevocations();
			notify(this.onPollCycle);
		}
	}

	private async wbaFile(base: string, host: string): Promise<WBAFile> {
		const entry = this.dirCache.get(host);
		if (entry && this.now() < entry.exp) return entry.file;
		return this.syncRefresh(base, host);
	}

	// beginSync reports whether an unknown-thumbprint force-refresh for host may
	// proceed now, recording the attempt when it does — at most one per debounce
	// window per host, so N unknown thumbprints for one host drive ONE fetch, not N.
	private beginSync(host: string): boolean {
		const now = this.now();
		const last = this.lastSync.get(host);
		if (last !== undefined && now - last < this.syncDebounceMs) return false;
		this.lastSync.set(host, now);
		return true;
	}

	// syncRefresh force-fetches host's directory, bypassing the TTL cache. A
	// concurrent burst for the same host coalesces to ONE in-flight GET: the first
	// caller records the promise in `inflight` (synchronously, before any await),
	// so peers awaiting the same host share it rather than each issuing a fetch.
	private syncRefresh(base: string, host: string): Promise<WBAFile> {
		const existing = this.inflight.get(host);
		if (existing) return existing;
		const pending = this.doRefresh(base, host).finally(() => {
			this.inflight.delete(host);
		});
		this.inflight.set(host, pending);
		return pending;
	}

	private async doRefresh(base: string, host: string): Promise<WBAFile> {
		const file = await this.fetchDirectory(base);
		this.dirCache.set(host, { file, exp: this.now() + this.ttlMs });
		await this.refreshRevocationFor(host, file);
		return file;
	}

	private async fetchDirectory(base: string): Promise<WBAFile> {
		const body = await fetchStrict(this.fetchFn, base + WBA_DIRECTORY_PATH);
		try {
			return WBAFileSchema.parse(JSON.parse(body));
		} catch (err) {
			throw new DirectoryUnavailable("wba directory decode", { cause: err });
		}
	}

	private isRevoked(host: string, thumbprintKey: string): boolean {
		return this.revSnapshots.get(host)?.thumbprints.has(thumbprintKey) ?? false;
	}

	// revocationSnapshotPresent reports whether a revocation snapshot has ever been
	// fetched for host. DISTINCT from "the snapshot is empty": an empty snapshot
	// means revocation WAS evaluated and nothing is revoked, whereas an absent
	// snapshot means revocation was never evaluated (revocation_url unreachable /
	// not host-anchored / not yet polled).
	private revocationSnapshotPresent(host: string): boolean {
		return this.revSnapshots.has(host);
	}

	revoked(keyId: string): boolean {
		if (keyId === "") return false;
		for (const set of this.revSnapshots.values()) {
			if (set.thumbprints.has(keyId)) return true;
		}
		return false;
	}

	// Best-effort: a missing/cross-host/failed/undecodable revocation_url leaves the
	// prior snapshot in place. The monotonic guard + as_of clamp live here so BOTH
	// the sync path and the poller apply them identically.
	private async refreshRevocationFor(
		host: string,
		file: WBAFile,
	): Promise<void> {
		const revURL = file.revocation_url;
		if (!revURL || !wbaHostAnchored(host, revURL)) return;
		const body = await fetchSoft(this.fetchFn, revURL);
		if (body === undefined) return;
		let list: ReturnType<typeof KeyRevocationListSchema.parse>;
		try {
			list = KeyRevocationListSchema.parse(JSON.parse(body));
		} catch {
			return;
		}
		this.applyRevocation(host, list);
	}

	private applyRevocation(
		host: string,
		list: ReturnType<typeof KeyRevocationListSchema.parse>,
	): void {
		let asOf = list.as_of ? Date.parse(list.as_of) : 0;
		if (Number.isNaN(asOf)) asOf = 0;
		const ceiling = this.now() + AS_OF_SKEW_MS;
		if (asOf > ceiling) asOf = ceiling; // clamp a far-future baseline (first-poll integrity)
		const next: RevSet = { thumbprints: new Set(list.revoked ?? []), asOf };
		const prev = this.revSnapshots.get(host);
		// Monotonic guard: a snapshot whose as_of is not STRICTLY newer than the one
		// held is a rollback and is ignored — a revoked thumbprint is never silently
		// un-revoked. The first seed is always accepted.
		if (prev !== undefined && asOf <= prev.asOf) return;
		this.revSnapshots.set(host, next);
	}

	private async refreshAllRevocations(): Promise<void> {
		const entries = [...this.dirCache.entries()];
		for (const [host, entry] of entries) {
			await this.refreshRevocationFor(host, entry.file);
		}
	}

	private jitteredInterval(): number {
		const delta = Math.floor(this.pollMs / 10);
		if (delta <= 0) return this.pollMs;
		return this.pollMs + Math.floor(Math.random() * (2 * delta + 1)) - delta;
	}
}

function notify(hook: (() => void) | undefined): void {
	if (hook) hook();
}

function whenAborted(signal: AbortSignal): Promise<void> {
	if (signal.aborted) return Promise.resolve();
	return new Promise((resolve) => {
		signal.addEventListener("abort", () => resolve(), { once: true });
	});
}

/** Normalize a Signature-Agent value (bare host, host:port, or full URL) into a
 * scheme://host base and its host key, or `undefined` when it names no host. */
function directoryBase(
	ref: string,
	scheme: string,
): { base: string; host: string } | undefined {
	const withScheme = ref.includes("://") ? ref : `${scheme}://${ref}`;
	let url: URL;
	try {
		url = new URL(withScheme);
	} catch {
		return undefined;
	}
	if (url.host === "") return undefined;
	return { base: `${url.protocol}//${url.host}`, host: url.host };
}

/** Whether `candidate` is anchored to `anchor` — the same host and port, or a
 * subdomain of that host on that port. An SSRF guard: a cross-host
 * revocation_url is skipped, and the key stays valid.
 *
 * The predicate itself is the shared hostAnchored, which is the ONE place the
 * rule is written; this wrapper exists for the two things that are local to WBA.
 * It answers a bool rather than throwing, because a directory that names an
 * unparseable revocation_url is simply not anchored and its caller logs a skip.
 * And it requires an ABSOLUTE reference: the shared predicate reads a schemeless
 * value as https, which is right for an exchange domain and wrong here, where the
 * value is a URL a directory published rather than a domain it named.
 *
 * This used to be a private near-namesake that compared `URL.host`. It agreed on
 * ordinary hosts and diverged on the ones that matter: a default port folded away
 * at parse time cannot borrow a scheme from the other side, so an anchor of
 * "a.example:80" and a candidate of "http://a.example:80" reached two different
 * answers, and a directory that spelled its port out stopped anchoring its own
 * revocation URL. A skipped revocation poll leaves a revoked key resolving. */
function wbaHostAnchored(anchor: string, candidate: string): boolean {
	if (!candidate.includes("://")) return false;
	try {
		return hostAnchored(anchor, candidate);
	} catch {
		return false;
	}
}

/** The key in `file` whose RFC 7638 thumbprint equals `keyID` (locally computed),
 * or `undefined`. Keys with an undecodable `x` are skipped. */
async function keyByThumbprint(
	file: WBAFile,
	keyID: string,
): Promise<WBAJwk | undefined> {
	for (const key of file.keys ?? []) {
		const pub = publicKeyOfSafe(key);
		if (!pub) continue;
		if ((await thumbprint(pub)) === keyID) return key;
	}
	return undefined;
}

/** Decode `key`'s Ed25519 public key, or `undefined` on any field/length fault. */
function publicKeyOfSafe(key: WBAJwk): Uint8Array | undefined {
	// kty/crv are matched CASE-INSENSITIVELY — a deliberate lenient SDK convention
	// (RFC 7517/8037 specify the exact-case "OKP" / "Ed25519"); the three SDKs accept
	// any case identically so a case-varying directory resolves the SAME key.
	if (key.kty.toUpperCase() !== "OKP" || key.crv.toLowerCase() !== "ed25519")
		return undefined;
	// JWK OKP `x` is UNPADDED base64url (RFC 8037); reject padding / the standard
	// alphabet so this matches Go's base64.RawURLEncoding and the tri-language
	// selector picks the SAME key on a malformed-`x` directory.
	const raw = decodeBase64UrlStrict(key.x);
	if (!raw || raw.length !== ED25519_PUBLIC_KEY_BYTES) return undefined;
	return raw;
}

/** Decode `key`'s public key; throws only for a key that already matched by
 * thumbprint (so the decode is known-good). */
function publicKeyOf(key: WBAJwk): Uint8Array {
	const raw = publicKeyOfSafe(key);
	if (!raw) throw new DirectoryUnavailable("wba jwk decode");
	return raw;
}

/** First window-active, well-formed Ed25519 key (raw 32 bytes) from `directory`,
 * or `null`. Selects an identity's signing key BY DOCUMENT ORDER when its thumbprint
 * is not known ahead of time — complementing WBAKeyResolver, which matches a KNOWN
 * thumbprint. Iterates the directory's keys in document order and returns the FIRST
 * key that passes ALL of: window-active ([not_before, not_after) half-open covers
 * `now` (epoch-ms), both bounds RFC 3339-parseable — a missing/unparseable bound
 * makes the key inactive); `kty === "OKP"` and `crv === "Ed25519"` matched
 * CASE-INSENSITIVELY (a deliberate lenient SDK convention: RFC 7517/8037 specify the
 * exact-case "OKP" / "Ed25519", but all three SDKs accept any case IDENTICALLY so a
 * case-varying directory resolves the SAME key everywhere); and a present `x` that
 * base64url-decodes to exactly 32 bytes. Any key failing any check is skipped and
 * iteration continues.
 *
 * The result is the first window-active key in document order — this SDK's
 * deterministic tie-break, NOT a normative "current" key: the protocol permits
 * several simultaneously-active keys during overlap rotation and defines no "first".
 *
 * `maxScan` is an OPTIONAL document-order bound. `undefined` (the default) scans the
 * WHOLE directory — unbounded, so a valid key at any position is reachable; a silent
 * cap would make a high-position key indistinguishable from "no active key" (a
 * DoS-by-directory-padding footgun). A defined bound caps the scan at
 * `Math.max(0, maxScan)` keys (0 or negative scans none); when a positive bound is
 * exhausted while more keys remain, the exhaustion is logged. Returns `null` when no
 * examined key qualifies (or `directory` is null/undefined). Byte-parity with the
 * Go `ActiveEd25519Key` / Python `active_ed25519_key` oracles.
 *
 * REVOCATION: this selector screens ONLY validity windows and key well-formedness —
 * it does NOT consult any revocation channel. A key that was emergency-revoked but
 * is still window-active in a (possibly CDN-cached) directory WILL be selected. A
 * caller on a VERIFICATION path MUST NOT trust the result until it has screened the
 * selected key's RFC 7638 thumbprint against the resolver's revoked-thumbprint set
 * (`WBAKeyResolver.revoked` / a revocation snapshot); otherwise adopting this
 * selector defeats emergency revocation. Prefer {@link activeEd25519KeyScreened},
 * which folds that screen into selection. This bare form is for non-verification
 * callers only. */
export function activeEd25519Key(
	directory: WBAFile,
	now: number,
	maxScan?: number,
): Uint8Array | null {
	return selectActiveEd25519Key(directory, now, maxScan)?.key ?? null;
}

/** Like {@link activeEd25519Key}, but ALSO returns the selected key's expiry.
 * Runs the IDENTICAL document-order selection and returns `{ key, notAfter }` for
 * the FIRST qualifying key — the raw 32 bytes plus the SAME `not_after` the window
 * check parsed, as epoch-ms (the module's time convention). A downstream caller
 * (e.g. an offer-key cache) clamps its cache TTL to `min(now + ttl, notAfter)` so
 * a cached key never outlives its validity window. `notAfter` is guaranteed
 * finite — selection required it (a key with a missing/unparseable bound is
 * inactive and skipped). Returns `null` when no examined key qualifies.
 * Byte-parity with the Go `ActiveEd25519KeyWithExpiry` / Python
 * `active_ed25519_key_with_expiry` oracles.
 *
 * REVOCATION: like {@link activeEd25519Key}, this bare form does NOT consult
 * revocation — it can return a window-active-but-revoked key. A VERIFICATION path
 * MUST screen the result, or use the revocation-aware
 * {@link activeEd25519KeyWithExpiryScreened} instead. */
export function activeEd25519KeyWithExpiry(
	directory: WBAFile,
	now: number,
	maxScan?: number,
): { key: Uint8Array; notAfter: number } | null {
	return selectActiveEd25519Key(directory, now, maxScan);
}

/** {@link activeEd25519Key} made REVOCATION-AWARE. Runs the same document-order
 * window + well-formedness selection but ALSO skips any key whose RFC 7638
 * thumbprint `revoked` reports true, so a window-active-but-revoked key is never
 * returned. It is the selector a VERIFICATION path adopts — folding the revoked-set
 * screen the bare {@link activeEd25519Key} leaves to the caller into selection
 * itself, so an emergency-revoked key still listed in a CDN-cached directory is
 * passed over for the next active, non-revoked key. `revoked` is REQUIRED: pass a
 * predicate over the resolver's revoked-thumbprint set (e.g. `WBAKeyResolver.revoked`)
 * or, for a caller with no revocation channel, an explicit `() => false` to make the
 * waiver visible. It is ASYNC because screening computes each candidate's RFC 7638
 * thumbprint (the SAME `crypto.subtle` primitive `WBAKeyResolver.resolve` keys on).
 * Returns `null` when no examined, non-revoked key qualifies. */
export async function activeEd25519KeyScreened(
	directory: WBAFile,
	now: number,
	revoked: (thumbprint: string) => boolean,
	maxScan?: number,
): Promise<Uint8Array | null> {
	return (
		(await selectActiveEd25519KeyScreened(directory, now, revoked, maxScan))
			?.key ?? null
	);
}

/** {@link activeEd25519KeyWithExpiry} made REVOCATION-AWARE (see
 * {@link activeEd25519KeyScreened}): the same selection, plus a skip of any key whose
 * RFC 7638 thumbprint `revoked` reports true, returned with the selected key's
 * `notAfter` for cache-TTL clamping. `revoked` is REQUIRED; ASYNC for the same
 * thumbprint reason. Returns `null` when no examined, non-revoked key qualifies. */
export async function activeEd25519KeyWithExpiryScreened(
	directory: WBAFile,
	now: number,
	revoked: (thumbprint: string) => boolean,
	maxScan?: number,
): Promise<{ key: Uint8Array; notAfter: number } | null> {
	return selectActiveEd25519KeyScreened(directory, now, revoked, maxScan);
}

/** Shared REVOCATION-AWARE selector behind the two screened faces: the FIRST
 * window-active, well-formed, non-revoked Ed25519 key in document order (cap
 * `maxScan`), as `{ key, notAfter }`, or `null`. Mirrors {@link selectActiveEd25519Key}
 * with the added thumbprint-revocation skip; async because the thumbprint is. */
async function selectActiveEd25519KeyScreened(
	directory: WBAFile,
	now: number,
	revoked: (thumbprint: string) => boolean,
	maxScan?: number,
): Promise<{ key: Uint8Array; notAfter: number } | null> {
	const { scanned, keys } = scanWindow(directory, maxScan);
	for (const key of scanned) {
		if (!keyActiveAt(key, now)) continue;
		const raw = publicKeyOfSafe(key);
		if (!raw) continue;
		// Revocation screen: skip a window-active key whose thumbprint is revoked, so an
		// emergency-revoked key still listed in a CDN-cached directory is never selected.
		if (revoked(await thumbprint(raw))) continue;
		const notAfter = parseRfc3339Ms(key.not_after);
		if (Number.isNaN(notAfter)) continue; // unreachable: keyActiveAt required a parseable bound
		return { key: raw, notAfter };
	}
	logScanExhaustion(maxScan, keys.length);
	return null;
}

/** Shared selector behind the two active-key faces: the FIRST window-active,
 * well-formed Ed25519 key in document order (UNBOUNDED by default; `maxScan`
 * optionally caps it), as `{ key, notAfter }` (notAfter epoch-ms), or `null`.
 * `activeEd25519Key` drops the expiry; `activeEd25519KeyWithExpiry` returns it.
 * `notAfter` reuses the SAME `Date.parse` {@link keyActiveAt} used, so the two faces
 * never disagree on the selected key. */
function selectActiveEd25519Key(
	directory: WBAFile,
	now: number,
	maxScan?: number,
): { key: Uint8Array; notAfter: number } | null {
	const { scanned, keys } = scanWindow(directory, maxScan);
	for (const key of scanned) {
		if (!keyActiveAt(key, now)) continue;
		const raw = publicKeyOfSafe(key);
		if (!raw) continue;
		// not_after is guaranteed finite: keyActiveAt above rejects any key whose
		// window bounds do not parse, so the selected key always has one.
		const notAfter = parseRfc3339Ms(key.not_after);
		if (Number.isNaN(notAfter)) continue; // unreachable: keyActiveAt required a parseable bound
		return { key: raw, notAfter };
	}
	logScanExhaustion(maxScan, keys.length);
	return null;
}

/** Resolve the document-order scan window shared by both selectors. A null/undefined
 * `directory` is guarded (empty scan, never a throw), matching Go's nil guard.
 * `maxScan` undefined scans EVERY key (unbounded); a defined bound caps the scan at
 * `Math.max(0, maxScan)` keys — 0 or negative scans none, matching Go's clamp-to-zero
 * and Python's `keys[: max(0, n)]`. Returns the full key list too so the caller can
 * detect bounded exhaustion. */
function scanWindow(
	directory: WBAFile,
	maxScan?: number,
): { scanned: WBAJwk[]; keys: WBAJwk[] } {
	const keys = directory?.keys ?? [];
	const scanned =
		maxScan === undefined ? keys : keys.slice(0, Math.max(0, maxScan));
	return { scanned, keys };
}

/** Bounded-scan exhaustion signal: a positive explicit bound was exhausted while the
 * directory held MORE keys than the bound, so a valid key beyond the cap is
 * unreachable. Warn rather than let a bounded miss masquerade as a genuine "no active
 * key" — the DoS-by-padding footgun the unbounded default avoids. */
function logScanExhaustion(
	maxScan: number | undefined,
	totalKeys: number,
): void {
	if (maxScan !== undefined && maxScan > 0 && maxScan < totalKeys) {
		console.warn(
			`active-key scan hit explicit max_scan bound without selecting a key; a valid key beyond the cap is unreachable (max_scan=${maxScan}, total_keys=${totalKeys})`,
		);
	}
}

/** Parse an RFC 3339 instant to epoch-ms, REQUIRING an explicit UTC offset
 * (`Z`/`z` or `±HH:MM`). An offset-less string — which bare `Date.parse` would
 * silently interpret in the host's LOCAL zone — returns `NaN`, so the key is
 * treated as inactive. This keeps parity with Go's time.Parse(time.RFC3339) and
 * Python's offset-required `_parse_rfc3339`, both of which reject an offset-less
 * bound rather than guessing a zone. */
function parseRfc3339Ms(value: string | undefined): number {
	if (!value) return Number.NaN;
	// RFC 3339 mandates a time-offset after the time component: 'Z'/'z' or ±HH:MM.
	if (!/([Zz]|[+-]\d{2}:\d{2})$/.test(value)) return Number.NaN;
	return Date.parse(value);
}

/** Whether `now` (epoch-ms) is inside `key`'s [not_before, not_after) half-open
 * window. A missing/unparseable/offset-less bound makes the key inactive —
 * validity must be explicit. */
function keyActiveAt(key: WBAJwk, now: number): boolean {
	const notBefore = parseRfc3339Ms(key.not_before);
	const notAfter = parseRfc3339Ms(key.not_after);
	if (Number.isNaN(notBefore) || Number.isNaN(notAfter)) return false;
	return now >= notBefore && now < notAfter;
}
