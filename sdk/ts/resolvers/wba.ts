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
// sync directory-fetch path AND the Run poller (R5) — never poller-only.

import {
  KeyRevocationListSchema,
  WBAFileSchema,
} from "../../../gen/ts/wire/schemas.ts";
import { decodeBase64Url } from "../src/base64url.ts";
import { thumbprint } from "../src/thumbprint.ts";
import { DirectoryUnavailable, KeyExpired, KeyRevoked, RevocationUnevaluated } from "./errors.ts";
import { type FetchLike, guardedFetch, fetchSoft, fetchStrict } from "./http.ts";

const WBA_DIRECTORY_PATH = "/.well-known/http-message-signatures-directory";
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
  resolve(thumbprint: string, directory: string): Promise<Uint8Array | undefined>;
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
export function newWBAKeyResolver(opts: WBAKeyResolverOptions = {}): WBAKeyResolver {
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
    this.pollMs = opts.pollIntervalMs && opts.pollIntervalMs > 0 ? opts.pollIntervalMs : DEFAULT_POLL_MS;
    this.syncDebounceMs =
      opts.syncDebounceMs && opts.syncDebounceMs > 0 ? opts.syncDebounceMs : DEFAULT_SYNC_DEBOUNCE_MS;
    this.requireRevocation = opts.requireRevocation ?? false;
    this.now = opts.now ?? Date.now;
    this.after = opts.after ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
    this.onPollArmed = opts.onPollArmed;
    this.onPollCycle = opts.onPollCycle;
    // The WBA directory host comes from the request-supplied Signature-Agent and
    // is fetched pre-auth, so the default is SSRF-guarded (matches the Go oracle).
    this.fetchFn = opts.fetch ?? guardedFetch;
  }

  async resolve(keyID: string, directory: string): Promise<Uint8Array | undefined> {
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
    if (this.requireRevocation && file.revocation_url && !this.revocationSnapshotPresent(host)) {
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
  // the sync path and the poller apply them identically (R5).
  private async refreshRevocationFor(host: string, file: WBAFile): Promise<void> {
    const revURL = file.revocation_url;
    if (!revURL || !hostAnchored(host, revURL)) return;
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

/** Whether `candidate`'s host is anchored to `anchor` — equal or a subdomain
 * (case-insensitive, full-label boundary, so "evil-a.com" is not under "a.com").
 * An SSRF guard: a cross-host revocation_url is skipped, the key stays valid. */
function hostAnchored(anchor: string, candidate: string): boolean {
  let url: URL;
  try {
    url = new URL(candidate);
  } catch {
    return false;
  }
  if (url.host === "") return false;
  const a = anchor.toLowerCase().replace(/\.$/, "");
  const c = url.host.toLowerCase().replace(/\.$/, "");
  if (a === "") return false;
  return c === a || c.endsWith(`.${a}`);
}

/** The key in `file` whose RFC 7638 thumbprint equals `keyID` (locally computed),
 * or `undefined`. Keys with an undecodable `x` are skipped. */
async function keyByThumbprint(file: WBAFile, keyID: string): Promise<WBAJwk | undefined> {
  for (const key of file.keys ?? []) {
    const pub = publicKeyOfSafe(key);
    if (!pub) continue;
    if ((await thumbprint(pub)) === keyID) return key;
  }
  return undefined;
}

/** Decode `key`'s Ed25519 public key, or `undefined` on any field/length fault. */
function publicKeyOfSafe(key: WBAJwk): Uint8Array | undefined {
  if (key.kty.toUpperCase() !== "OKP" || key.crv.toLowerCase() !== "ed25519") return undefined;
  const raw = decodeBase64Url(key.x);
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

// Document-order scan cap for activeEd25519Key: a WBA directory padded with junk
// entries beyond this many keys cannot force unbounded selection work (a DoS cap);
// a valid key listed past the first DEFAULT_ACTIVE_KEY_SCAN positions is unreachable.
const DEFAULT_ACTIVE_KEY_SCAN = 10;

/** First window-active, well-formed Ed25519 key (raw 32 bytes) from `directory`,
 * or `null`. Selects an identity's CURRENT signing key BY DOCUMENT ORDER when its
 * thumbprint is not known ahead of time — complementing WBAKeyResolver, which
 * matches a KNOWN thumbprint. Iterates the directory's keys in document order,
 * examining AT MOST the first `maxScan` (default 10 — a DoS cap so a padded
 * directory cannot force unbounded work), and returns the FIRST key that passes
 * ALL of: window-active ([not_before, not_after) half-open covers `now` (epoch-ms),
 * both bounds RFC 3339-parseable — a missing/unparseable bound makes the key
 * inactive); `kty === "OKP"` and `crv === "Ed25519"`; and a present `x` that
 * base64url-decodes to exactly 32 bytes. Any key failing any check is skipped and
 * iteration continues; a valid key listed beyond the first `maxScan` positions is
 * unreachable. Returns `null` when no examined key qualifies. Byte-parity with the
 * Go `ActiveEd25519Key` / Python `active_ed25519_key` oracles. */
export function activeEd25519Key(
  directory: WBAFile,
  now: number,
  maxScan: number = DEFAULT_ACTIVE_KEY_SCAN,
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
 * `active_ed25519_key_with_expiry` oracles. */
export function activeEd25519KeyWithExpiry(
  directory: WBAFile,
  now: number,
  maxScan: number = DEFAULT_ACTIVE_KEY_SCAN,
): { key: Uint8Array; notAfter: number } | null {
  return selectActiveEd25519Key(directory, now, maxScan);
}

/** Shared selector behind the two active-key faces: the FIRST window-active,
 * well-formed Ed25519 key in document order (cap `maxScan`), as `{ key, notAfter }`
 * (notAfter epoch-ms), or `null`. `activeEd25519Key` drops the expiry;
 * `activeEd25519KeyWithExpiry` returns it. `notAfter` reuses the SAME `Date.parse`
 * {@link keyActiveAt} used, so the two faces never disagree on the selected key. */
function selectActiveEd25519Key(
  directory: WBAFile,
  now: number,
  maxScan: number,
): { key: Uint8Array; notAfter: number } | null {
  for (const key of (directory.keys ?? []).slice(0, maxScan)) {
    if (!keyActiveAt(key, now)) continue;
    const raw = publicKeyOfSafe(key);
    if (!raw) continue;
    // not_after is guaranteed finite: keyActiveAt above rejects any key whose
    // window bounds do not parse, so the selected key always has one.
    const notAfter = Date.parse(key.not_after);
    if (Number.isNaN(notAfter)) continue; // unreachable: keyActiveAt required a parseable bound
    return { key: raw, notAfter };
  }
  return null;
}

/** Whether `now` (epoch-ms) is inside `key`'s [not_before, not_after) half-open
 * window. A missing/unparseable bound makes the key inactive — validity must be
 * explicit. */
function keyActiveAt(key: WBAJwk, now: number): boolean {
  const notBefore = Date.parse(key.not_before);
  const notAfter = Date.parse(key.not_after);
  if (Number.isNaN(notBefore) || Number.isNaN(notAfter)) return false;
  return now >= notBefore && now < notAfter;
}
