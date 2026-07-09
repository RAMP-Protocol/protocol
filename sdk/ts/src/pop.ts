import { thumbprint } from "./thumbprint.ts";
import { decodeBase64Url, utf8Bytes } from "./base64url.ts";
import { opaqueUrl } from "./opaque-url.ts";

// Proof-of-possession verification for delivery-URL identity binding (ADR-013),
// relocated from the app edge (src/edge/src/pop.ts) as a pure L1 helper.
//
// When a signed URL carries an `agent_id` (the agent's RFC 7638 thumbprint), a
// code-capable edge requires the fetcher to prove possession of the bound key —
// fully offline:
//
//   1. present its raw Ed25519 public key in `X-RAMP-Agent-Key`, and
//   2. sign the GET with RFC 9421 over `@method` + `@target-uri`,
//
// and the edge enforces the 3-way identity:
//
//   agent_id (URL) == keyid (Signature-Input) == thumbprint(presented key)
//
// The Ed25519 verify primitive is INJECTABLE (input.verifyEd25519) so a runtime
// without WebCrypto Ed25519 (Fastly Compute) can supply its own — the byte
// contract is the signature base, not the primitive. The default primitive is
// WebCrypto crypto.subtle, which observes byte-identical output on the default
// path. Byte-parity guard: the pop vectors are produced by the sdk/go signer
// over the same @method/@target-uri base (sigbase.go buildSignatureBase).

export const AGENT_KEY_HEADER = "x-ramp-agent-key";

const ED25519_PUBLIC_KEY_BYTES = 32;

export type PopFailure =
  | "missing_agent_key"
  | "bad_agent_key"
  | "missing_sig"
  | "malformed_sig_input"
  | "unsupported_alg"
  | "bad_covered_components"
  | "keyid_mismatch"
  | "thumbprint_mismatch"
  | "pop_missing_created"
  | "pop_future_created"
  | "pop_missing_exp"
  | "pop_expired"
  | "pop_sig_invalid";

export interface PopResult {
  ok: boolean;
  reason?: PopFailure;
}

/**
 * Ed25519 verify primitive: (publicKey, signature, message) -> valid?. Injected
 * so non-WebCrypto runtimes can supply their own without changing the byte
 * contract. Defaults to WebCrypto. Byte params are `Uint8Array<ArrayBuffer>`
 * (never SharedArrayBuffer-backed) so the default can hand them to WebCrypto's
 * BufferSource without casts.
 */
export type Ed25519Verify = (
  publicKey: Uint8Array<ArrayBuffer>,
  signature: Uint8Array<ArrayBuffer>,
  message: Uint8Array<ArrayBuffer>,
) => Promise<boolean>;

export interface PopInput {
  /** Full request URL — the value the agent signed as `@target-uri`. */
  url: string;
  method: string;
  headers: Headers;
  /** The bound thumbprint carried in the URL's `agent_id` param. */
  agentId: string;
  now?: () => number;
  /** Optional Ed25519 verify primitive; defaults to WebCrypto crypto.subtle. */
  verifyEd25519?: Ed25519Verify;
}

interface SignatureInput {
  covered: string[];
  /** Verbatim params string after `label=`, used to rebuild @signature-params. */
  rawParams: string;
  keyid: string;
  alg: string;
  created?: number;
  expires?: number;
}

const okResult: PopResult = { ok: true };
const fail = (reason: PopFailure): PopResult => ({ ok: false, reason });

/**
 * Verify the agent's proof of possession of the key bound to `agentId`.
 * Returns `{ ok: true }` only when the presented key, the RFC 9421 signature,
 * and the 3-way identity all check out.
 */
export async function verifyAgentBinding(input: PopInput): Promise<PopResult> {
  const presented = readPresentedKey(input.headers);
  if (!presented.ok) return presented.result;

  const parsed = parseSignatureInput(input.headers.get("signature-input"));
  if (!parsed) return fail("malformed_sig_input");
  // alg is an early reject only; the verify primitive is hard-pinned to Ed25519,
  // so alg is never a key/algorithm SELECTION input (no downgrade possible).
  if (parsed.alg.toLowerCase() !== "ed25519") return fail("unsupported_alg");
  if (!coversExactly(parsed.covered)) return fail("bad_covered_components");

  const sigBytes = parseSignature(input.headers.get("signature"));
  if (!sigBytes) return fail("missing_sig");

  // 3-way identity. keyid and the presented-key thumbprint must both equal the
  // URL-bound agent_id before any signature work is trusted.
  if (parsed.keyid !== input.agentId) return fail("keyid_mismatch");
  const presentedThumb = await thumbprint(presented.key);
  if (presentedThumb !== input.agentId) return fail("thumbprint_mismatch");

  const stale = freshnessFailure(parsed, input.now);
  if (stale) return fail(stale);

  // Coerce a URL-like input (Fastly hands a URL object, not a string) to its
  // opaque string form once at the boundary. The @target-uri line must carry the
  // verbatim bytes the agent signed, never a WHATWG-normalized toString(). This
  // is behavior-neutral for the template literal on a string caller
  // (String(s) === s); it makes the opaque-string contract explicit and matches
  // the signed-URL verify boundary.
  const url = opaqueUrl(input.url);
  const base = signatureBase(input.method, url, parsed.rawParams);
  const verify = input.verifyEd25519 ?? defaultVerifyEd25519;
  const valid = await verify(presented.key, sigBytes, utf8Bytes(base));
  return valid ? okResult : fail("pop_sig_invalid");
}

type PresentedKey = { ok: true; key: Uint8Array<ArrayBuffer> } | { ok: false; result: PopResult };

function readPresentedKey(headers: Headers): PresentedKey {
  const raw = headers.get(AGENT_KEY_HEADER);
  if (!raw) return { ok: false, result: fail("missing_agent_key") };
  const bytes = decodeBase64Url(raw);
  if (!bytes || bytes.length !== ED25519_PUBLIC_KEY_BYTES) {
    return { ok: false, result: fail("bad_agent_key") };
  }
  return { ok: true, key: bytes };
}

function coversExactly(covered: string[]): boolean {
  return covered.length === 2 && covered.includes("@method") && covered.includes("@target-uri");
}

// MAX_FUTURE_SKEW_SEC: a proof's created timestamp may not lead the verifier
// clock by more than this (mirrors the Go service-to-service verifier).
const MAX_FUTURE_SKEW_SEC = 300;

function freshnessFailure(parsed: SignatureInput, now?: () => number): PopFailure | undefined {
  const nowSec = Math.floor((now?.() ?? Date.now()) / 1000);
  if (parsed.created === undefined) return "pop_missing_created";
  if (parsed.created > nowSec + MAX_FUTURE_SKEW_SEC) return "pop_future_created";
  if (parsed.expires === undefined) return "pop_missing_exp";
  if (nowSec >= parsed.expires) return "pop_expired";
  return undefined;
}

/**
 * Rebuild the RFC 9421 signature base for the covered GET components. Order
 * mirrors the inner list (`@method`, `@target-uri`), then `@signature-params`.
 * MUST stay byte-identical to the sdk/go signer (sigbase.go buildSignatureBase).
 */
export function signatureBase(method: string, url: string, rawParams: string): string {
  return [
    `"@method": ${method.toUpperCase()}`,
    `"@target-uri": ${url}`,
    `"@signature-params": ${rawParams}`,
  ].join("\n");
}

/** Parse `label=("@method" "@target-uri");keyid="..";alg="..";created=..;expires=..`. */
export function parseSignatureInput(raw: string | null): SignatureInput | undefined {
  if (!raw) return undefined;
  const eq = raw.indexOf("=");
  if (eq < 0) return undefined;
  const rawParams = raw.slice(eq + 1).trim();
  const listMatch = rawParams.match(/^\(([^)]*)\)(.*)$/);
  if (!listMatch) return undefined;
  const covered = [...(listMatch[1] ?? "").matchAll(/"([^"]+)"/g)].map((m) => m[1] as string);
  const tail = listMatch[2] ?? "";

  const keyid = matchParam(tail, /;keyid="([^"]*)"/);
  const alg = matchParam(tail, /;alg="([^"]*)"/);
  if (keyid === undefined || alg === undefined) return undefined;
  const created = matchInt(tail, /;created=(\d+)/);
  const expires = matchInt(tail, /;expires=(\d+)/);

  return {
    covered,
    rawParams,
    keyid,
    alg,
    ...(created !== undefined ? { created } : {}),
    ...(expires !== undefined ? { expires } : {}),
  };
}

function matchParam(s: string, re: RegExp): string | undefined {
  return s.match(re)?.[1];
}

function matchInt(s: string, re: RegExp): number | undefined {
  const m = s.match(re);
  return m ? Number(m[1]) : undefined;
}

/** Parse the RFC 9421 `Signature` header value `label=:<base64>:`. */
export function parseSignature(raw: string | null): Uint8Array<ArrayBuffer> | undefined {
  if (!raw) return undefined;
  const m = raw.match(/:([^:]+):/);
  if (!m || !m[1]) return undefined;
  // The Signature byte string is standard base64; decodeBase64Url's url->std
  // alphabet remap is a no-op on it, so the shared decoder handles it.
  return decodeBase64Url(m[1]);
}

const defaultVerifyEd25519: Ed25519Verify = async (pubkey, sig, message) => {
  try {
    const key = await crypto.subtle.importKey("raw", pubkey, { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify("Ed25519", key, sig, message);
  } catch {
    return false;
  }
};
