import { z } from "zod";
import { decodeBase64Url, utf8Bytes } from "./base64url.ts";
import { opaqueUrl } from "./opaque-url.ts";
import { canonicalUrl } from "./signurl.ts";

// Ed25519 signed delivery-URL verification (ADR-013), relocated from the app
// edge (src/edge/src/verify.ts) as a pure, IO-free L1 helper. Key resolution is
// INJECTED (VerifyDeps.resolveKey) so no IO/state lives in the SDK — the ADR-020
// §4 KeyResolver split. Byte-parity guard: the signed-URL vectors are produced by
// the sdk/go signer (SignURLEd25519), so the "no re-sort on verify" canonical
// message is fed the exact canonically-sorted string the signer emitted.

export interface VerifyResult {
  valid: boolean;
  expired: boolean;
  kid?: string;
  /** RFC 7638 thumbprint the URL is bound to (base64url string, the agent_id
   * param verbatim) — the same name/representation as Go VerifiedURL.AgentID
   * and Python SignedUrlResult.agent_id. Absent on a bearer (unbound) URL. */
  agentId?: string;
  reason?: VerifyFailure;
}

export type VerifyFailure =
  | "missing_sig"
  | "missing_exp"
  | "bad_sig_encoding"
  | "bad_exp_encoding"
  | "expired"
  | "bad_agent_encoding"
  | "signature_mismatch";

const ParamsSchema = z.object({
  sig: z.string().min(1),
  exp: z.string().regex(/^\d+$/),
  kid: z.string().min(1).optional(),
  agentId: z.string().min(1).optional(),
});

export interface VerifyDeps {
  now?: () => number;
  resolveKey: (kid: string | undefined) => Promise<CryptoKey | undefined>;
}

export async function verifyEd25519SignedUrl(
  rawUrl: string,
  deps: VerifyDeps,
): Promise<VerifyResult> {
  // Coerce a URL-like input (a Fastly Compute request URL object) to its opaque
  // string form ONCE at the boundary, so param parsing and the canonical message
  // both operate on the same verbatim bytes. No-op for string callers.
  const raw = opaqueUrl(rawUrl);
  const url = new URL(raw);
  const params = parseParams(url);
  if (!params.ok) {
    return { valid: false, expired: false, reason: params.reason };
  }
  const { sig, exp, kid, agentId } = params.value;

  const nowSec = Math.floor((deps.now?.() ?? Date.now()) / 1000);
  if (nowSec >= Number(exp)) {
    return { valid: false, expired: true, reason: "expired" };
  }

  const sigBytes = decodeBase64Url(sig);
  if (!sigBytes) {
    return { valid: false, expired: false, reason: "bad_sig_encoding" };
  }

  if (agentId !== undefined) {
    // Decode purely as VALIDATION: a malformed agent_id is rejected before any
    // signature work; the public surface carries the base64url STRING verbatim.
    if (!decodeBase64Url(agentId)) {
      return { valid: false, expired: false, reason: "bad_agent_encoding" };
    }
  }

  const key = await deps.resolveKey(kid);
  if (!key) {
    return buildResult({ valid: false, expired: false, kid, reason: "signature_mismatch" });
  }

  const message = canonicalMessage(raw);
  const okSig = await crypto.subtle.verify("Ed25519", key, sigBytes, message);
  if (!okSig) {
    return buildResult({ valid: false, expired: false, kid, reason: "signature_mismatch" });
  }
  return buildResult({ valid: true, expired: false, kid, ...(agentId !== undefined && { agentId }) });
}

function buildResult(r: {
  valid: boolean;
  expired: boolean;
  kid: string | undefined;
  agentId?: string;
  reason?: VerifyFailure;
}): VerifyResult {
  const out: VerifyResult = { valid: r.valid, expired: r.expired };
  if (r.kid !== undefined) out.kid = r.kid;
  if (r.agentId !== undefined) out.agentId = r.agentId;
  if (r.reason !== undefined) out.reason = r.reason;
  return out;
}

interface ParsedParams {
  sig: string;
  exp: string;
  kid?: string;
  agentId?: string;
}

function parseParams(
  url: URL,
): { ok: true; value: ParsedParams } | { ok: false; reason: VerifyFailure } {
  const sig = url.searchParams.get("sig");
  if (!sig) return { ok: false, reason: "missing_sig" };
  const exp = url.searchParams.get("exp");
  if (!exp) return { ok: false, reason: "missing_exp" };
  const kidRaw = url.searchParams.get("kid");
  const agentRaw = url.searchParams.get("agent_id");

  const candidate: Record<string, string> = { sig, exp };
  if (kidRaw !== null) candidate.kid = kidRaw;
  if (agentRaw !== null) candidate.agentId = agentRaw;

  const parsed = ParamsSchema.safeParse(candidate);
  if (!parsed.success) {
    return { ok: false, reason: "bad_exp_encoding" };
  }
  const value: ParsedParams = { sig: parsed.data.sig, exp: parsed.data.exp };
  if (parsed.data.kid !== undefined) value.kid = parsed.data.kid;
  if (parsed.data.agentId !== undefined) value.agentId = parsed.data.agentId;
  return { ok: true, value };
}

/**
 * The canonical signed message: "GET\n<url>" over the URL as OPAQUE BYTES. Only
 * the `sig` param is stripped and the query is deterministically re-encoded;
 * scheme/host/path are preserved verbatim (no `new URL()` host-lowercasing,
 * default-port stripping, or path-escaping). Reuses the SAME builder the sign
 * face uses (signurl.ts::canonicalUrl) so signer and verifier agree by
 * construction — see the verbatim-canonicalization contract there.
 *
 * rawUrl is coerced via opaqueUrl defensively: some edge runtimes (Fastly Compute)
 * hand the request URL as a URL-like object rather than a primitive string, and
 * canonicalUrl needs string operations. For a primitive string this is a no-op,
 * so the verbatim bytes are preserved for the server-to-server callers that own
 * the raw URL string. This coercion is retained even though verifyEd25519SignedUrl
 * now coerces at its boundary: canonicalMessage is a public export with its own
 * external callers, so it owns its input contract independently.
 */
export function canonicalMessage(rawUrl: string): Uint8Array<ArrayBuffer> {
  return utf8Bytes(`GET\n${canonicalUrl(opaqueUrl(rawUrl))}`);
}
