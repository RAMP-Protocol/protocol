import { z } from "zod";
import { decodeBase64Url, utf8Bytes } from "./base64url.ts";

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
  agentHash?: Uint8Array;
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
  const url = new URL(rawUrl);
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

  let agentHash: Uint8Array | undefined;
  if (agentId !== undefined) {
    const decoded = decodeBase64Url(agentId);
    if (!decoded) {
      return { valid: false, expired: false, reason: "bad_agent_encoding" };
    }
    agentHash = decoded;
  }

  const key = await deps.resolveKey(kid);
  if (!key) {
    return buildResult({ valid: false, expired: false, kid, reason: "signature_mismatch" });
  }

  const message = canonicalMessage(url);
  const okSig = await crypto.subtle.verify("Ed25519", key, sigBytes, message);
  if (!okSig) {
    return buildResult({ valid: false, expired: false, kid, reason: "signature_mismatch" });
  }
  return buildResult({ valid: true, expired: false, kid, ...(agentHash && { agentHash }) });
}

function buildResult(r: {
  valid: boolean;
  expired: boolean;
  kid: string | undefined;
  agentHash?: Uint8Array;
  reason?: VerifyFailure;
}): VerifyResult {
  const out: VerifyResult = { valid: r.valid, expired: r.expired };
  if (r.kid !== undefined) out.kid = r.kid;
  if (r.agentHash !== undefined) out.agentHash = r.agentHash;
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
 * The canonical signed message: "GET\n<url-without-sig>". Only the `sig` param is
 * stripped — the query is NOT re-sorted, matching the Go signer's already-sorted
 * output (url.Values.Encode()).
 */
export function canonicalMessage(url: URL): Uint8Array<ArrayBuffer> {
  const stripped = new URL(url.toString());
  stripped.searchParams.delete("sig");
  const canonical = `GET\n${stripped.toString()}`;
  return utf8Bytes(canonical);
}
