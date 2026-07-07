// sdk/ts framework-agnostic RFC 9421 MULTISIG forwarding-chain SERVER-verify face
// — the TS port of Go helpers.VerifyMultisigRequest[Resolved] (verify.go /
// keyresolver.go). Where core/verify-request.ts is the SINGLE-SIG surface, this is
// the multi-hop verify a Broker/Exchange built in TS wires when a request carries
// a forwarding chain (RAMP-56): it parses ALL labels, enforces the hop budget
// FIRST, the structural forwarding chain NEXT, then cryptographically verifies
// every hop — returning a verdict with the verified keyids in chain order, never
// throwing.
//
// Reject precedence (parity-critical, mirrors Go VerifyMultisigRequest):
//   hop_budget → broken_chain → signature.
//
// NO replay (o3szv R1): the Go helpers oracle VerifyMultisigRequest[Resolved]
// performs no replay (replay lives at the connectserver layer), so this face
// reuses the replay-free per-signature core (verifyParsedSignature) and never
// touches a ReplayStore. The chain link resolves to the LIVE predecessor bytes, so
// a stripped, reordered, or tampered predecessor is rejected.

import { stdBase64 } from "./sign.ts";
import type { ChainLink } from "./sign-request.ts";
import {
	type MultisigMember,
	parseMultisigSignatureInput,
	signatureBytesByLabel,
} from "./multisig-parse.ts";
import {
	type KeyResolverTs,
	type RequestVerifyFields,
	verifyParsedSignature,
} from "./verify-request.ts";

/**
 * The classified multisig reject reason (mirrors the Go taxonomy): "hop_budget"
 * (count exceeds the configured budget), "broken_chain" (labels non-contiguous /
 * reordered / missing or wrong link), and "signature" (any per-hop
 * authenticity/freshness/key/covered-set failure — the default).
 */
export type MultisigRejectReason = "signature" | "broken_chain" | "hop_budget";

/** The injected keyid-keyed verifying-key resolver — every hop's key resolves
 * through it (the SDK owns no keys). Structurally identical to KeyResolverTs. */
export type MultisigKeyResolver = KeyResolverTs;

/** The lowercased request headers a multisig server-verify reads. */
export interface MultisigVerifyHeaders {
	"content-digest": string;
	"signature-input": string;
	signature: string;
	authorization: string;
	"signature-agent": string;
}

/** Inputs for verifyMultisigRequestServer. */
export interface VerifyMultisigRequestInput {
	method: string;
	url: string;
	body: Uint8Array<ArrayBuffer>;
	headers: MultisigVerifyHeaders;
	resolve: MultisigKeyResolver;
	/** Injected clock returning unix seconds — verify reads time ONLY through this. */
	now: () => number;
	/** The Exchange hop bound: reject a chain longer than this BEFORE any crypto.
	 * 0 / omitted means unbounded (mirrors Go opts.MaxSignatures). */
	maxSignatures?: number;
}

/** The returned verdict: valid with the verified keyids in chain order, or invalid
 * with the classified reason. Never thrown — always returned. */
export interface MultisigVerifyVerdict {
	valid: boolean;
	reason?: MultisigRejectReason;
	keyids?: string[];
}

const rejectMultisig = (reason: MultisigRejectReason): MultisigVerifyVerdict => ({
	valid: false,
	reason,
});

/**
 * enforceSignatureChain — the STRUCTURAL forwarding-chain gate (Go
 * enforceSignatureChain): labels are exactly sig1..sigN contiguous in header
 * order, sig1 carries no "signature" component, and every sigK (K>1) covers
 * exactly one "signature";key="sig(K-1)". Cryptographic binding is the per-hop
 * verify's job; this is structure only.
 */
function enforceSignatureChain(members: MultisigMember[]): boolean {
	for (let i = 0; i < members.length; i += 1) {
		const member = members[i] as MultisigMember;
		if (member.label !== `sig${i + 1}`) return false;
		const links = member.covered.filter((c) => c.name === "signature");
		if (i === 0) {
			if (links.length !== 0) return false;
			continue;
		}
		if (links.length !== 1 || links[0]?.chainKey !== `sig${i}`) return false;
	}
	return true;
}

// chainLinkFor builds the forwarding-chain base line for hop i (>0): the token
// `"signature";key="sig(i)"` and its value `:<std-base64(live predecessor bytes)>:`
// resolved from the LIVE Signature member, or undefined if the predecessor bytes
// are absent (a per-hop signature failure).
function chainLinkFor(
	i: number,
	sigMap: Record<string, Uint8Array<ArrayBuffer>>,
): ChainLink | undefined {
	const prevLabel = `sig${i}`;
	const prevBytes = sigMap[prevLabel];
	if (!prevBytes) return undefined;
	return { token: `"signature";key="${prevLabel}"`, value: `:${stdBase64(prevBytes)}:` };
}

/**
 * Verify an inbound MULTISIG forwarding-chain RAMP request; return a reason-tagged
 * verdict carrying the verified keyids in chain order. Enforces the hop budget,
 * then the structural chain, then every hop's signature — in that precedence.
 */
export async function verifyMultisigRequestServer(
	input: VerifyMultisigRequestInput,
): Promise<MultisigVerifyVerdict> {
	const members = parseMultisigSignatureInput([input.headers["signature-input"]]);
	if (!members) return rejectMultisig("signature");

	const budget = input.maxSignatures ?? 0;
	if (budget > 0 && members.length > budget) return rejectMultisig("hop_budget");

	if (!enforceSignatureChain(members)) return rejectMultisig("broken_chain");

	const sigMap = signatureBytesByLabel(input.headers.signature);
	const nowSec = Math.floor(input.now());
	const fields: RequestVerifyFields = {
		method: input.method,
		url: input.url,
		digestHeader: input.headers["content-digest"],
		authorization: input.headers.authorization,
		signatureAgent: input.headers["signature-agent"],
		body: input.body,
	};

	const keyids: string[] = [];
	for (let i = 0; i < members.length; i += 1) {
		const member = members[i] as MultisigMember;
		let chainLink: ChainLink | undefined;
		if (i > 0) {
			chainLink = chainLinkFor(i, sigMap);
			if (!chainLink) return rejectMultisig("signature");
		}
		const ok = await verifyParsedSignature(
			fields,
			{
				rawParams: member.rawInner,
				covered: new Set(member.covered.map((c) => c.name)),
				keyid: member.keyid,
				alg: member.alg,
				...(member.created !== undefined ? { created: member.created } : {}),
				...(member.expires !== undefined ? { expires: member.expires } : {}),
			},
			sigMap[member.label],
			input.resolve,
			nowSec,
			chainLink,
		);
		if (!ok || member.keyid === null) return rejectMultisig("signature");
		keyids.push(member.keyid);
	}
	return { valid: true, keyids };
}
