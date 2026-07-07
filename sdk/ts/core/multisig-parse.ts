// sdk/ts multi-member RFC 8941 Signature-Input dictionary parser + verbatim
// inner-per-label extractor — the TS port of Go helpers.parseAllSignatures /
// rawInnerByLabel / splitTopLevelMembers (verify.go). The single-sig verify path
// (core/verify-request.ts) hand-rolls a minimal ONE-label parser; the multisig
// forwarding chain (o3szv) needs the FULL multi-member dictionary parse plus the
// exact byte-verbatim inner value each hop's base terminates with.
//
// Dependency-light on purpose: no new runtime dep, mirroring the existing minimal
// single-label parsers. Correctness on ADVERSARIAL headers (quoted-comma,
// backslash escapes, top-level splitting, malformed reject) is pinned by
// tests/multisig-parse.edge.test.ts — the canonical Go golden vectors are
// well-behaved and do NOT gate the parser (o3szv R2).

import { decodeBase64Url } from "../src/base64url.ts";

/** One covered-component identifier: a lowercased name plus, for a forwarding
 * chain link `"signature";key="sigN"`, the referenced predecessor label. */
export interface MultisigCovered {
	name: string;
	chainKey?: string;
}

/** One parsed Signature-Input dictionary member (one hop's label). `rawInner` is
 * the VERBATIM value after `label=` — the exact @signature-params bytes the hop's
 * signature base must terminate with (Go sigParams.RawInner). */
export interface MultisigMember {
	label: string;
	rawInner: string;
	covered: MultisigCovered[];
	keyid: string | null;
	alg: string | null;
	created?: number;
	expires?: number;
}

/**
 * Split one SFV dictionary header value on TOP-LEVEL commas, honoring quoted
 * strings and their backslash escapes (Go splitTopLevelMembers). A comma inside a
 * quoted keyid must NOT tear the member in two.
 */
export function splitTopLevelMembers(s: string): string[] {
	const parts: string[] = [];
	let start = 0;
	let inQuote = false;
	let escaped = false;
	for (let i = 0; i < s.length; i += 1) {
		const c = s[i];
		if (escaped) {
			escaped = false;
		} else if (c === "\\" && inQuote) {
			escaped = true;
		} else if (c === '"') {
			inQuote = !inQuote;
		} else if (c === "," && !inQuote) {
			parts.push(s.slice(start, i));
			start = i + 1;
		}
	}
	parts.push(s.slice(start));
	return parts;
}

/**
 * The VERBATIM member value after `label=` for each label across the given
 * Signature-Input header values (Go rawInnerByLabel). Later occurrences overwrite
 * earlier ones, matching SFV dictionary last-wins semantics.
 */
export function rawInnerByLabel(values: string[]): Record<string, string> {
	const out: Record<string, string> = {};
	for (const v of values) {
		for (const member of splitTopLevelMembers(v)) {
			const eq = member.indexOf("=");
			if (eq <= 0) continue;
			const label = member.slice(0, eq).trim();
			out[label] = member.slice(eq + 1).trim();
		}
	}
	return out;
}

// findQuoteEnd returns the index of the closing quote for the quoted string that
// opens at `open`, honoring backslash escapes, or -1 if unterminated.
function findQuoteEnd(s: string, open: number): number {
	let escaped = false;
	for (let i = open + 1; i < s.length; i += 1) {
		const c = s[i];
		if (escaped) {
			escaped = false;
		} else if (c === "\\") {
			escaped = true;
		} else if (c === '"') {
			return i;
		}
	}
	return -1;
}

// findInnerListEnd returns the index of the inner-list closing paren, honoring
// quoted strings (a param value may contain a paren), or -1 if unterminated.
function findInnerListEnd(s: string): number {
	let inQuote = false;
	let escaped = false;
	for (let i = 1; i < s.length; i += 1) {
		const c = s[i];
		if (escaped) {
			escaped = false;
		} else if (c === "\\" && inQuote) {
			escaped = true;
		} else if (c === '"') {
			inQuote = !inQuote;
		} else if (c === ")" && !inQuote) {
			return i;
		}
	}
	return -1;
}

// parseCovered parses an inner-list body ("c1" "c2";key="v" …) into ordered
// covered components. Returns undefined on a malformed token.
function parseCovered(inner: string): MultisigCovered[] | undefined {
	const items: MultisigCovered[] = [];
	let i = 0;
	while (i < inner.length) {
		if (inner[i] === " ") {
			i += 1;
			continue;
		}
		if (inner[i] !== '"') return undefined;
		const nameEnd = findQuoteEnd(inner, i);
		if (nameEnd < 0) return undefined;
		const comp: MultisigCovered = { name: inner.slice(i + 1, nameEnd).toLowerCase() };
		i = nameEnd + 1;
		while (inner[i] === ";") {
			const next = parseComponentParam(inner, i, comp);
			if (next < 0) return undefined;
			i = next;
		}
		items.push(comp);
	}
	return items;
}

// parseComponentParam parses one `;key="val"` component parameter starting at
// `pos` (the ';'), stamping a chainKey onto comp for key="…". Returns the index
// after the param, or -1 on malformed.
function parseComponentParam(inner: string, pos: number, comp: MultisigCovered): number {
	const eq = inner.indexOf("=", pos);
	if (eq < 0 || inner[eq + 1] !== '"') return -1;
	const pname = inner.slice(pos + 1, eq);
	const vEnd = findQuoteEnd(inner, eq + 1);
	if (vEnd < 0) return -1;
	if (pname === "key") comp.chainKey = inner.slice(eq + 2, vEnd);
	return vEnd + 1;
}

function matchQuoted(s: string, re: RegExp): string | null {
	const m = s.match(re);
	return m ? (m[1] ?? "") : null;
}

function matchInt(s: string, re: RegExp): number | undefined {
	const m = s.match(re);
	return m ? Number(m[1]) : undefined;
}

// parseMember parses one `label=(inner);params` member into a MultisigMember, or
// undefined on a malformed inner list / member.
function parseMember(raw: string): MultisigMember | undefined {
	const eq = raw.indexOf("=");
	if (eq <= 0) return undefined;
	const label = raw.slice(0, eq).trim();
	const rawInner = raw.slice(eq + 1).trim();
	if (rawInner[0] !== "(") return undefined;
	const close = findInnerListEnd(rawInner);
	if (close < 0) return undefined;
	const covered = parseCovered(rawInner.slice(1, close));
	if (!covered) return undefined;
	const tail = rawInner.slice(close + 1);
	const created = matchInt(tail, /;created=(\d+)/);
	const expires = matchInt(tail, /;expires=(\d+)/);
	return {
		label,
		rawInner,
		covered,
		keyid: matchQuoted(tail, /;keyid="([^"]*)"/),
		alg: matchQuoted(tail, /;alg="([^"]*)"/),
		...(created !== undefined ? { created } : {}),
		...(expires !== undefined ? { expires } : {}),
	};
}

/**
 * Full multi-label parse of the Signature-Input header values, preserving header
 * order. Returns undefined (clean reject) on any malformed member — never a
 * mis-slice into a bogus covered set.
 */
export function parseMultisigSignatureInput(values: string[]): MultisigMember[] | undefined {
	const members: MultisigMember[] = [];
	for (const v of values) {
		for (const raw of splitTopLevelMembers(v)) {
			const member = parseMember(raw);
			if (!member) return undefined;
			members.push(member);
		}
	}
	return members.length > 0 ? members : undefined;
}

/**
 * Parse the RFC 9421 `Signature` header (`label=:<std-base64>:, …`) into a
 * label→raw-bytes map — the per-label lookup the forwarding-chain link resolution
 * and the multisig verify loop share (Go signatureBytesForLabel / parseSigLabel).
 */
export function signatureBytesByLabel(sigHeader: string): Record<string, Uint8Array<ArrayBuffer>> {
	const out: Record<string, Uint8Array<ArrayBuffer>> = {};
	for (const member of splitTopLevelMembers(sigHeader)) {
		const eq = member.indexOf("=");
		if (eq <= 0) continue;
		const label = member.slice(0, eq).trim();
		const val = member.slice(eq + 1).trim();
		const first = val.indexOf(":");
		const last = val.lastIndexOf(":");
		if (first < 0 || last <= first) continue;
		const bytes = decodeBase64Url(val.slice(first + 1, last));
		if (bytes) out[label] = bytes;
	}
	return out;
}

/**
 * The highest sigN label number present in a Signature-Input value (0 when none)
 * — Go maxSignatureLabelN. Backs append's next-label / predecessor resolution.
 */
export function maxSigLabelN(signatureInput: string): number {
	let max = 0;
	for (const label of Object.keys(rawInnerByLabel([signatureInput]))) {
		if (!label.startsWith("sig")) continue;
		const n = Number(label.slice(3));
		if (Number.isInteger(n) && n > max) max = n;
	}
	return max;
}
