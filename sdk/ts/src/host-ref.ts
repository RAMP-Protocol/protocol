// The one reading of a host reference, shared by the routing predicates in
// hosts.ts and by the endpoint rule in the resolvers tier.
//
// It is a module of its own, and deliberately absent from both package export maps
// (the same shape src/opaque-url.ts already has), for the reason the Go oracle's
// internal endpointrule package gives: the rule is checked in two places for two
// different reasons, and written twice it drifts. Stated once here, a refusal
// decided over one reading and enforced over another cannot happen — which is
// exactly the defect that shipped when the two halves used different parsers.
//
// Nothing here is public API. hosts.ts re-exports the predicates built on it;
// this module's names are internal to the SDK.

/** A reference that cannot be read as a host at all. The Go oracle exposes an
 * errors.Is sentinel here; this port throws, as the audience check above does,
 * because a sentinel is not how a caller in this language distinguishes causes.
 *
 * The reference is redacted before it is named. Every refusal the parse raises passes
 * through here, including the ones a credential-bearing value reaches — a control
 * character, a backslash in the userinfo, a malformed escape — so this is the one
 * place that has to do it. */
export function invalidHost(ref: string, why: string): Error {
	return new Error(
		`hosts: reference is not a usable host: ${why}: ${JSON.stringify(redactUserinfo(ref))}`,
	);
}

/** Split what follows an authority's start into the authority and everything after.
 *
 * The authority ends at the first delimiter that starts a path, query or fragment —
 * the three things a reference can carry beyond it.
 *
 * One function because the parse and the redaction have to agree on where it ends.
 * Written twice, a change to the delimiter set moves one copy and not the other, and
 * the two then read different authorities — a split reading inside the module that
 * exists to prevent split readings. */
function splitAuthority(rest: string): [string, string] {
	const end = rest.search(/[/?#]/);
	return end < 0 ? [rest, ""] : [rest.slice(0, end), rest.slice(end)];
}

/** Every index at which an authority could plausibly begin, most authoritative
 * first, de-duplicated.
 *
 * A reference the parse has REFUSED has no one true reading — that is what being
 * refused means — so the redaction cannot pick a single one and be safe. Each of
 * these is a reading something could take:
 *
 * - past a valid scheme at the front, which is how the parse reads it;
 * - index 2 behind a bare `//`, which opens an authority while naming no scheme and
 *   carries no `://` anywhere;
 * - index 0, a schemeless `host` or `user:pw@host`;
 * - past the first `://` in the string, which is not a scheme separator to this
 *   parse but is what a laxer reader downstream may take it for.
 *
 * Taking only the first of these traded one leak for another: reading solely by
 * search let a path segment supply the start, so `u:pw@evil.example/x://a.example`
 * came back untouched — and reading solely by the parse's rule then left
 * `1https://u:pw@a.example/` untouched instead, because a scheme may not begin with
 * a digit. */
function authorityStarts(ref: string): number[] {
	const scheme = schemeAtFront.exec(ref);
	const starts: number[] = [];
	if (scheme !== null) {
		starts.push(scheme[0].length);
	}
	if (ref.startsWith("//")) {
		starts.push(2);
	}
	starts.push(0);
	const sep = ref.indexOf("://");
	if (sep >= 0) {
		starts.push(sep + 3);
	}
	return [...new Set(starts)];
}

/** Replace any userinfo in a reference with a marker, so a message built from it
 * cannot carry a credential.
 *
 * Deliberately conservative, and deliberately NOT the rule: it runs on strings the
 * parse has already refused, so it cannot assume they are well formed, and
 * over-redacting a message costs nothing while under-redacting is the bug. It
 * redacts at the FIRST reading in authorityStarts that finds an "@", rather than
 * deciding on one reading — a credential any reader could see is one that must not
 * reach a log. It looks only for an "@" in what could be the authority, which is why
 * an "@" in a path is left alone.
 *
 * The whole userinfo goes, not just the password. Go's own url.URL.Redacted() keeps
 * the username, which is right for a URL the caller owns — but this value arrives in
 * a third-party manifest, where the username is as much the operator's secret as the
 * password is.
 *
 * The oracle does echo the raw reference here, and that is not a parity break: the
 * shared corpus records a verdict and never a message, precisely so each language can
 * phrase its errors its own way. Do not "restore" this to match Go. */
export function redactUserinfo(ref: string): string {
	for (const start of authorityStarts(ref)) {
		const [authority, beyond] = splitAuthority(ref.slice(start));
		const at = authority.lastIndexOf("@");
		if (at >= 0) {
			return `${ref.slice(0, start)}[redacted]${authority.slice(at)}${beyond}`;
		}
	}
	return ref;
}

// An authority admits a CLOSED set of ASCII characters; everything outside it is
// refused. Stating the set rather than a list of separators is what makes the
// refusal structural: a separator nobody thought of is already outside it. Code
// points at or above 0x80 are admitted — the oracle's parser keeps them, so a name
// in a non-ASCII script is a usable host even though the wire's domain rule
// refuses it.
const hostAscii = new Set(
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~!$&'()*+,;=:[]<>\"",
);

// Userinfo admits a DIFFERENT closed set from the host: no `"`, `<`, `>` or `]`.
// Reusing the host set here would close the backslash hole and still under-refuse
// four characters the oracle rejects — and the gap is not cosmetic. WHATWG treats
// `\` as a fourth authority delimiter in special schemes, so a backslash smuggled
// into userinfo ends the authority early and the fetch reaches an entirely
// different host from the one the anchor check just approved.
const userinfoAscii = new Set(
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~!$&'()*+,;=:",
);

// A scheme, and only at the front. The oracle reads `://` as a separator solely
// when a valid scheme precedes it at position 0; anywhere else the text is a path.
// Locating the separator by search instead let a path segment supply the host —
// `evil.example/x://a.example` answered `a.example`.
const schemeAtFront = /^[A-Za-z][A-Za-z0-9+.-]*:\/\//;
const escapePair = /%(?![0-9A-Fa-f]{2})/;

// A control character is refused outright rather than removed. This is the reason
// the platform parser cannot be used here: `new URL` strips tabs, newlines and
// leading control characters per WHATWG, so it answers "host" where the oracle
// answers "not a host". The port is read textually below for the same kind of
// reason — `new URL` folds a scheme's default port away at PARSE time, which is
// earlier than this rule decides which scheme is even in play.
const controlChar = /[\u0000-\u001F\u007F]/;
const digitsOnly = /^[0-9]*$/;

export interface ParsedRef {
	/** The authority with userinfo removed and the port kept, exactly as written. */
	host: string;
	/** The authority's host alone: no port, IPv6 brackets stripped, case preserved. */
	hostname: string;
	/** The port as written, or "" when none was. Never a default filled in. */
	port: string;
	/** Whether the caller actually WROTE a scheme. Anchoring needs this: a scheme
	 * decides which port counts as the default, so a value that named none must not
	 * be treated as having named https. */
	hadScheme: boolean;
	/** The scheme written, or "https" for a reference that named none. */
	scheme: string;
	/** Whether the authority carried userinfo. The endpoint rule refuses a
	 * credential and needs the answer from THIS reading of the reference: decided
	 * over a second, differently-shaped parse it disagrees with the anchor check on
	 * exactly the shape it exists to stop. */
	hasUserinfo: boolean;
}

/** Read a bare domain, a host:port pair, or a full URL into its authority. A ref
 * with no scheme is read as though it carried https, since a bare domain is
 * otherwise indistinguishable from a path. One parse behind both host predicates,
 * so neither can disagree with the other about what a reference even is. */
export function parseRef(ref: string): ParsedRef {
	if (ref.trim() === "") {
		throw invalidHost(ref, "empty reference");
	}
	if (controlChar.test(ref)) {
		throw invalidHost(ref, "control character");
	}
	// `://` is a separator only behind a valid scheme at the front. A reference that
	// carries the sequence anywhere else is not schemeless — it is malformed, which
	// is what the oracle answers, so treating it as schemeless and prepending https
	// would trade one wrong answer for another.
	const hadScheme = ref.includes("://");
	if (hadScheme && !schemeAtFront.test(ref)) {
		throw invalidHost(ref, 'no valid scheme before "://"');
	}
	const work = hadScheme ? ref : `https://${ref}`;
	const sep = work.indexOf("://");
	const scheme = hadScheme ? work.slice(0, sep).toLowerCase() : "https";

	const [authority, beyond] = splitAuthority(work.slice(sep + 3));

	// Escapes are read PER COMPONENT, because the oracle reads them per component.
	// A malformed escape is refused in a path and in a fragment, and admitted in a
	// query, which is not unescaped at parse time. Checking the whole reference
	// instead refused `?q=a%20b` — an ordinary, fully conformant endpoint.
	//
	// The fragment is cut FIRST, and that ordering is the rule rather than a detail:
	// everything after the first "#" is fragment, so a "?" inside one does not start
	// a query. Reading the query first leaves `/#a?b=%zz` looking like a query and
	// admits a malformed escape the oracle refuses.
	const hash = beyond.indexOf("#");
	const fragment = hash < 0 ? "" : beyond.slice(hash + 1);
	const beforeFragment = hash < 0 ? beyond : beyond.slice(0, hash);
	const query = beforeFragment.indexOf("?");
	const path = query < 0 ? beforeFragment : beforeFragment.slice(0, query);
	if (escapePair.test(path)) {
		throw invalidHost(ref, "malformed percent-escape in path");
	}
	if (escapePair.test(fragment)) {
		throw invalidHost(ref, "malformed percent-escape in fragment");
	}

	// Userinfo is split at the LAST "@", so an "@" inside a credential does not
	// become part of the host.
	const at = authority.lastIndexOf("@");
	const hasUserinfo = at >= 0;
	const userinfo = hasUserinfo ? authority.slice(0, at) : "";
	const host = hasUserinfo ? authority.slice(at + 1) : authority;
	if (host === "") {
		throw invalidHost(ref, "no host");
	}
	for (const ch of userinfo) {
		const cp = ch.codePointAt(0) ?? 0;
		// "%" and "@" are excluded from the set check on purpose: escapes are read
		// below, and an "@" before the last one is part of the credential, not a
		// second separator.
		if (cp < 0x80 && ch !== "%" && ch !== "@" && !userinfoAscii.has(ch)) {
			throw invalidHost(ref, `invalid character ${JSON.stringify(ch)} in userinfo`);
		}
	}
	if (escapePair.test(userinfo)) {
		throw invalidHost(ref, "malformed percent-escape in userinfo");
	}
	for (const ch of host) {
		const cp = ch.codePointAt(0) ?? 0;
		// A percent-escape is refused in the HOST, and only there. The oracle admits
		// just the escapes decoding to a byte at or above 0x80, plus %25 — none of
		// which a domain name carries — so refusing the lot costs nothing a caller
		// can use and removes an unescaping step the three languages would each get
		// subtly wrong. Every value the two answers differ on refuses downstream
		// anyway: a host holding a raw high byte anchors to no bare domain.
		if (ch === "%") {
			throw invalidHost(ref, "percent-escape in the host component");
		}
		if (cp < 0x80 && !hostAscii.has(ch)) {
			throw invalidHost(ref, `invalid character ${JSON.stringify(ch)} in host`);
		}
	}

	let hostname: string;
	let port: string;
	if (host.startsWith("[")) {
		const close = host.indexOf("]");
		if (close < 0) {
			throw invalidHost(ref, "missing ']' in host");
		}
		hostname = host.slice(1, close);
		const after = host.slice(close + 1);
		if (after === "") {
			port = "";
		} else if (after.startsWith(":")) {
			port = after.slice(1);
		} else {
			throw invalidHost(ref, "trailing characters after ']' in host");
		}
	} else {
		if (host.includes("[")) {
			throw invalidHost(ref, "missing ']' in host");
		}
		// From the FIRST colon onward, so a value that merely ENDS in digits does
		// not pass as a port: "a.example::443" and "a.example:44:3" are refused.
		const colon = host.indexOf(":");
		hostname = colon < 0 ? host : host.slice(0, colon);
		port = colon < 0 ? "" : host.slice(colon + 1);
	}
	if (!digitsOnly.test(port)) {
		throw invalidHost(ref, `invalid port ${JSON.stringify(port)} after host`);
	}
	return { host, hostname, port, hadScheme, scheme, hasUserinfo };
}

// The port a scheme reaches when none is written.
const defaultPorts: Record<string, string> = { http: "80", https: "443" };

/** canonicalPort renders "the same port" as one string, so a port written out in
 * full and the same port left implicit compare equal. An unknown scheme has no
 * default to fold, so its port is kept verbatim. */
function canonicalPort(scheme: string, port: string): string {
	if (port === "") {
		return "";
	}
	const def = defaultPorts[scheme.toLowerCase()];
	return def !== undefined && port === def ? "" : port;
}

/** sameOrSubdomain reports whether candidate equals anchor or is a subdomain of
 * it. Comparison is case-insensitive and tolerant of ONE trailing root dot — not
 * of every trailing dot, which would make a doubled root dot compare equal to a
 * name that never carried one. A subdomain match requires a full dot-delimited
 * label boundary, so "evil-a.com" is NOT treated as a subdomain of "a.com" — the
 * check a bare suffix match gets wrong, and the one an attacker registers a domain
 * to exploit. */
function sameOrSubdomain(anchor: string, candidate: string): boolean {
	const a = anchor.toLowerCase().replace(/\.$/, "");
	const c = candidate.toLowerCase().replace(/\.$/, "");
	if (a === "") {
		return false;
	}
	return c === a || c.endsWith(`.${a}`);
}

/** anchoredParsed is the anchor comparison over two references that have ALREADY
 * been read. It exists so a caller holding a parse can reach the verdict without
 * triggering a second one — the endpoint rule needs the userinfo answer and the
 * anchor answer from one reading of the same string.
 *
 * A side that named no scheme borrows the other's, which decides only WHICH port
 * counts as the default. Hostname and port are compared as two values rather than
 * one joined string: joined, the label boundary would have to find ".a.com" at the
 * end of "sub.a.com:8443" and would refuse a subdomain for having a port — the
 * right answer reached through the wrong comparison is still the wrong comparison. */
export function anchoredParsed(a: ParsedRef, c: ParsedRef): boolean {
	const anchorScheme = a.hadScheme ? a.scheme : c.scheme;
	const candidateScheme = c.hadScheme ? c.scheme : a.scheme;
	return (
		sameOrSubdomain(a.hostname, c.hostname) &&
		canonicalPort(anchorScheme, a.port) === canonicalPort(candidateScheme, c.port)
	);
}
