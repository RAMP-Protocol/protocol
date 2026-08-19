// Audience check and bare-domain shape — TS port of the sdk/go oracle
// (helpers/hosts.go, helpers/audience.go).
//
// Addressed requests carry the recipient's bare domain in a body field. The RFC
// 9421 signature does not already establish the recipient: it proves the sender
// signed THE URL IT DIALLED, not that the URL was the right one. That dial target
// is resolved from a fetched, cached /.well-known/ramp.json, so a poisoned or
// stale resolution redirects the request while every signature still verifies.
// The field states whom the sender MEANT, independently of that resolution.
//
// The field is stamped by whoever authors each request — the agent on the requests
// it signs, a Broker on the legs it authors as sender. It is a statement BY that
// sender, not tamper-evidence against it. For transactions the binding audience
// statement is per item: Offer.exchange inside the Exchange-signed offer.
//
// Pure string work, no IO. Byte-parity-guarded against the Go oracle by the
// shared vectors at sdk/go/helpers/testdata/audience-vectors.json.

/**
 * bareDomainPattern is the wire shape of a domain-valued field: a bare domain
 * with an optional ":port", never a URL. It carries the same bytes as the Go
 * `helpers.BareDomainPattern` and as the protovalidate pattern on the contract's
 * recipient-addressing fields — the `exchange` field on each addressed request,
 * `Offer.exchange` and their neighbours, not every field in ramp.proto that
 * happens to hold a domain. One rule, so the check a client makes before sending
 * and the check the wire makes on arrival cannot answer differently. The parity
 * suite asserts these bytes against the shared vectors.
 *
 * The port is a real 1-65535 range rather than "one to five digits", which is why
 * it is spelled out at this length: `:0`, `:65536` and `:99999` name no port at
 * all, and `:0443` is not a spelling of 443 but a different string.
 */
export const bareDomainPattern =
	String.raw`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*(:(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3}))?$`;

/**
 * maxBareDomainLen is the length bound belonging to the same rule — the
 * protovalidate `string.max_len` those fields carry, so this SDK cannot accept a
 * pattern-valid but over-length value the server then rejects.
 */
export const maxBareDomainLen = 260;

// Compiled once. JavaScript's `$` (without the `m` flag) matches only at the end
// of input and — unlike Python's — does NOT match before a trailing newline, so
// `test` reproduces Go's RE2 anchoring here without further help. The shared
// vectors carry a trailing-newline case that fails any port which gets this
// wrong.
const bareDomainRe = new RegExp(bareDomainPattern);

/**
 * isBareDomain reports whether v is a bare domain of the shape the wire admits.
 *
 * The length is checked FIRST so the work stays bounded on hostile input. This is
 * insurance rather than a fix for a known blowup: the pattern is unambiguous —
 * every repetition is anchored by a literal dot no label class can consume — so it
 * cannot backtrack catastrophically, and matching it costs time linear in the
 * input. Bounding that is still worth one comparison on an engine that
 * backtracks. The order costs nothing in agreement — a value whose length differs
 * between UTF-16 units, code points and bytes contains something outside ASCII,
 * and the pattern refuses it regardless.
 */
export function isBareDomain(v: string): boolean {
	return v.length <= maxBareDomainLen && bareDomainRe.test(v);
}

/**
 * The outcome of checking a request's claimed recipient against this Exchange's
 * own identity. The tokens are the Go `AudienceVerdict.String()` vocabulary
 * verbatim, which is what the shared vectors record.
 *
 * `no_verdict` means the check did not run because the configured identity is
 * unusable. It is never RETURNED here — this port throws in that case, since a
 * deployment fault is not something a caller should be able to read as a value
 * — but it is in the vocabulary because the shared vectors carry it.
 */
export type AudienceVerdict =
	| "no_verdict"
	| "accepted"
	| "empty"
	| "malformed"
	| "mismatch";

/**
 * checkAudience reports whether every claimed recipient names this Exchange.
 *
 * `self` is this Exchange's own bare domain — the domain it publishes as its
 * IDENTITY, which is the value it stamps into the offers it issues. It is not the
 * host the process happens to listen on, and the two are allowed to differ: an
 * Exchange at `exchange.example` may serve its API from `api.exchange.example`, so
 * an operator who configures this from the listening host would refuse every
 * request that named them correctly.
 *
 * `claimed` holds the recipient
 * values the request carries — ONE for a message with a single `exchange`
 * field, MANY for a message whose audience lives per item (a TransactionRequest
 * states it once per item, in each item's signed offer). Every value must name
 * this Exchange; the first that does not decides the verdict, and a request
 * carrying no values at all is refused rather than waved through.
 *
 * The comparison is EXACT: a subdomain of this Exchange is a different party and
 * does not name it. That is narrower than the endpoint rule, which does let a
 * manifest advertise its endpoint on a subdomain of the host that served it —
 * there the question is which addresses one Exchange may be reached at, here it
 * is who the Exchange IS.
 *
 * Two spellings of the same identity still match: case is folded, and a port of
 * 443 written out is the same as leaving it off, since a schemeless domain is
 * read as https throughout this SDK. Port 80 is not folded — it is not the
 * default of the scheme a bare domain implies.
 *
 * Throws when `self` is not a bare domain. That is a fault in this deployment,
 * never in the request, and the two are kept apart so a caller can map them onto
 * different status codes without inspecting any message.
 */
export function checkAudience(self: string, ...claimed: string[]): AudienceVerdict {
	if (!isBareDomain(self)) {
		throw new Error(
			`hosts: configured Exchange identity is not a bare domain: ${JSON.stringify(self)}`,
		);
	}
	if (claimed.length === 0) {
		return "empty";
	}
	const want = normalizeDomain(self);
	for (const c of claimed) {
		if (c === "") {
			return "empty";
		}
		if (!isBareDomain(c)) {
			return "malformed";
		}
		if (normalizeDomain(c) !== want) {
			return "mismatch";
		}
	}
	return "accepted";
}

// splitHostPort splits `host[:port]` on the last colon; no colon means no port.
// Shared by the audience comparison and the identity-document rule, because the
// 443 fold below is half of BOTH origin comparisons and a change to it must not
// have to be made twice. Anything stranger than host[:port] is refused by
// isBareDomain, before this or right after it.
function splitHostPort(v: string): [string, string] {
	const i = v.lastIndexOf(":");
	if (i < 0) {
		return [v, ""];
	}
	return [v.slice(0, i), v.slice(i + 1)];
}

// 443 spelled out and 443 left implicit are the same port; nothing else folds. A
// schemeless domain is read as https everywhere in this SDK. Port 80 is NOT
// folded: that would be reading a scheme into a value that names none.
function foldDefaultPort(port: string): string {
	return port === "443" ? "" : port;
}

// normalizeDomain renders the two spellings of one identity as one string. It
// runs only on values isBareDomain has already accepted, so the input is ASCII
// and holds at most one colon followed by digits — which is what lets it split
// on that colon rather than parse a URL, and is why it reproduces the Go oracle
// exactly.
function normalizeDomain(v: string): string {
	const [rawHost, rawPort] = splitHostPort(v);
	const host = rawHost.toLowerCase();
	const port = foldDefaultPort(rawPort);
	return port === "" ? host : `${host}:${port}`;
}

// Identity-document resolution (TypeScript side of sdk/go/helpers/identitydocs.go).
//
// Deliberately NOT built on `hostAnchored` in ../resolvers/wba.ts: that one
// implements the endpoint rule, host or subdomain, and this field refuses a
// subdomain. Whoever takes over the host an endpoint names misdirects calls they
// still cannot sign for; whoever takes over the host an identity document names
// publishes their own keys and BECOMES the participant.
//
// The authority is read off the RAW string rather than through `new URL(...)`,
// and that is the load-bearing part of this port. WHATWG URL parsing runs IDNA
// on the host, which maps U+212A KELVIN SIGN to a plain ASCII "k" — so a
// homograph host would arrive already disguised as the name it is imitating.
// The same parse also lowercases the host and drops a spelled-out :443, which
// would quietly turn a padded port such as :0443 into a match. `isBareDomain`
// runs on the untouched value, and the port is compared as written, exactly as
// the Go oracle does.

// A scheme, if the reference carries one at all (RFC 3986 §3.1).
const uriSchemeRe = /^[A-Za-z][A-Za-z0-9+.-]*:/;

// The authority of a reference that HAS one: an absolute URI with "//" or a
// network-path reference beginning with "//". A reference matching neither is
// relative and inherits the base's authority untouched.
const uriAuthorityRe = /^(?:[A-Za-z][A-Za-z0-9+.-]*:)?\/\/([^/?#]*)/;

function uriScheme(ref: string): string {
	const m = uriSchemeRe.exec(ref);
	return m ? m[0].slice(0, -1).toLowerCase() : "";
}

// Every byte the coarse RFC 3986 character set admits: the unreserved set, the
// gen-delims, the sub-delims, and the percent sign that introduces an escape.
const uriCharRe = /^[A-Za-z0-9\-._~:/?#[\]@!$&'()*+,;=%]$/;
const hexDigitRe = /^[0-9A-Fa-f]$/;

/**
 * Say why `s` may not be resolved, as a fragment completing "the reference …",
 * or "" when it is fine. NEVER echoes the input, which can carry a credential.
 * Port of `untameReason` in sdk/go/helpers/identitydocs.go.
 *
 * This exists because the three SDKs do not share a URL parser, and the three
 * parsers disagree about everything outside this character set. Go percent-
 * encodes a literal "|" and a space, this port and the Python one keep them; a
 * control character makes the authority regex above read an ABSOLUTE reference
 * as a relative one and skip every origin check; Go refuses an invalid escape
 * and the other two accept it. Reproducing three parsers byte for byte is not
 * achievable, so the untame input is refused instead.
 *
 * DO NOT tighten this to the per-component pchar grammar. pchar would refuse
 * "[" and "]", which all three SDKs currently agree on, and there is a vector
 * pinning that.
 */
function untameReason(s: string): string {
	for (let i = 0; i < s.length; i++) {
		const c = s[i] ?? "";
		if (!uriCharRe.test(c)) {
			// Every control character, every space, the backslash, and every
			// non-ASCII code unit leaves through here.
			return "is not written in the RFC 3986 character set";
		}
		if (c !== "%") {
			continue;
		}
		const a = s[i + 1] ?? "";
		const b = s[i + 2] ?? "";
		if (!hexDigitRe.test(a) || !hexDigitRe.test(b)) {
			return "carries an invalid percent-escape";
		}
		// A percent-encoded dot needs its own refusal. The rule above admits a
		// percent followed by two hex digits, and dot-segment removal only ever
		// sees a LITERAL dot, so "%2e" would survive every other check — and
		// this is the port that splits: `new URL` decodes it and then collapses
		// the segment, which names a DIFFERENT DOCUMENT than Go and Python
		// return.
		if (`${a}${b}`.toLowerCase() === "2e") {
			return "carries a percent-encoded dot segment";
		}
	}
	return "";
}

/**
 * Is this a decimal number a TCP port can take? An omitted port passes. Port of
 * `portIsWritable` in sdk/go/helpers/identitydocs.go.
 *
 * The five-digit cap is not decoration: a padded ":0443" is accepted (it is a
 * different string from ":443" and does not fold, which a vector pins), so the
 * value cannot be compared as text — and without a length bound a long run of
 * leading zeros overflows Go's Atoi while the other two accept it, which would
 * be a new divergence.
 */
function portIsWritable(port: string): boolean {
	if (port === "") {
		return true;
	}
	if (port.length > 5 || !/^[0-9]+$/.test(port)) {
		return false;
	}
	const n = Number(port);
	return n >= 1 && n <= 65535;
}

/**
 * Resolve an `identity_documents` member against the URL ramp.json came from.
 *
 * `ref` is an RFC 3986 URI reference, relative or absolute. `manifestUrl` is the
 * URL the manifest was actually FETCHED FROM, never its self-asserted `domain`
 * member — a hostile manifest that named its own anchor would validate itself.
 *
 * Refuses unless BOTH strings are tame (written in the coarse RFC 3986 character
 * set, every percent-escape valid, no percent-encoded dot segment — see
 * `untameReason`); the base is https, names a plain host and carries no
 * userinfo; the reference is non-empty; and the resolved URL is https, carries
 * no userinfo, names a port inside 1-65535 and sits on the SAME ORIGIN as the
 * base (equal host, equal effective port).
 * Vetting the base is not a courtesy: a base of `http://a.example/ramp.json`
 * resolving to `https://a.example/doc` passes every later check, and accepting
 * it means trusting a manifest that arrived unauthenticated.
 *
 * Returns the resolved URL in canonical form — host lowercased, a default port
 * folded away — so every SDK returns the same string for the same input.
 *
 * @throws Error when the reference may not be fetched.
 */
export function resolveIdentityDocument(manifestUrl: string, ref: string): string {
	const baseWhy = untameReason(manifestUrl);
	if (baseWhy !== "") {
		// The base is checked as strictly as the reference. A tab in the base
		// PATH — not a leading one, which the scheme check already catches — was
		// accepted here and refused by Go, and every answer below is computed
		// from this string.
		throw new Error(`identity document: manifest URL ${baseWhy}`);
	}
	if (manifestUrl.includes("#")) {
		// A fragment is never sent to a server, so the URL a manifest was FETCHED
		// FROM cannot carry one. Refused rather than ignored: RFC 3986 5.2.2
		// inherits the base's fragment for a reference that defines none, and the
		// three SDKs disagree about whether a reference of "#" defines an empty
		// fragment or none at all. No fragment on the base, no question to
		// disagree about.
		throw new Error("identity document: manifest URL carries a fragment");
	}
	if (uriScheme(manifestUrl) !== "https") {
		throw new Error("identity document: manifest URL is not https");
	}
	const baseAuthorityMatch = uriAuthorityRe.exec(manifestUrl);
	if (baseAuthorityMatch === null) {
		throw new Error("identity document: manifest URL names no authority");
	}
	// Always present when the pattern matched; the ?? keeps the strict index
	// check happy, and an empty authority is refused by isBareDomain below anyway.
	const baseAuthority = baseAuthorityMatch[1] ?? "";
	if (baseAuthority.includes("@")) {
		// Deliberately does not echo the URL: it carries the credential.
		throw new Error("identity document: manifest URL carries userinfo");
	}
	const [baseHost, rawBasePort] = splitHostPort(baseAuthority);
	if (!isBareDomain(baseHost)) {
		throw new Error("identity document: manifest URL does not name a plain host");
	}
	if (!portIsWritable(rawBasePort)) {
		throw new Error("identity document: manifest URL names a port outside 1-65535");
	}
	const basePort = foldDefaultPort(rawBasePort);

	if (ref.trim() === "") {
		throw new Error("identity document: empty reference");
	}
	const refWhy = untameReason(ref);
	if (refWhy !== "") {
		throw new Error(`identity document: reference ${refWhy}`);
	}
	const refScheme = uriScheme(ref);
	// RFC 3986 3.3 and 4.2: a reference with no scheme is path-noscheme, and its
	// FIRST segment may not contain a colon — ":/x" and "1:x" would otherwise be
	// ambiguous with a scheme. Go's url.Parse refuses ":/x"; this port and the
	// Python one resolved both into an ordinary path segment. Spelled out so the
	// answer does not depend on which parser happens to notice.
	if (refScheme === "" && /^[^/?#]*:/.test(ref)) {
		throw new Error("identity document: reference's first segment carries a colon");
	}
	const refAuthorityMatch = uriAuthorityRe.exec(ref);
	if (refScheme !== "" && refScheme !== "https") {
		throw new Error("identity document: reference does not resolve to an https URL");
	}
	if (refScheme !== "" && refAuthorityMatch === null) {
		// "https:/dir" — a scheme with no "//" names no authority, so it resolves
		// to a URL with no host rather than borrowing the base's.
		throw new Error("identity document: reference names no authority");
	}
	if (refAuthorityMatch !== null) {
		const refAuthority = refAuthorityMatch[1] ?? "";
		if (refAuthority.includes("@")) {
			// Deliberately does not echo the reference: it carries the credential.
			throw new Error("identity document: reference carries userinfo");
		}
		const [refHost, refPort] = splitHostPort(refAuthority);
		if (!isBareDomain(refHost)) {
			throw new Error("identity document: reference does not name a plain host");
		}
		if (!portIsWritable(refPort)) {
			throw new Error("identity document: reference names a port outside 1-65535");
		}
		if (refHost.toLowerCase() !== baseHost.toLowerCase()) {
			throw new Error("identity document: reference is not on the manifest's origin");
		}
		if (foldDefaultPort(refPort) !== basePort) {
			throw new Error("identity document: reference is on a different port than the manifest");
		}
	}

	// Only the path, query and fragment are taken from the join: the authority is
	// rebuilt from the values already checked above, which is what makes the
	// output canonical rather than an echo of however the manifest spelled it —
	// and what keeps WHATWG's own normalizations out of the answer.
	//
	// THE REBUILD IS LOAD-BEARING, not a formatting step. The origin checks above
	// read the authority off the RAW string with a regex; if that regex is ever
	// made to disagree with `new URL` about where the authority ends, the join
	// can land on another host while every check above passes. Rebuilding from
	// baseHost means the answer is on the checked origin even then. That is not
	// theoretical — before the tame predicate above, a leading tab made this
	// regex read an absolute reference to evil.example as a relative path, and
	// this line was the only thing that kept the result on a.example.
	let joined: URL;
	try {
		joined = new URL(ref, manifestUrl);
	} catch {
		// `new URL` throws a bare TypeError, which is outside the error family
		// this function documents. Everything measured that reached it is
		// refused above, so this is the backstop rather than the rule — but a
		// caller catching by message prefix must never see an unhandled throw.
		throw new Error("identity document: reference cannot be resolved against the manifest URL");
	}
	const authority = basePort === "" ? baseHost.toLowerCase() : `${baseHost.toLowerCase()}:${basePort}`;
	return `https://${authority}${joined.pathname}${joined.search}${joined.hash}`;
}
