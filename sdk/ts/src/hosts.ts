// Host predicates, the audience check and the bare-domain shape — TS port of the
// sdk/go oracle (helpers/hosts.go, helpers/audience.go).
//
// Two kinds of predicate live here and keeping them apart is the point. The
// ROUTING predicates — isBareHost and hostAnchored — precede a signed call to an
// address a network party named: a value that arrives inside an offer, or inside
// a manifest that offer pointed at, is about to be concatenated into a URL or
// dialled directly. The SHAPE predicate — isBareDomain — answers a different
// question: whether a value is the form the wire contract admits at all.
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

// normalizeDomain renders the two spellings of one identity as one string. It
// runs only on values isBareDomain has already accepted, so the input is ASCII
// and holds at most one colon followed by digits — which is what lets it split
// on that colon rather than parse a URL, and is why it reproduces the Go oracle
// exactly.
function normalizeDomain(v: string): string {
	const i = v.lastIndexOf(":");
	const host = (i >= 0 ? v.slice(0, i) : v).toLowerCase();
	const port = i >= 0 ? v.slice(i + 1) : "";
	// A schemeless domain is read as https everywhere in this SDK, so 443 spelled
	// out and 443 left implicit are the same port. Any other port is kept, 80
	// included: folding it would be reading a scheme into a value that names none.
	if (port === "" || port === "443") {
		return host;
	}
	return `${host}:${port}`;
}

// ---------------------------------------------------------------------------
// Routing predicates
// ---------------------------------------------------------------------------

/** A reference that cannot be read as a host at all. The Go oracle exposes an
 * errors.Is sentinel here; this port throws, as the audience check above does,
 * because a sentinel is not how a caller in this language distinguishes causes. */
function invalidHost(ref: string, why: string): Error {
	return new Error(`hosts: reference is not a usable host: ${why}: ${JSON.stringify(ref)}`);
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

// A control character is refused outright rather than removed. This is the reason
// the platform parser cannot be used here: `new URL` strips tabs, newlines and
// leading control characters per WHATWG, so it answers "host" where the oracle
// answers "not a host". The port is read textually below for the same kind of
// reason — `new URL` folds a scheme's default port away at PARSE time, which is
// earlier than this rule decides which scheme is even in play.
const controlChar = /[\u0000-\u001F\u007F]/;
const digitsOnly = /^[0-9]*$/;

interface ParsedRef {
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
}

/** Read a bare domain, a host:port pair, or a full URL into its authority. A ref
 * with no scheme is read as though it carried https, since a bare domain is
 * otherwise indistinguishable from a path. One parse behind both host predicates,
 * so neither can disagree with the other about what a reference even is. */
function parseRef(ref: string): ParsedRef {
	if (ref.trim() === "") {
		throw invalidHost(ref, "empty reference");
	}
	if (controlChar.test(ref)) {
		throw invalidHost(ref, "control character");
	}
	// A percent-escape is refused rather than decoded. The oracle admits only the
	// escapes that decode to a byte at or above 0x80 (and %25 itself), which no
	// domain name carries; refusing all of them costs nothing a caller can use and
	// removes an unescaping step the three languages would each get subtly wrong.
	// Every value the two answers differ on is one both refuse at every call site.
	if (ref.includes("%")) {
		throw invalidHost(ref, "percent-escape in a host reference");
	}

	const hadScheme = ref.includes("://");
	const work = hadScheme ? ref : `https://${ref}`;
	const sep = work.indexOf("://");
	const scheme = hadScheme ? work.slice(0, sep).toLowerCase() : "https";

	// The authority ends at the first delimiter that starts a path, query or
	// fragment — the three things a reference can carry beyond it.
	const rest = work.slice(sep + 3);
	const end = rest.search(/[/?#]/);
	const authority = end < 0 ? rest : rest.slice(0, end);

	// Userinfo is split at the LAST "@", so an "@" inside a credential does not
	// become part of the host.
	const at = authority.lastIndexOf("@");
	const host = at < 0 ? authority : authority.slice(at + 1);
	if (host === "") {
		throw invalidHost(ref, "no host");
	}
	for (const ch of host) {
		const cp = ch.codePointAt(0) ?? 0;
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
	return { host, hostname, port, hadScheme, scheme };
}

/**
 * hostOf extracts the host (including any port) from a bare domain, a host:port
 * pair, or a full URL. A ref with no scheme is read as though it carried https,
 * since a bare domain is otherwise indistinguishable from a path.
 *
 * Throws when the reference cannot be read as a host at all.
 */
export function hostOf(ref: string): string {
	return parseRef(ref).host;
}

/**
 * isBareHost reports whether ref is EXACTLY a host — nothing a URL could carry
 * besides the authority. It answers false for a ref with a scheme, userinfo, a
 * path, a query or a fragment, because hostOf had to strip something to reach the
 * host. A port is NOT a strip: "exchange.example:8443" is a bare host, and the
 * well-known resolver concatenates host-with-port unchanged.
 *
 * It exists for the callers that hand a network-supplied domain to code which
 * builds a URL by concatenation. There, narrowing a rich reference to its host is
 * the wrong repair: the value was never a domain, and accepting it silently means
 * the far side chose the path that gets fetched, not just the host it is fetched
 * from. Comparing against the extracted host is what makes the rejection
 * structural rather than a blocklist of the separators anyone thought to name.
 *
 * This is NOT isBareDomain. A trailing root dot, a leading or trailing hyphen, an
 * underscore, an empty label and a bracketed IPv6 literal are all usable hosts and
 * none of them is a value the wire rule accepts. A caller vetting a value it is
 * about to dial wants this one; a caller vetting a value that arrived in a message
 * wants isBareDomain.
 */
export function isBareHost(ref: string): boolean {
	const host = hostOf(ref);
	// A trailing colon parses as a host with an empty port and would otherwise
	// compare equal to itself. It is not a domain anyone meant to write, and the
	// callers here concatenate the value into a URL, so it is refused rather than
	// quietly normalized away.
	if (host.endsWith(":")) {
		return false;
	}
	return host === ref;
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

/**
 * hostAnchored reports whether candidate is anchored to anchor — the same host and
 * port, or a subdomain of that host on that port. Either side may be a bare
 * domain, a host:port pair or a full URL; a reference that does not parse throws,
 * which callers treat as "not anchored".
 *
 * The use is checking a value a remote document supplied against the host that
 * served that document: it may point at itself or at one of its own subdomains,
 * and nothing else. Without it, a host could redirect a signed request — or a
 * revocation poll — to an unrelated third-party address that a dial-time address
 * guard would happily allow, because the address is perfectly public.
 *
 * The PORT is part of the comparison. What is being anchored is a place a signed
 * call is sent, and a different port is a different service — one the party that
 * published the anchor need not control. A DEFAULT port and its omission are the
 * same port, so https://x, https://x:443 and x all anchor to one another; refusing
 * an operator who merely wrote :443 out in full would be a spelling check wearing
 * a security check's clothes.
 *
 * The SCHEME is still not compared. Whether a leg may run in the clear is the
 * guarded transport's decision, made in one place from one flag. Its only job here
 * is choosing which port counts as the default — and a side that NAMED no scheme
 * borrows the other's for that purpose, rather than being assumed to mean https.
 * Both anchors in this SDK arrive schemeless: a WBA directory's authority and an
 * Offer.exchange host are bare host[:port] values. Assuming https for them meant an
 * anchor of "a.example:80" kept its port (80 is not https's default) while the
 * candidate "http://a.example:80" folded it away — the same authority reaching two
 * answers, which silently un-anchored every plaintext directory that spelled :80
 * in full.
 */
export function hostAnchored(anchor: string, candidate: string): boolean {
	const a = parseRef(anchor);
	const c = parseRef(candidate);
	const anchorScheme = a.hadScheme ? a.scheme : c.scheme;
	const candidateScheme = c.hadScheme ? c.scheme : a.scheme;
	// Compared as two values rather than one joined string. Joined, the label
	// boundary would have to find ".a.com" at the end of "sub.a.com:8443" and would
	// refuse a subdomain for having a port — the right answer reached through the
	// wrong comparison is still the wrong comparison.
	return (
		sameOrSubdomain(a.hostname, c.hostname) &&
		canonicalPort(anchorScheme, a.port) === canonicalPort(candidateScheme, c.port)
	);
}
