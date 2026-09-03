// Reading what one Exchange asks of a registration — the terms revision that
// submitting one accepts, and the schema its registration_data must match — out of
// that Exchange's own /.well-known/ramp.json. TS port of the Go oracle
// (resolvers/registrationrequirements.go).
//
// EVERY READ IS A FRESH FETCH, and that is the whole design. The protocol requires
// it in as many words: a registering client MUST read the terms digest from a
// freshly fetched manifest rather than a cached copy. A cached ENDPOINT is fine — a
// wrong one fails loudly — but a cached DIGEST is not, because a client cannot
// detect staleness locally, so a warm cache would make it echo a value the Exchange
// has already stopped accepting and retry the same refusal until the cache expired.
//
// That is why this is a SEPARATE face rather than a third method on the endpoint
// resolver. That resolver is built out of exactly the mechanism this value may not
// touch — a per-host TTL cache with single-flight coalescing on top — and it exposes
// no bypass. A face that holds no document cache leaves no cache slot to reuse,
// which is what makes the rule structural rather than a convention callers remember.
//
// Not even the compiled validator is held. Memoising it is a cache, and the useful
// key for one is a property of a deployment's threat model rather than of the
// protocol; an application that wants it wraps this face.

import { isBareDomain } from "../src/hosts.ts";
import { invalidHost } from "../src/host-ref.ts";
import {
  compileRegistrationSchema,
  type RegistrationSchema,
  type SchemaVerdict,
} from "../src/regschema.ts";
import { DirectoryUnavailable, ExchangeNotPermitted, ManifestNotExchange } from "./errors.ts";
import { type FetchLike, defaultFetch, fetchStrict } from "./http.ts";

/** What one Exchange asks of a registration. Both members are optional in the
 * contract, and their absence is a normal answer rather than a failure. */
export interface RegistrationRequirements {
  /** The manifest's `terms_digest`, `undefined` when the Exchange publishes none.
   * Copy it onto `RegisterRequest.terms_digest` unchanged: the request signature
   * covers the echo, and that echo is the durable record of which terms revision
   * the operator accepted. */
  termsDigest: string | undefined;
  /** Validates `registration_data` before anything is signed. `null` in TWO cases
   * — the Exchange publishes none, and it publishes one this SDK refuses — and
   * `verdict` is what tells them apart. Both are deliberately the same VALUE,
   * because the contract requires a client that cannot check locally to send
   * anyway: a local check that cannot run must not become a local veto. */
  schema: RegistrationSchema | null;
  /** The SDK's answer for the published schema. `not_published` is the ordinary
   * absent case; `accepted` means `schema` is usable; anything else names why a
   * published schema was refused, which is worth logging and is never worth
   * refusing the registration over. */
  verdict: SchemaVerdict;
}

/** The well-known registration-requirements face, named for the concrete reader
 * the oracle exposes (`resolvers.WellKnownRequirementsReader`). */
export interface WellKnownRequirementsReader {
  resolveRegistrationRequirements(exchange: string): Promise<RegistrationRequirements>;
}

/** Options for the reader. `ttlMs` and `now` are deliberately absent: it caches
 * nothing, so it has no freshness to compute. */
export interface WellKnownRequirementsOptions {
  fetch?: FetchLike;
  /** Trust allowlist consulted BEFORE the fetch. A domain it rejects never
   * reaches the network. */
  allow?: (domain: string) => boolean;
  /** The URL scheme used to build `{scheme}://{domain}/.well-known/ramp.json`
   * (tests inject "http"). */
  scheme?: string;
}

/** Read registration requirements from an Exchange's own well-known manifest. */
export function createWellKnownRequirementsReader(
  opts: WellKnownRequirementsOptions = {},
): WellKnownRequirementsReader {
  const fetchFn: FetchLike = opts.fetch ?? defaultFetch;
  const scheme = opts.scheme && opts.scheme !== "" ? opts.scheme : "https";
  const allow = opts.allow;

  return {
    async resolveRegistrationRequirements(exchange: string): Promise<RegistrationRequirements> {
      // The SHAPE predicate is the contract's isBareDomain, not the routing tier's
      // isBareHost. The two are kept apart deliberately and this leg is where the
      // difference bites: nothing upstream has run the contract's rule, and the URL
      // below is built by concatenation, so a value carrying a path or userinfo
      // would choose WHAT is fetched rather than merely where from.
      if (!isBareDomain(exchange)) {
        throw invalidHost(exchange, "not a bare domain");
      }
      if (allow && !allow(exchange)) {
        throw new ExchangeNotPermitted(`exchange ${exchange} not permitted by policy`);
      }
      const url = `${scheme}://${exchange}/.well-known/ramp.json`;
      const body = await fetchStrict(fetchFn, url);
      let doc: unknown;
      try {
        doc = JSON.parse(body);
      } catch (err) {
        throw new DirectoryUnavailable(`manifest decode ${url}`, { cause: err });
      }
      if (doc === null || typeof doc !== "object" || Array.isArray(doc)) {
        throw new DirectoryUnavailable(`manifest at ${url} is not a JSON object`);
      }
      if (!describesExchange(doc)) {
        throw new ManifestNotExchange(`host=${exchange}`);
      }
      const digest = (doc as { terms_digest?: unknown }).terms_digest;
      const out: RegistrationRequirements = {
        termsDigest: typeof digest === "string" ? digest : undefined,
        schema: null,
        verdict: "not_published",
      };
      // Compiled from the bytes AS SERVED. Every cap the registration-schema rules
      // state is defined over those bytes, so the member is sliced out of the body
      // rather than re-serialised from the parsed value: JSON.parse discards
      // whitespace and reformats numbers, and a document that minifies under the
      // cap while exceeding it on the wire would be refused by an Exchange and
      // accepted here — the two-privately-chosen-limits failure the contract's
      // numbers exist to prevent.
      const raw = rawMember(body, "account_registration", "data_schema");
      if (raw !== undefined) {
        const compiled = compileRegistrationSchema(raw);
        out.schema = compiled.schema;
        out.verdict = compiled.verdict;
      }
      return out;
    },
  };
}

/** proto-JSON renders an enum as its name or its number, so both are accepted. An
 * absent or unrecognised role is not an Exchange. */
function describesExchange(doc: unknown): boolean {
  const role = (doc as { role?: unknown }).role;
  return role === "ROLE_EXCHANGE" || role === 2;
}

/** rawMember returns the EXACT served text of a nested object member, or
 * `undefined` when any step of the path is absent.
 *
 * It exists because JavaScript has no equivalent of a raw-message slice: the only
 * way to hand a nested member to a rule defined over the bytes AS SERVED is to
 * find its extent in the body. `body` has already parsed as JSON when this runs,
 * so the scan below is over known-well-formed input and needs no error path — it
 * returns `undefined` for anything it cannot walk, and the caller reads that as
 * "no schema published", which is the safe direction.
 */
function rawMember(body: string, ...path: string[]): string | undefined {
  let start = 0;
  for (let step = 0; step < path.length; step++) {
    const found = memberExtent(body, start, path[step] as string);
    if (found === undefined) return undefined;
    if (step === path.length - 1) return body.slice(found[0], found[1]);
    start = found[0];
  }
  return undefined;
}

/** memberExtent finds `key` in the object beginning at `from` and returns the
 * [start, end) of its VALUE. */
function memberExtent(body: string, from: number, key: string): [number, number] | undefined {
  let i = skipWhitespace(body, from);
  if (body[i] !== "{") return undefined;
  i = skipWhitespace(body, i + 1);
  if (body[i] === "}") return undefined;
  for (;;) {
    if (body[i] !== '"') return undefined;
    const keyEnd = skipString(body, i);
    const name = JSON.parse(body.slice(i, keyEnd)) as string;
    i = skipWhitespace(body, keyEnd);
    if (body[i] !== ":") return undefined;
    const valueStart = skipWhitespace(body, i + 1);
    const valueEnd = skipValue(body, valueStart);
    if (valueEnd === undefined) return undefined;
    if (name === key) return [valueStart, valueEnd];
    i = skipWhitespace(body, valueEnd);
    if (body[i] === ",") {
      i = skipWhitespace(body, i + 1);
      continue;
    }
    return undefined;
  }
}

/** RFC 8259 whitespace, and nothing wider — the same four bytes the blank-schema
 * rule counts. */
function skipWhitespace(body: string, i: number): number {
  while (i < body.length) {
    const c = body[i];
    if (c !== " " && c !== "\t" && c !== "\r" && c !== "\n") return i;
    i++;
  }
  return i;
}

/** skipString returns the index just past a JSON string starting at `i`. */
function skipString(body: string, i: number): number {
  i++; // the opening quote
  while (i < body.length) {
    const c = body[i];
    if (c === "\\") {
      i += 2;
      continue;
    }
    if (c === '"') return i + 1;
    i++;
  }
  return i;
}

/** skipValue returns the index just past the JSON value starting at `i`, or
 * `undefined` when the value does not terminate. */
function skipValue(body: string, i: number): number | undefined {
  const c = body[i];
  if (c === '"') return skipString(body, i);
  if (c === "{" || c === "[") {
    const close = c === "{" ? "}" : "]";
    let depth = 0;
    while (i < body.length) {
      const ch = body[i];
      if (ch === '"') {
        i = skipString(body, i);
        continue;
      }
      if (ch === "{" || ch === "[") depth++;
      else if (ch === "}" || ch === "]") {
        depth--;
        if (depth === 0) {
          return body[i] === close ? i + 1 : undefined;
        }
      }
      i++;
    }
    return undefined;
  }
  // A number, or one of the three literals: everything up to the next structural
  // character. The body has already parsed, so whatever lies here is well formed.
  const end = /[\s,}\]]/.exec(body.slice(i));
  return end === null ? body.length : i + end.index;
}
