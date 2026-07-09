// opaqueUrl coerces a URL-like input to the primitive string the OPAQUE-URL-BYTES
// contract (signurl.ts) operates on, ONCE at each public SDK boundary.
//
// The URL-consuming faces (Ed25519 signed-URL verify, RFC 9421 GET-PoP verify)
// type their input as `string`, but some edge runtimes — Fastly Compute — hand
// the request URL as a URL-LIKE OBJECT. Left uncoerced, that object either throws
// (canonicalUrl's indexOf/slice string ops) or silently WHATWG-normalizes (a
// `@target-uri` template literal calls toString(): lowercased host, stripped
// :443, re-escaped path) — producing a signature base that diverges from the
// verbatim bytes the signer covered.
//
// Coercing here is a NO-OP for the common server-to-server string caller
// (String(s) === s, so the verbatim bytes are preserved) and gives a URL-like
// object a single, explicit string form instead of an implicit toString() at
// every downstream parse/interpolation site. It is deliberately NOT
// `new URL(x).toString()`: that re-normalizes and would break byte-parity with
// the Go signer's verbatim @target-uri (sigbase.go reconstructTargetURI).
export function opaqueUrl(url: string | { toString(): string }): string {
  return String(url);
}
