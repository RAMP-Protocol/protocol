// The references registry: the SINGLE source of truth for the external standards the
// protocol cites. It is consumed twice — rendered as the References page
// (reference/standards) and used by remark-standards to link the first mention of
// each standard in the docs. One entry per standard, so a standard can never resolve
// to two different URLs.
//
// Each entry: { id, name, title, url, aliases }. `aliases` are the literal,
// word-bounded terms that link to this entry (case-sensitive — list case variants
// explicitly, e.g. Ed25519/ed25519). RFC-defined acronyms fold into the RFC entry.
const rfc = (n) => `https://www.rfc-editor.org/rfc/rfc${n}`;

export const STANDARDS = [
  { id: 'rfc-2119', name: 'RFC 2119', title: 'Key words for requirement levels (MUST/SHOULD/MAY)', url: rfc(2119), aliases: ['RFC 2119'] },
  { id: 'rfc-3161', name: 'RFC 3161', title: 'X.509 Time-Stamp Protocol (TSP)', url: rfc(3161), aliases: ['RFC 3161'] },
  { id: 'rfc-3339', name: 'RFC 3339', title: 'Date and Time on the Internet: Timestamps', url: rfc(3339), aliases: ['RFC 3339'] },
  { id: 'rfc-3986', name: 'RFC 3986', title: 'URI: Generic Syntax', url: rfc(3986), aliases: ['RFC 3986'] },
  { id: 'rfc-6648', name: 'RFC 6648', title: 'Deprecating the "X-" Prefix in application protocols', url: rfc(6648), aliases: ['RFC 6648'] },
  { id: 'rfc-7252', name: 'RFC 7252', title: 'Constrained Application Protocol (CoAP)', url: rfc(7252), aliases: ['RFC 7252'] },
  { id: 'rfc-7515', name: 'RFC 7515', title: 'JSON Web Signature (JWS)', url: rfc(7515), aliases: ['RFC 7515', 'JWS'] },
  { id: 'rfc-7517', name: 'RFC 7517', title: 'JSON Web Key (JWK)', url: rfc(7517), aliases: ['RFC 7517', 'JWK'] },
  { id: 'rfc-7519', name: 'RFC 7519', title: 'JSON Web Token (JWT)', url: rfc(7519), aliases: ['RFC 7519', 'JWT'] },
  { id: 'rfc-7638', name: 'RFC 7638', title: 'JSON Web Key (JWK) Thumbprint', url: rfc(7638), aliases: ['RFC 7638'] },
  { id: 'rfc-7800', name: 'RFC 7800', title: 'Proof-of-Possession key semantics for JWTs (cnf)', url: rfc(7800), aliases: ['RFC 7800'] },
  { id: 'rfc-8032', name: 'RFC 8032', title: 'Edwards-Curve Digital Signature Algorithm (EdDSA / Ed25519)', url: rfc(8032), aliases: ['RFC 8032', 'EdDSA', 'Ed25519', 'ed25519'] },
  { id: 'rfc-8785', name: 'RFC 8785', title: 'JSON Canonicalization Scheme (JCS)', url: rfc(8785), aliases: ['RFC 8785', 'JCS'] },
  { id: 'rfc-9052', name: 'RFC 9052', title: 'CBOR Object Signing and Encryption (COSE)', url: rfc(9052), aliases: ['RFC 9052', 'COSE'] },
  { id: 'rfc-9421', name: 'RFC 9421', title: 'HTTP Message Signatures', url: rfc(9421), aliases: ['RFC 9421'] },
  { id: 'rfc-9449', name: 'RFC 9449', title: 'OAuth 2.0 Demonstrating Proof of Possession (DPoP)', url: rfc(9449), aliases: ['RFC 9449'] },
  { id: 'rfc-9635', name: 'RFC 9635', title: 'Grant Negotiation and Authorization Protocol (GNAP)', url: rfc(9635), aliases: ['RFC 9635'] },
  { id: 'rfc-9676', name: 'RFC 9676', title: 'LEX: a URN namespace for sources of law', url: rfc(9676), aliases: ['RFC 9676'] },
  { id: 'c2pa', name: 'C2PA', title: 'Coalition for Content Provenance and Authenticity', url: 'https://c2pa.org/specifications/', aliases: ['C2PA'] },
  { id: 'spdx', name: 'SPDX', title: 'Software Package Data Exchange license list', url: 'https://spdx.org/licenses/', aliases: ['SPDX'] },
  { id: 'iso-3166', name: 'ISO 3166', title: 'Country codes (alpha-2)', url: 'https://www.iso.org/iso-3166-country-codes.html', aliases: ['ISO 3166'] },
  { id: 'w3c-trace-context', name: 'W3C Trace Context', title: 'Distributed trace context propagation', url: 'https://www.w3.org/TR/trace-context/', aliases: ['W3C Trace Context', 'Trace Context'] },
  { id: 'rsl', name: 'RSL', title: 'Really Simple Licensing', url: 'https://rslstandard.org/', aliases: ['RSL'] },
  { id: 'biscuit', name: 'biscuit', title: 'Biscuit authorization tokens', url: 'https://www.biscuitsec.org/', aliases: ['biscuit', 'Biscuit'] },
];
