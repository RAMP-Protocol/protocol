# RAMP Design History

RAMP v1.0 is presented as a single, cleanly designed protocol, but several of its
shapes are the result of deliberate reversals during design. This document
records the *reasoning* behind the decisions that most shaped the wire format, so
that the absence of the alternatives is understood as intentional rather than
accidental. It is not a changelog — the per-revision wire-format detail lives in
git history.

## Request and hop authentication: RFC 9421, hop-by-hop

Early drafts carried authentication inside the protobuf messages: per-message
signature fields on requests, on each intermediary hop, and on catalog pushes. We
moved all request authentication to RFC 9421 HTTP Message Signatures
(`alg=ed25519`) and removed those fields. Two reasons drove this. First, signing
the HTTP request rather than a serialized body means the signature covers exactly
what the transport delivers — method, path, headers, content digest — and is
verifiable by standard middleware and edge functions without RAMP-specific
parsing. Second, multi-hop chains (Agent → Broker → … → Exchange) are the
expected common case, not an exception. RFC 9421 lets each hop add its own
`Signature` / `Signature-Input` entry independently, so a verifier checks each
hop against the key it fetches from that hop's `/.well-known/ramp.json` — there is
no nested in-message co-signing scheme to define or version. Content that must
outlive a single HTTP exchange — offers, attestations — keeps its signature as
JWS (RFC 7515, `alg=EdDSA`), because those objects are stored, forwarded, and
re-verified out of band.

Multi-hop forwarding rides on the same primitive rather than an in-message hop
list. A forwarded request carries a stack of RFC 9421 signatures — one per party
(the agent, then each broker), each covering the request and the previous hop's
signature — so the ordered set of signatures is the forwarding chain,
tamper-evident and order-bound, with no nested co-signing scheme or hop array to
define and version. `RequestConstraints.max_hops` and
`WellKnownManifest.max_intermediary_hops` let the agent and the Exchange,
respectively, publish a chain-depth tolerance, enforced by counting signatures.
Responses do not retrace the chain: the terminal Exchange returns directly to the
originating agent, because the signed `retrieval_endpoint` is already bound to the
agent's identity (`agent_identity_hash`) and needs no return-path relay.

## Canonical signing: JCS over proto-JSON, not deterministic protobuf

The two signed RAMP payloads that cover a protobuf message — `Offer.signature` and
the agent's `AgentAcceptance.signature` — originally covered deterministic protobuf
*binary*: marshal the message with deterministic field order, sign those bytes. We
reversed that and moved both onto RFC 8785 JCS over canonical proto-JSON,
`JCS(protojson(msg with the signature fields cleared))`, under one pinned
proto-JSON option set (snake_case field names, enums as name strings, unpopulated
fields omitted). (`ResourceAttestation.signature` also outlives an HTTP exchange but
is out of scope here: it signs a hand-built JSON object — `{verifier, keyid,
attested_at, uri, claims}` — under its own rule, never a rendering of its proto
message.)

Deterministic protobuf marshaling is not actually canonical. Protobuf's own
documentation disclaims byte stability across languages, across library versions,
and in the presence of unknown fields — it is a best-effort local property, not a
wire-format guarantee. That makes it unusable as the basis of a signature two
independent implementations must agree on, which is precisely the RAMP case: an
agent SDK signs, a broker relays, an Exchange verifies, and none of them need share
a language. It also forces every verifier — including an edge worker or a browser
client — to link a protobuf binary codec just to check a signature. JCS over
proto-JSON has neither problem: it is a published canonicalization of JSON, and any
language can reproduce the signed bytes from the JSON rendering alone. The
Go-emitted golden vector is the arbiter, and the TS and Python SDKs replay it
byte-for-byte.

The form then changed a **second** time, within JCS. The first cut rendered
proto-JSON with its default camelCase `json_name` keys; we re-pinned it to
snake_case proto field names (`UseProtoNames=true`) so the wire, the conformance
corpus, the generated Pydantic/Zod clients, and the signed form all share one
naming — protojson accepts both spellings on input, so the duality was silently
hiding client divergence rather than absorbing it. That re-pin **re-signed the
golden vectors**: signatures produced over the camelCase-JCS form no longer verify,
and all three SDKs had to move in the same commit.

One clause of that pinned option set carries more weight than it looks.
`EmitUnpopulated=false` means an empty field is *absent* from the JSON, not present
with an empty value — so the canonical bytes for an empty string field are never the
bytes for a populated one. Go inherits that from `protojson` for free. A port that
assembles the JSON object by hand does not, and has to enumerate the omission for
every field or it signs bytes Go never produces. The acceptance payload is the one
place the Python and TS ports hand-build the object — Go renders the
`AgentAcceptancePayload` message through the same protojson canonicalizer as the
offer — and it is exactly where the divergence
appeared: Python and TS dropped an empty `requester_domain` but emitted an empty
`requester_id`, which is wire-valid because `Requester.id` carries no `min_len`. Such
a mismatch fails closed, but it falsifies the byte-equivalence the canonical-bytes
accessors promise, so the shared corpus now carries a vector that holds every port to
the omission.

The two reversals left a consequence worth naming, because it is the reason the
canonical bytes are a first-class SDK export rather than an internal detail. A
canonical form that has already changed twice can change again, and a verifier that
re-derives the bytes at verification time has silently pinned an *already-signed*
payload to whatever canonicalization the SDK implements *later* — the failure would
surface as "the signature does not verify", indistinguishable from "it was never
signed". So all three SDKs expose the exact signed bytes as a public accessor
(`CanonicalOfferBytes` / `CanonicalAcceptanceBytes` in Go, `canonical_offer_payload`
/ `jcs_acceptance_payload` in Python, `canonicalOfferPayload` / `acceptancePayload`
in TS). A party keeping evidence stores those bytes and re-verifies against them
verbatim, rather than trusting a future canonicalizer to reproduce the past.

Storing them is necessary, not sufficient. A signature that verifies over stored bytes
proves only that the holder of that key signed *those bytes*; it says nothing about
which transaction they belong to. Whoever reads the evidence must also parse the stored
bytes and match their content — offer id, requester, idempotency key — against the
transaction under dispute. Skip that and any valid triple minted under the same key
passes as evidence for any transaction.

## "Marketplace" → "Exchange"

The selling intermediary was originally called a *marketplace*. We renamed it to
*Exchange* throughout — service name, field names, enum values, and well-known
filenames. "Marketplace" overloaded a term that, in the surrounding ad-tech and
content-licensing world, implies a consumer-facing storefront and a particular
business model. RAMP's intermediary is closer to a financial or advertising
*exchange*: a neutral venue that matches buyers (agents and brokers) to priced
inventory, clears a transaction, and produces an auditable settlement record. The
narrower word sets the right expectation for implementers and avoids colliding
with publishers' existing "marketplace" products. With no external consumers at
the time, the rename was taken as a clean break rather than carried as an alias.

## One unified `WellKnownManifest`, not per-role manifests

Discovery initially used a different well-known document per role — a provider
manifest, an exchange manifest at `ramp-exchange.json`, an agent key file at
`ramp-agent.json`, a verifier file at `ramp-verifier.json`, plus a separate
`/marketplace/v1/keys` key endpoint. We collapsed all of them into a single
`WellKnownManifest` served at `/.well-known/ramp.json` by every participant,
role-tagged by a `role` enum. Every RAMP party already needs the same core thing
at the same path: a domain, its public keys, and a contact. Maintaining four
near-identical schemas and four fetch paths multiplied the discovery surface and
the failure modes — which file do you fetch for a party that is both a publisher
and an exchange? — without buying anything. A single document with
role-conditional fields means one fetch, one cache entry, one schema to evolve.
Verifiers, which had their own file, fold into whichever role their operating
domain holds; there is no separate verifier role.

## Inline keys instead of key-URI pointers

Relatedly, keys moved from a `keys_uri` / `jwks_uri` pointer pattern to inline
RFC 7517 JWK objects (`WellKnownManifest.public_keys`) carrying explicit
`not_before` / `not_after` bounds, with an optional `invalidation_url` for
emergency revocation. Inlining removes a second network fetch from every
verification path, and a second thing that can go stale or 404. The time bounds
let a verifier reason about key validity entirely from the one document it
already fetched, while the separate, short-TTL invalidation list keeps emergency
revocation fast without making the manifest itself uncacheable.

## Registration is a manifest block, and terms versioning sits outside it

An earlier revision published the registration contract as one flat manifest
field, `registration_schema`: a JSON Schema for the `registration_data` an agent
sends to `Register`, where publishing the field *was* the switch that turned
enforcement on. That much survives unchanged. What changed is the shape around
it. Registration turned out to have more than one publishable facet — the schema
describes the API mode, and a later web mode needs to publish a URL to a page
where a human completes the steps an API call cannot carry (explicit terms
confirmation, identity checks, manual review). Two flat siblings on a manifest
that already carries thirty fields give a reader no signal that they are one
subject, so the schema moved inside an `account_registration` block whose second
field number is reserved for that future mode. The precedence rule was fixed at
the same time, while only one mode existed and the answer was still cheap: an
Exchange publishing `data_schema` MUST accept registration through the API, and a
registration URL is an additional option an agent may offer its user, never a
replacement. Deciding that later would have meant breaking whichever
interpretation agents had already settled on.

Terms versioning deliberately did NOT go into that block. `terms_uri` names a
document whose content changes, so after the first revision every earlier
registration points at text that no longer says what was agreed — a dispute can
then be answered only with a timestamp. `terms_digest` pins the document, the
registration echoes it, and the request signature covers the echo, which makes
the acceptance a durable record rather than a pointer. Putting it inside
`account_registration` would have coupled "I enforce a schema" to "I version my
terms": an Exchange with pass-through registration publishes no block at all, and
it still needs to pin which terms it is serving. The two decisions are
independent, so the fields are too.

## The registration schema is a narrowed dialect, and the caps are on the wire

A published `data_schema` is the only part of the manifest a consumer both reads
out of a third party's document and then EXECUTES. A JSON Schema is a small
program: it resolves references, it compiles regexes, and it recurses. Reading one
from a party you have not authenticated — which is exactly what a client doing a
registration pre-check does, since the fetch precedes any signature — puts an
attacker-authored program on the critical path of a service. The rules that
followed all come from that one observation.

The reference rule and the size cap were there from the start. Two things were
not, and both were discovered the same way: by asking what a SECOND implementation
would do with the same document.

The first is that "a consumer SHOULD bound validation time and recursion depth"
does not bound anything. It reads like a rule and behaves like a suggestion,
because the number is left to whoever implements it — and this schema is validated
at BOTH ends of one registration. The Exchange enforces it; the client pre-checks
against it before signing. Two privately chosen depth limits mean a schema one
side compiles and the other refuses, so a payload passes the pre-check and is
rejected at the Exchange, or worse passes the Exchange having never been checked.
The limit had to become a number in the contract for the same reason the domain
pattern did: one value space with two contracts is the state that produces the
bugs.

What the first attempt got wrong is WHICH quantity to bound. It capped the document
— 16KB and 32 nested containers — and those bound nothing about the work of checking
a payload against it. `anyOf` branches multiply along a reference chain, so a
1,675-byte schema five containers deep, a tenth of the size cap and a sixth of the
depth cap, measured 16.7 million evaluations and took twenty-seven seconds against a
two-member payload. The bound that matters is a static count of evaluations, and it
is now 10000 — about fifteen milliseconds, several hundred times what a schema
describing a business entity needs. Counting it requires following every reference to
its target, which is how the same walk also decides two questions the three libraries
had been answering three different ways: whether a reference cycle is present, and
whether a same-document reference resolves at all. `{"$ref":"#"}` is twelve bytes and
used to crash two of the three ports out of an API documented as returning a verdict
rather than throwing.

A related correction, because it generalises: a bound belongs on the phase whose cost
it models. The agreed design called for a *compile* timeout. Compilation turned out to
be one to seventy milliseconds in every shape anyone could construct, while validation
was the expensive phase — so the timeout as specified would have caught nothing. It is
kept anyway, on the language whose runtime can actually preempt, because a phase left
unbounded on the grounds that a different phase's bound is tighter today is not
bounded; but the control that does the work is the static count.

The second is `pattern`, and it is the more interesting failure. Draft 2020-12
says patterns are ECMA-262. The engines real implementations run are not ECMA-262:
Go's RE2, JavaScript's RegExp and Python's `re` intersect on considerably less than
any one of them accepts, and the gap runs in both directions. The direction
everyone thinks of is RE2 refusing lookaround, atomic groups and backreferences —
loud, visible, and merely annoying, since one implementation errors while the
others work. The direction that matters is the quiet one: inline flags, Unicode
property classes, text anchors and POSIX bracket names are accepted by one engine
and either refused or read DIFFERENTLY by another. `[[:alpha:]]` is a character
class to RE2 and the literal characters `:alph` to JavaScript. Both compile. Both
report success. They then disagree about which registrations are valid, with
nothing logged and no error to catch — a conformance divergence that no test suite
finds because neither side ever fails.

So the admitted alphabet is the intersection, stated as syntactic rules a lexical
scan can apply identically in three languages.

The first version of that rule made a mistake worth recording, because it is the
mistake the whole section is about. It treated one rule as the answer to two
different problems. Constructs one engine cannot PARSE and constructs every engine
parses and then READS differently are both divergences, but they need opposite
remedies: the first can only be refused, while refusing the second would have gutted
the feature, because the second is `$`, `\d` and `\w`. Those appear in nearly every
real pattern, and the shipped rule left them in — so `^[A-Z]{2}[0-9]+$`, the example
the contract itself gives, accepted `"DE12345\n"` under one implementation and refused
it under two, silently. The rule now refuses only what cannot be reconciled, and the
implementation whose engine differs corrects it: ASCII character classes, and `$`
anchored at the end of the text and nowhere else. `\s` is the exception that proves
the split — there is no single set to correct TO, since RE2, Python and ECMA-262 each
read it as a different collection of characters, so it joins the refused list and an
author writes the class out.

The second mistake was the claim that excluding lookaround and backreferences means
catastrophic backtracking "falls out of the same rule". It does not. `(a+)+` needs
neither construct, and every classic form was admitted by the shipped alphabet. That
is now its own rule — a quantified group's body may not itself repeat or branch — and
it has to be a PUBLISHING rule rather than a runtime timeout, which is the part worth
remembering: a regex spin holds CPython's interpreter and blocks Node's event loop, so
a consumer cannot interrupt one it has already started. A timer would have been a
control that cannot preempt the work it names.

And the deepest lesson is about the corpus rather than the rules. Three dimensions and
141 cases all passed while the three implementations disagreed about which payloads a
published schema accepts, because every dimension recorded which schemas were
ADMITTED and none recorded what an admitted schema then MATCHED. A rule that is only
asserted is a rule nobody checks; the fourth dimension exists so the alphabet can be
maintained empirically rather than by argument.

`format`, `contentEncoding` and `contentMediaType` are pinned as annotations by
the same argument at a smaller scale. Every library defaults differently on
whether to assert them, so a schema whose verdict depends on which library read it
has no single answer — and "depends on the library" is not a semantics a contract
can publish.

One consequence worth stating because it is easy to get backwards. A client that
finds a schema breaking any of these rules SKIPS its pre-check and sends anyway;
it does not refuse locally. The Exchange's enforcement is the deciding check, and
a client that vetoed here would block payloads the Exchange would have accepted —
turning a safety rule about reading a hostile document into a denial of service
against its own user. An Exchange applying the same rules to its OWN configured
schema reads a failure the opposite way: nothing third-party is involved, so it is
a misconfigured deployment, and the one outcome it must not reach is advertising a
schema it is not itself enforcing. Same rules, same code, opposite response — which
is why the SDK face returns a verdict naming WHICH rule broke rather than a bare
error.

A second review then found the same lesson twice more, in places the fourth dimension
did not reach.

The alphabet had been written as a list of the escapes the engines disagree about, and
that list can never be finished. Two rounds of review found new members by trying them
— `\B`, `\cA`, `\a`, `\012`, `\x{41}`, `\uHHHH`, the identity escapes — and `\B` was the
dangerous kind, since all three engines compile it and then disagree about the empty
string. Enumerating the bad set is the wrong side of the rule when the bad set is
open-ended, which is a judgement this repo had already made twice elsewhere: the SSRF
guard allowlists URL schemes because "a scheme denylist is unwinnable", and the bare-host
check compares against a parsed host rather than "a blocklist of the separators anyone
thought to name". The pattern alphabet is now an allowlist for the same reason, and it
was derived by running every ASCII escape through all three engines in three positions
rather than by reasoning about which ones ought to be portable. JSON Schema's own
interoperability section recommends a subset in the same spirit, and a narrower one.

The correction for a divergence has to reach every place a regex is compiled, not the
one that is obvious. Overriding the `pattern` KEYWORD left `patternProperties` — whose
regexes are KEYS — and the matched-key scans behind `additionalProperties` and
`unevaluatedProperties` all using the library's defaults, so a property name that was a
non-ASCII digit matched `^\d+$` in one implementation and not the other two. The fix
moves the correction into the schema SOURCE, once, where every call site reads it,
including any a future release of the library adds.

And the rules sit on top of a byte decode that nobody had specified. Three
implementations gave three different answers to a byte order mark, to invalid UTF-8 and
to `NaN`, not because they disagreed about JSON Schema but because their JSON decoders
differ: two strip a leading mark and one does not, one repairs ill-formed bytes to
U+FFFD and enforces a document nobody published, and one accepts JavaScript's numeric
literals. RFC 8259 permits either mark policy, which is exactly why the contract has to
pick one — the size cap is defined over the bytes as served, and a parser that silently
drops three of them is measuring something else.

The same decode also decided a question nobody had noticed was a question: what "this
Exchange publishes no schema" looks like in bytes. That gate runs before every rule and
turns enforcement OFF, and each language had been asking its own runtime what "blank"
means — three different sets, and the JavaScript one strips a byte order mark before
answering, so a mark followed by a space read as "nothing published" and never reached
the rule that refuses a mark. An empty configuration file saved by an editor that adds
one would have left that Exchange enforcing nothing, quietly, while the other two called
the same bytes malformed. Emptiness is now RFC 8259's four whitespace bytes, tested over
the bytes rather than a decoded string. The general shape is the one this feature keeps
running into: a rule is only as portable as the layer underneath it, and "ask the
platform" is not a specification.

The brace rules arrived last and are the clearest statement of the pattern. `a{,5}` and a
lone `}` had been admitted the whole time, and each was found the same way the bracket
rules were — by asking a second engine what it thought the pattern meant, rather than by
reading the rule. What makes them worth recording is that the two failure modes sit side
by side in one construct: the missing first bound is SILENT, with RE2 reading five literal
characters and Python reading a repeat, while the unmatched brace is LOUD, refused by
ECMA-262 under the `u` flag and accepted by the other two. A rule set that only closed the
loud half would have looked complete and left the dangerous half open.

Three enforcement lessons came with them, none of which changed a rule. Correcting a
divergence has to happen where every consumer of the value reads it: the TypeScript port's
dot correction is written into the schema source for the same reason Python's `$` rewrite
is, because a matcher-level fix reaches one call site and a source-level fix reaches all of
them. A port can diverge through a standard-library detail rather than a design decision —
`String.split`'s second argument caps the result and discards the remainder where Go and
Python keep it, which is why one scanner alone admitted `a{1,2,3}`. And a bound stated over
one axis does not constrain another: the schema depth cap counts containers, so a flat
reference chain of five hundred links is three containers deep and passed it, then
exhausted the interpreter stack of the one port whose walk was recursive.

That fix was one stage short. Making the cost walk iterative stopped the SDK's own walk
from recursing, and the library it then hands an accepted schema to still resolved the
chain recursively — so the same document compiled and crashed on the first payload. The
lesson is about where a bound belongs: an implementation can only make its own walk
iterative, and a rule the contract does not state has to be survived independently by
every library any implementation chooses. Chain length is now a number beside the depth
and work caps, and it is a THIRD axis rather than a refinement of either — a flat chain is
shallow and cheap, which is exactly why the other two never saw it.

The payload had the same gap on a different axis, and it surfaced in the most useful way
possible: a test passed locally and failed in CI. Not flakiness — the two ran different
releases of the same language, and the verdict for a deeply nested payload was a function
of which one. Canonicalising walks the payload recursively; 3.11 spends C stack on
Python-to-Python calls and 3.12 does not, so the same nominal recursion limit admitted
roughly twice the nesting, while the other two SDKs accepted every depth tried. It had
been recorded as "this port is deliberately stricter", which was the wrong reading of the
evidence — it was not stricter, it was undetermined.

Two lessons worth keeping. A bound that comes from a runtime's remaining stack is not a
bound, because nothing states it and every environment answers differently; and the check
that enforces a depth bound must not itself recurse, or it fails on exactly the inputs it
exists to reject.

The last gap was the other side of the same coin. Every cap protected the schema, and
nothing protected the payload the schema is applied to — validation cost is the schema's
cost multiplied by the elements in the payload, so the multiplier was the unbounded
half. Bounding it turned out to be less about the number than about the unit. Every
other cap in the contract is over bytes somebody served; `registration_data` arrives as
a decoded `Struct` and is never served as bytes at all, so "16KB" is not a rule until an
encoding is named. The reference Exchange had already picked one privately — a sum of
key and rendered-value lengths, with numbers rendered in shortest-decimal form, under
which `1e300` weighs three hundred bytes and seven as JSON — which is precisely the kind
of quiet, defensible, incompatible choice this whole feature exists to remove. The
contract names RFC 8785 instead, because all three SDKs already compute it for signing
and because it fixes number formatting by specification rather than by whichever
renderer a language reaches for.

## Recipient addressing: a body field, not the signed request URL

Every addressed request carries `exchange`, the bare host of its intended
recipient, and a recipient rejects a request naming someone else. The obvious
objection is that the RFC 9421 request signature already covers `@target-uri`, so
the recipient is established without a body field. It is not. The signature proves the sender signed *the URL it dialled*, not that
the URL was the right one: the dial target is resolved from a fetched, cached
manifest, so a poisoned or stale resolution redirects the request while the
signature still verifies. The body field states whom the sender meant,
independently of that resolution, and the recipient rejects a request naming
someone else. On a verbatim-forwarded path the agent signs its `@target-uri`
against the final recipient's endpoint, not the Broker's, so the field is a
redundant cross-check there, same as on a direct hop. On the legs a Broker
authors itself (the discovery fan-out, a re-packaged transaction) the Broker
stamps the field as sender — the field is a statement by whoever signed the
request it rides in, never tamper-evidence against that party. For transactions
the binding audience statement is `Offer.exchange` inside the Exchange-signed
offer.

Cross-recipient replay is not this field's job. A recipient that reconstructs
`@target-uri` from its own configured identity rejects a replayed capture at
signature verification already. The body field backstops only a recipient that
rebuilds `@target-uri` from the arriving request, where a forged Host can make
a signature over another party's URL verify.

The value is a bare host and never an endpoint URL. An endpoint in the payload
would hand the caller the choice of where the next hop dials, which is the lever
the resolver exists to remove: the endpoint always comes from the recipient's own
`/.well-known/ramp.json`. Two messages are deliberately exempt. `DiscoveryRequest`
travels one direct hop and terminates at the Broker, which authors fresh
per-Exchange `ResourceQuery` messages rather than forwarding it — and the agent
could not name the recipients anyway, since choosing the fan-out set is the
Broker's job. `TransactionRequest` needs no top-level field because its audience
statement already exists per item: `Offer.exchange` is the execute-routing
target, signed by the issuing Exchange, and the receive rule is that every item's
offer names this Exchange. A redundant top-level copy would only add a
top-level-versus-items mismatch to police. That last exemption is why
`Offer.exchange` became presence-enforced rather than staying a plain unvalidated
string: an empty value is unroutable, and the swap-protection its signature is
supposed to provide is vacuous when the signed bytes carry no recipient at all.

## The audience match is exact; the endpoint rule is not

Two host comparisons sit a few sections apart in this document and answer
deliberately different questions, so they compare differently and neither should
be relaxed into the other.

The endpoint rule admits a **set**: a manifest may advertise its service on the
host that served the document or on a subdomain of that host. The question there
is which addresses one Exchange can be reached at, and an operator fronting
`exchange.example` from `api.exchange.example` is the ordinary case.

The audience check admits **one** value. An Exchange has exactly one identity —
the domain it stamps into the offers it issues — and a subdomain of it is a
different party, not another address for the same one. `eu.exchange.example` does
not name `exchange.example`. Widening this to the endpoint rule's shape would let
anyone who controls a subdomain claim to be the parent, which is precisely what
the check exists to refuse. The configured value is the identity domain and never
the host the process listens on; when those differ, taking the listening host
refuses every correctly addressed request.

What survives normalization is only spelling. Case folds, and a port of 443
written out is the same as leaving it off, because a schemeless domain reads as
https throughout the SDK. Port 80 does not fold — it is not that scheme's
default — and a padded `:0443` is refused for its shape before any comparison,
since the wire rule's port group is a real 1-65535 range rather than a digit
count.

That rule is carried in two places on purpose — the protovalidate pattern on the
contract's recipient-addressing fields, and an exported constant in each SDK so a
client can refuse a bad value before sending it. It is *not* on every field that
happens to hold a domain; several carry no rule, and whether they should is a
separate question from this one. Exporting the constant breaks the precedent set by
the money pattern, which mirrors a wire rule and stays private in all three
languages. The difference is who needs it: money's is an internal detail of
formatting a decimal, while this one is a protocol constant an implementer writes
their own validator against — and in TypeScript the export is structural, since the
parity test imports the constant to assert it against the shared vectors. It is not
exported for the conformance guard's sake; that guard reads the vectors file, and
the emitter that writes it sits inside the same package as the constant either way.
Its length bound of 260 is the `max_len` the contract carries on every one of those
fields; it is not derived from DNS's 253, and trying to reconstruct it from that
plus a port will not land on the same number.

## CoMP as an extension; attestations instead of quality scores

Two earlier couplings were undone. The core protocol no longer imports IAB CoMP;
CoMP's Package/Function objects live in a `ramp-comp-v1` extension profile, and
IAB metadata rides optionally in `ext`. Tying every RAMP message to the full CoMP
object graph forced implementers who needed only pricing and transactions to
carry a large ad-tech schema; making it an extension keeps the core small and
lets domain semantics layer in through profiles (news, academic, legal, pharma,
medical imaging, C2PA). Separately, a free-form `ResourceQuality` score was
replaced by signed `ResourceAttestation` claims. "Quality" as an unsigned number
invited gaming and meant little across exchanges, whereas a cryptographically
signed claim from a named verifier is verifiable, attributable, and disputable
through the same dispute chain as the rest of the protocol.

## Universal Licensing Core

Licensing collapsed from several parallel, partly-overlapping shapes into one
`LicenseTerm` that carries `License`, `Restriction`, `Quota`, `Obligation`, and
`Pricing`, and appears with the *same shape* at both ends of the protocol —
`ResourceEntry.terms` at ingestion and `Offer.terms` at emission. A resource
carries zero or more terms; each term is one self-contained commercial/access
arrangement, and discovery projects one offer per term. The earlier
`AccessRestrictions` type, the `Offer.restrictions` projection, and `revshare`
pricing were removed, and `PricingModel` was narrowed to the charging
*structure* (`FREE` / `PER_UNIT` / `FLAT`) with the open-ended metering basis
("per what") moved to the `Pricing.unit` vocabulary axis. One model at both ends
means the bytes a publisher pushes are the bytes the agent verifies under the
offer signature, with no lossy ingestion→emission transform to reconcile.

Two shaping decisions are deliberate and worth recording because their
alternatives are conspicuously absent:

- **The licensing core is uniformly closed — no `ext` seam anywhere, including
  `Pricing`.** `License` / `Restriction` / `Quota` / `Obligation` /
  `LicenseTerm` / `Pricing` have no `ext` / `ext_critical` fields. Licensing
  semantics are the part of the contract that must mean the same thing to every
  participant and survive disputes; an open extension seam there would let any
  party introduce terms others cannot evaluate, which is exactly the ambiguity a
  license is supposed to remove. `Pricing` briefly carried an `ext` Struct
  (inherited from the CoMP/COSE lineage) and it was removed: an untyped blob in a
  signed, cross-exchange-comparable object quietly defeats the comparability that
  `unit_cost` exists to provide, and re-opens the unbounded-payload surface the
  vocabulary axes were closed to avoid. New dimensions — commercial or
  licensing — therefore arrive as typed fields or a vocabulary axis (where the
  value set is genuinely open), through a deliberate core change, not as
  per-deployment `ext` blobs. The general protocol `ext` / `ext_critical`
  mechanism still exists on transport/discovery messages (`Offer`, queries,
  disputes) where contextual, ignorable metadata is appropriate; it just has no
  place inside the license itself.

- **Restrictions are agent-selected, not Exchange-enforced.** Restrictions ride
  on the offer; the agent self-selects the term it can honour and bears
  compliance, with enforcement downstream at accept → report → reconcile. An
  Exchange or Broker MAY pre-filter offers as a convenience using attributes the
  requester volunteers, but that is advisory, never an enforcement gate. Putting
  the responsibility on the agent keeps the Exchange a neutral venue and avoids
  baking each requester's self-declared attributes into a trust boundary.

The full message-level specification and the membership/validation rules live in
ADR-014 (Universal Licensing Core) in the deployment repository; this entry
records only the wire-shaping reasoning.

## `license_id` → `billing_ref`: identity is the signature, not a field

> **Superseded — the renamed field was later removed outright:**
> after the Broker cost guard moved to the authenticated agent identity,
> nothing read `Requester.billing_ref`, and the caller-written
> label collided by name with the authoritative account handle minted at
> `Register`. The field was deleted outright — pre-v1, removed field numbers
> return to the free pool rather than being `reserved`. The reasoning below
> still stands — it is the same separation (identity = signature,
> entitlement = scopes/delegation) taken one step further: billing needs no
> request field at all.

`Requester` once carried a `license_id`, and the name implied that the value was
what entitled the requester to access — that holding the right `license_id`
granted the right resources. We renamed it `billing_ref` and recast it as an
opaque handle into the operator's billing system, nothing more. The rename
follows from a clean separation that the rest of the protocol already assumes:
*identity* is the RFC 9421 request signature (a verifier knows who is calling
because the request is signed by their key), and *entitlement* is scopes plus
delegation (what that identity is allowed to reach). A billing reference is
neither — it is a bookkeeping pointer the Exchange uses to attribute charges, and
treating it as an entitlement would have created a second, weaker authorization
path that a leaked or guessed string could ride. Calling the field `billing_ref`
makes its role unmistakable and removes the temptation to gate access on it.

## DenialReason consolidation

> **Superseded — the billing-reference reason later split in two:**
> `DENIAL_REASON_BILLING_REF_INACTIVE` became `DENIAL_REASON_ACCOUNT_INACTIVE`
> (same wire number), joined by `DENIAL_REASON_ACCOUNT_NOT_REGISTERED`. The
> collapse below was right about *why* and wrong about *what* it was collapsing.
> Its test — does splitting give the caller a different action to take? — still
> stands; for this pair the honest answer turned out to be yes. The two halves
> the old reason carried are not two causes of one condition, they are two states
> of the caller with two different remedies: "your account exists and is awaiting
> activation" means wait or contact the operator, while "you have no account
> here" means call `Register`, which an agent can do unattended and which the SDK
> is meant to automate. Neither value discloses anything about the Exchange's
> billing system; both describe the caller's own account state, which the caller
> may already query with `GetAccountStatus`. `TransactionDenial` gains an
> `exchange` field alongside them, because the agent hits this wall at execute
> rather than at register and otherwise would not know *where* to register
> without fetching a manifest to work it out — as a HINT the caller checks
> against a domain it already trusts, never as an instruction. The field rides in
> a response, and a response on a relayed path passed through an intermediary, so
> nothing signs it: that is the same unsigned addressing the request-side field
> exists to refuse, pointed the other way. An intermediary free to choose the
> value would be choosing where an unattended agent registers, and registering
> hands over an operator's business data and a signed acceptance of that
> Exchange's terms. `DELEGATION_EXPIRED` →
> `DENIAL_REASON_DELEGATION_INVALID`, recorded below, is untouched: expiry
> genuinely is one of several ways a single condition fails, and re-issuing for
> time alone would still not fix it.

The denial enum carried separate `INVALID_LICENSE` and `EXPIRED_LICENSE`
reasons, and a `DELEGATION_EXPIRED` reason. Once `license_id` became
`billing_ref`, a denial that turns on the billing handle is not about a license
being malformed or expired — it is about the billing reference not being live.
Both former reasons collapse into a single `DENIAL_REASON_BILLING_REF_INACTIVE`:
from the requester's side the remedy is the same (their billing relationship is
not currently usable), and splitting the cause leaked the Exchange's internal
billing state without giving the caller a different action to take. Separately,
`DELEGATION_EXPIRED` was broadened to `DENIAL_REASON_DELEGATION_INVALID`, because
expiry is only one of several ways a delegation token can fail to authorize
(revoked, malformed, holder-binding mismatch, scope too narrow), and a single
reason avoids implying that re-issuing for time alone will fix it. The enum is
contiguous, with no gaps or reused numbers left by the removals.

## Delegation-claims profile: opaque token, bound holder

Delegation tokens stay opaque on the wire — RAMP does not parse or re-encode the
token, and `token_format` only names which verifier to run. But leaving the
*meaning* of a token entirely to each issuer made delegations non-portable: an
Exchange could verify a signature without agreeing on what the contained claims
asserted. We added a small registered claim/fact vocabulary that maps the same
named concepts across both supported formats (JWT registered claims ↔ Biscuit
facts), so a delegation expresses scope, expiry, and spend caps in terms every
RAMP verifier understands regardless of token format. Everything in the
vocabulary is optional with one exception: the subject/holder binding is
mandatory. The key that signs the RFC 9421 request MUST equal the holder key
named in the token. That single requirement is what stops a leaked token from
being bearer-usable — possession alone proves nothing, because the thief cannot
produce a request signature under the bound key. The vocabulary is
vendor-extensible through a `vendor:` namespace for issuer-specific facts, while
`ramp_`-prefixed names are reserved for future registered claims so a vendor
extension can never collide with one. Constraints are fail-closed by default: an
unrecognized or unverifiable binding constraint denies the request rather than
being skipped, unless the constraint is explicitly marked advisory — the same
binding-by-default posture the licensing restrictions take.

## Biscuit v3; JWT verification deferred

> **Superseded by "JWT (holder-of-key) is the default delegation token; Biscuit
> is optional" below.** This section records the earlier decision (Biscuit v3 as
> the v1 conformance format, JWT verification deferred). It was later reversed:
> JWT holder-of-key is now the default and Biscuit v3 is the optional profile.
> Retained for history; see the later section for the current model.

At the time of this (now-reversed) decision, the default delegation
`token_format` was moved from `biscuit-v2` to `"biscuit-v3"`, tracking the
Biscuit specification's own v3 revision, and Biscuit v3 was the format RAMP
implementations were expected to verify at v1. JWT was wire-permitted —
`token_format` accepted it and the claim vocabulary mapped onto JWT registered
claims — but its full verification path (proof-of-possession via `cnf`/DPoP, and
OIDC issuer discovery through to JWKS fetch) was deferred past v1. (This was
later reversed: see the current model below — **JWT holder-of-key is the
default**, and `biscuit-v3` is the optional alternative profile, never the
default.)

## One normative scope-matching algorithm

Scopes appear in two places — on the requester/delegation side (what an actor may
reach) and on `LicenseTerm.scopes` (what a term covers) — and earlier drafts left
the matching semantics implicit, which invited each implementation to choose its
own prefix or glob rules. v1 fixes one normative algorithm used identically
everywhere. A scope is segment-wise, `":"`-separated. A grant covers a
requirement only if, segment by segment, each granted segment either equals the
required segment or is `"*"`; a terminal `"*"` matches all remaining required
segments. There is no implicit prefix match — `a:b` does not cover `a:b:c` unless
it ends in `*` — and a grant narrower than the requirement never covers it.
Pinning the algorithm protocol-wide means a requester's scopes and a term's
scopes are compared by the same rule, so an actor either provably covers a term
or provably does not, with no venue-specific interpretation in between. The
Biscuit Datalog authorizer is treated as one conformant implementation of this
algorithm, not a separate semantics: it MUST produce identical results to the
normative rule.

## Revenue share stays off-protocol

CoMP's `License` carries a `revshare` rate next to `price`, and RAMP's
`PricingModel` was reduced to three charging structures (`FREE`, `PER_UNIT`,
`FLAT`), so the conspicuous question is whether RAMP should add a
`REVENUE_SHARE` model for parity. It does not, and the asymmetry is intentional.
A `PricingModel` is the structure an Exchange can quote, sign, and compare at
transaction time, each with a concrete `unit_cost`. A revenue share has no such
price: the rate and its reconciliation are an agreement struck off-protocol
between agent and publisher. Modelling it as an enum value would be either a
bare label with no rate (the agent still has to go ask "what share?") or, if a
rate field were added, would pull the commercial terms of that off-protocol
agreement into the signed, cross-exchange-comparable `Pricing` — the very thing
closing `Pricing` this cycle was meant to prevent, since it destroys price
comparability and asks the protocol to carry terms it never enforces.

The arrangement is already expressible with existing primitives, and identically
to a subscription: a `Pricing{model: FREE}` term gated by an agreement scope
(e.g. `revshare:publisher-x`) plus a `ReportingObligation`. The agent that
signed the deal holds a delegation carrying the matching scope, accesses at zero
marginal cost, and reports usage; revenue is settled off-protocol from those
reports. "Pay per crawl or take the revenue-share deal" is then just two
`LicenseTerm`s on one resource, and the agent self-selects. CoMP parity is kept
by mapping rather than duplication: a CoMP `revshare` rate rides through verbatim
in the `ramp-comp-v1` ext (`comp.license[].revshare`), full fidelity for
CoMP-aware parties and ignored by everyone else, while RAMP core stays
minimal and its signed offers stay price-comparable.

## JWT (holder-of-key) is the default delegation token; Biscuit is optional

> **Biscuit removed pre-v1; superseded by JWT.** This section records the
> transition from Biscuit-default to JWT-default. The optional `biscuit-v3`
> profile it leaves in place was itself dropped before v1 shipped: JWT is now the
> sole delegation `token_format`, and the entitlement *mechanism* (a
> holder-bound capability token on a covered header) is unchanged — only the
> Biscuit format is gone. Read the "still optional" language below as historical.

The delegation token started as a Biscuit (`token_format` defaulted to
`"biscuit-v3"`), chosen for offline attenuation. Modelling the holder-binding
guarantee end to end surfaced that the property RAMP actually depends on — "a
leaked token is not bearer-usable" — is proof-of-possession, not anything
specific to Biscuit: it is the request-signing key matching a key named in the
token, verified offline. A chain of `cnf`-bound JWTs delivers exactly that — the
authority JWT (issuer-signed) names the principal's key in `cnf`; the principal
issues a child JWT naming the agent's key and narrowing scope; the agent proves
possession with its RFC 9421 request signature; the verifier walks the chain
offline under the issuer's key alone (intermediate keys ride in the JOSE header
`jwk`). The chain-linkage invariant (each token signed by the key its parent
named) gives the same theft- and escalation-resistance as Biscuit's block chain.

What Biscuit adds beyond this — in-token Datalog and deep in-place attenuation by
mutually-distrusting intermediaries — RAMP does not use: the check set is fixed
(scope coverage, expiry, caps, holder binding) and delegation chains are shallow.
So `token_format` now defaults to `"jwt"`, and JWT is the one delegation
technology a conformant implementation must support. `"biscuit-v3"` stays a
permitted optional profile for deployments that genuinely want deep offline
attenuation. The win is adoption: JWT is ubiquitous, so RAMP asks implementers to
take on no genuinely new token technology by default.

## Failure as a typed contract: `ErrorDetail`, not strings

The success side of the protocol was a single validated contract — typed
messages, protovalidate CEL at the boundary — while the failure side was not. The
same failure was named in incompatible ways across implementations: a hand-rolled
Go `Kind` enum in the Exchange (with a seven-mode entitlement family that all
collapsed to `UNAUTHENTICATED` on the wire, distinguishable only by a server-side
tag), a separate `Kind` enum in the Broker, free-text reason strings on the
catalog path, a database denial enum whose values did not match the proto's own
`DenialReason`, and a lowercase token union in the edge worker. A client could
not read a failure as one validated, machine-readable value; the reason for a
failure was expressed differently in Go, TypeScript, and Python, and the error
shapes lived in code rather than in the contract.

We made failure a single contract. The transport carries a coarse canonical code
(gRPC / Connect `Code`) as the error *class*; a typed `ErrorDetail` message,
attached to the transport error's details the same way protovalidate attaches its
violations, carries the precise machine-readable *reason* (a typed enum) plus
structured context. Clients branch on the typed reason, never on a human string.
The per-domain reason enums (`TransactionDenial` reusing `DenialReason`,
`CatalogRejection`, `RegistrationFailure`, `DisputeFailure`,
`DomainVerificationFailure`, `RetrievalAuthFailure`, `UsageReportRejection`) are
the single source of truth that the hand-rolled vocabularies collapse onto: the
database stores the proto reason, the per-service Go error types shrink to mapping
a domain failure to a transport code only, and the edge token union becomes a
generated enum.

We chose closed, typed enums over the open `reason` string of
`google.rpc.ErrorInfo`. Google uses a string because its API surface is enormous
and federated; ours is a handful of RPCs we fully control, and the entire goal is
compile-time conformance across Go, TypeScript, and Python — which a closed enum
delivers and a string would surrender. `ErrorDetail` still carries an
ErrorInfo-compatible `domain` + `metadata` for generic tooling, but the
authoritative reason is the enum. We kept the wrapper (`ErrorDetail` with a
`oneof`) rather than attaching bare detail messages to the transport error,
because one carrier message means uniform client code: there is exactly one type
to look for.

## A failed action is not a success body

The corollary decision is where a failure lives. The rule is the gRPC / AIP-193
one: a method that could not perform the requested *action* returns a non-OK code
plus an `ErrorDetail`; a *query* that ran successfully returns its answer in the
body, and "no results" is a successful answer, not an error. So discovery keeps
its in-body `OfferGroup.absence_reason` (the query succeeded; there were simply no
offers), and a denied *single* transaction, a rejected usage report, a refused
dispute filing, and a failed domain verification all became transport errors
carrying the typed reason — the in-body `bool accepted` / `verified` flags and
`rejection_reason` / `failure_reason` strings were removed. Batch transactions are
the deliberate exception: a batch is a successful call whose per-item
`TransactionResultItem` may carry a denial reason in-body, exactly like discovery
absence, because the partial results *are* the successful answer. The effect is
that success bodies now carry only the payload-when-it-worked.

## One response envelope; correlation by header

With the failure fields gone, the response messages were standardized. Every RPC
request and response now carries `ver` at field 1 — version belongs on every
message, consistently positioned — and the external-contract messages all carry
`ext` / `ext_critical` so any of them is forward-extensible. This includes the
resource-bearing catalog messages `PushResourcesRequest`/`PushResourcesResponse`:
a publisher pushes protocol-specific extension fields (e.g. CoMP members not
already projected from the licensing data) through `ext`/`ext_critical` so they
surface on the resulting offer. The purely-administrative catalog messages
(`RemoveResources*`, `RefreshCatalog*`) carry `ver` only — they move no resource
payload, so extension slots there would be noise.

Correlation, by contrast, was removed from the proto entirely. Earlier drafts
carried a `request_id` ("originating RAMP request id, for traceability") on
several requests and echoed it on responses — but it was dead weight: the
implementations never read or wrote it. Correlation already flows the way
signatures do, over the transport — an `X-Request-ID` header, minted or
propagated by shared middleware in the broker, exchange, and edge, and bound to a
request-scoped logger. By the same reasoning that moved signatures to RFC 9421 (a
value the proxies, edge functions, and tracing systems read without parsing
protobuf belongs on the transport), a correlation id has no place in the message
body. So every `request_id` field was deleted; per-hop and cross-system
correlation ride on `X-Request-ID` — and, when distributed tracing is added, the
W3C Trace Context `traceparent` / `tracestate` headers, which are the ecosystem
standard rather than anything RAMP would hand-roll. The proto keeps only the
identifiers that are *acted on* or *persisted*: the settlement and evidence keys
(`transaction_id`, `billing_id`, `report_id`, `dispute_id`) the Exchange assigns
and the reconciliation chain joins on.

## Idempotency is an explicit `idempotency_key`, not an overloaded `id`

Idempotency is the mirror image of correlation, and the contrast is the point. A
correlation id is ephemeral observability and lives in a header; an idempotency
key is persisted, settlement-bound state the server *acts on* — the Exchange
dedupes on it, stores it under a `UNIQUE` constraint, and threads it into the
billing adapter so a replayed request cannot double-charge. By the rule that
governs the whole wire format — what must outlive the HTTP exchange and survive a
dispute stays a typed field — the idempotency key belongs in the message body,
not a header. (This is where RAMP diverges from Stripe's header-based key: RAMP's
key is part of the signed, persisted, reconciled record, not a transport hint.)

The mutating requests had been carrying this as a generically-named `id` — with
`TransactionRequest.id` the only one a server actually deduped on, and
`UsageReport.id` an unwired intention. We renamed it to `idempotency_key` and made
it required on the state-mutating RPCs (`ExecuteTransaction`, `ReportUsage`,
`DisputeTransaction`), so the contract names the guarantee for what it is: the
server MUST return the original result on replay rather than re-executing. The
request needs no separate own-id, because the durable identity of what it creates
is the Exchange-assigned id in the response (`transaction_id`, `report_id`,
`dispute_id`). Queries take no key — neither `DiscoverResources` nor the Broker's
`Resolve`, which is pure discovery (it returns offers, executes no transaction,
so retrying is naturally safe) — and the naturally-idempotent catalog
upsert/delete and onboarding calls are left out deliberately — a key there would
be ceremony, not a guarantee. The field is
declared in the contract ahead of full enforcement: the Exchange dedupes
`ExecuteTransaction` today, and the remaining RPCs adopt the same check as the
implementation catches up to the contract — the proto leads, the services follow.

## Docs are rendered from the proto descriptor, not hand-written or regex-parsed

The documentation site derives everything it says about the contract from the
**compiler's descriptor**, in one TypeScript pipeline — no hand-typed tables, no
`.proto` text parsing, no reimplemented utilities.

**Why the descriptor.** Protobuf is self-describing: `buf build -o gen/descriptor.binpb`
emits a `FileDescriptorSet` — the schema as data — carrying every message, field,
enum, service, the custom options (`buf.validate` CEL, `(ramp.v1.vocab)`), and, with
source info, the comments (`SourceCodeInfo`). It is the same artifact every code
generator consumes, and it is complete and language-neutral. Crucially it is NOT the
generated `gen/ts` runtime (which lacks protovalidate and strips comments) — we read
the descriptor as data via `@bufbuild/protobuf` as a codec, so `gen/ts`'s
incompleteness never enters the docs pipeline.

**The pipeline.**
- `gen/descriptor.binpb` is a committed, drift-gated generated artifact (Amplify reads
  the file; no `buf` at docs-build time).
- One TS module reads it (`@bufbuild/protobuf`) and exposes enums/values with comments
  (path-matched from `SourceCodeInfo`) and the vocab options.
- A remark plugin injects enum/vocab tables as **mdast** and autolinks proto-symbol
  references across prose *and* the generated table cells in a single pass, using
  `github-slugger` (exactly Starlight's heading-id slugger) for anchors.
  `starlight-links-validator` validates the result. Rendering and linking are one
  pipeline, so a symbol named in a proto comment is rendered AND linked automatically.

**Descriptions live in the proto.** An enum value's description is its proto comment —
the single source — rendered to the table. To change a description, edit the proto.

**Superseded approach (removed).** The earlier Go tooling — `cmd/symbolsjson`
(descriptor walk + regex enum-comment parse + a hand-rolled `slugify`) and
`cmd/vocabjson` (emitting a vocab JSON view from `gen/go/vocab`) — was a wrong-tradeoff
detour: it optimized for "Go-only, reuse the vocab Go packages" and so reimplemented a
slugger that already exists (`github-slugger`), parsed a compiled format with regex
instead of reading the descriptor, and rendered tables as opaque Astro components the
autolink pass could not see into. All of it is deleted. `protoc-gen-rampvocab` and
`gen/go/vocab` stay — they are a real Go-SDK surface the conformance suite uses
(`pricingunits.IsRegistered`).

## A covered header the peer never receives is not bound

The RFC 9421 covered set is fixed and unconditional: `@method`, `@target-uri`,
`content-digest`, `authorization` and `signature-agent` are bound into the signature base
whether or not they carry a value. Binding the empty ones is deliberate — it stops a later
injection piggy-backing an existing signature.

What that implies about the WIRE took a working system to notice. A verifier rebuilds the
base from the request it received, so it reads the covered names off `signature-input` and
requires each to be present; the Go verifier reads them with `Values` rather than `Get`
precisely so an explicitly-empty header is distinguishable from an absent one, and the Go
signer sets the empty header so it reaches the wire. Both ports bound the same two values
and attached neither. Every signed RPC was refused with `header "authorization" missing
from request`, and fixing only that one surfaced the identical failure on
`signature-agent` — one mechanism with two instances.

The rule is stated now, in one sentence both ports implement: **a signing face emits every
covered header at exactly the value that entered the signature base, empty values
included.** Emitting the signed value rather than defaulting to empty is what makes it safe
to merge over a caller's own headers — the value is already in the base, so restating it
cannot overwrite a real `Authorization` with an empty one.

The durable part is not the dropped header; it is what the gates were measuring. Every
corpus pinned what was **signed** — the base string, the parameters, the resulting
signature — and nothing pinned what was **sent**. All three languages agreed byte-for-byte
on the signature while two of them could not complete a single call, so every parity gate
passed throughout. This is the same shape as the corpus rows that named a file and read
none of its columns: a gate that measures the half of the claim that was never in doubt.

`sign-request-vectors.json` gained an `emitted_headers` column for it — what the signer
puts on a bare request, captured from the oracle and compared by all three as a whole map
rather than key by key. Membership assertions are what let two missing headers ship
invisibly. The corpus already carried both input shapes, including the no-directory signer
with an empty `signature_agent`, so the static-bootstrap instance is pinned by the same
column rather than by a second case someone has to remember, and an append/relay case
extends it to the forwarding leg.

**Then the rule was implemented with the wrong key, and the same blind spot caught it a
second time.** Header names are case-insensitive on the wire; a JavaScript object's keys
are not. The TypeScript signer emitted `Signature-Agent` from the exported constant while
reading incoming headers case-insensitively, so a caller who spelled it `signature-agent`
— which is every Node server, every WHATWG `Headers`, and HTTP/2 by definition — had their
key survive the merge BESIDE the signed one. Two field lines reached the wire under one
covered name; the verifier joins repeated values with `", "` before rebuilding the base, so
a correct signature was refused. The relay flow that worked before the fix stopped working
after it.

Two things follow, and both are about gates rather than headers. **A face that reads one
way and writes another will eventually disagree with itself** — the fix is the lowercase
key plus a merge that drops any incoming name colliding case-insensitively with a signed
one, so the write side agrees with `getHeader`. And **a gate must be able to express the
failure it exists to catch**: `emitted_headers` was a map of single strings built with
`Header.Get`, which cannot represent a duplicate at all, while the verifier it stands in for
reads `Values`. It records a list per name now. Every test in the repo had also passed the
one header spelling that cannot collide, so the whole suite was green over a broken relay —
the same shape as a corpus row that names a file and reads none of its columns.

**The rule binds the verify half too.** Both ports read the covered headers with a
default-to-empty (`headers.get("authorization", "")`), which collapses *absent* into
*empty* and accepts exactly the request Go refuses — the oracle reads them with `Values`
rather than `Get` precisely to tell the two apart. Defaulting there invents a value the
signer may never have bound. All four server-verify faces now refuse an absent covered
header and still accept a present-and-empty one, which is the distinction the empty
header exists to carry.

**Reading a header case-sensitively is the same defect one tier down.** The absent-header
guard first landed on three of the four faces, and it landed as a plain key test
(`"authorization" not in headers`). Both halves of that were wrong in the same way the
emit had been. A header bag whose keys are strings can hold `Authorization` and
`authorization` at once, where the wire has one field name spelled two ways — so the peer
DID send the header, under a spelling the reader never looked for. A guard that misses it
reports absent; a reader that misses it substitutes empty and rebuilds a base that
matches, accepting an unsigned bearer token sitting beside the signed empty one. That is
precisely the injection the covered set exists to prevent, and it was open on every face
before the fold landed.

The fix is a fold **and a join**, never a fold and a pick. Measured on the oracle, a
request carrying `authorization: ""` and `Authorization: Bearer …` resolves to
`", Bearer …"` — `http.Header.Values` returns both and RFC 9421 joins them with `", "`
before the base is rebuilt, so the covered value CHANGES and the signature fails. A port
that folds the case but returns the first match reads back the signer's empty value and
accepts the token next to it: the fold makes the bug harder to see without removing it.
Absent stays a distinct answer from either — zero field lines, not an empty one.

Both properties are pinned by Go-derived corpus rows rather than by prose, and the rows
are signed with EMPTY covered values on purpose. Omit a header whose signer bound a
non-empty value and the request is refused either way — a port that defaults the missing
header to `""` still reconstructs the wrong value, so the case cannot tell *refused
because absent* from *refused because the value differs*, and gates nothing. The first
attempt at these vectors made exactly that mistake and passed with the guard deleted.

**The last read to learn the rule was the oracle's own, and it was the most exposed.**
The entitlement-coverage gate — present-but-uncovered token, refuse — asked `Get`, the
first field line. Everything above applies to it, with one difference that inverts the
usual ranking: the ports need a header bag holding two differently-cased keys, which no
mainstream adapter produces, while Go needs only the header sent twice. That is ordinary
HTTP and no case trick at all. Measured on the oracle: `Add("")` then `Add("STOLEN")`
gives `Get()=""`, the gate never runs, and a capability token no signature committed to
is accepted. The signer half had the same shadow — `coveredFor` resolving the name with
`Get` leaves it UNCOVERED whenever an empty line precedes a real one, binding a value it
never committed to — so both sites moved, not just the gate.

Two lessons worth separating. A presence test is not exempt from how a header is
defined: "does the request carry this name" is answered by all of its field lines, not
by whichever one a map hands back first. And *parity with the oracle* is a rule about
where the answer comes from, not a licence to copy a hole — the port that had already
been fixed was the one diverging, and it was diverging by being right.

A negative vector cannot finish this. It separates a first-match reader from the join,
because both a last-match reader and the join refuse a tampered covered value — so a
port could resolve a covered name to its LAST field line and pass every rejection case
in the corpus. Only a POSITIVE case signed over two field lines, whose covered value
*is* the join, tells them apart: first-match and last-match each reconstruct a different
base and every hop fails. The same shape catches a case-sensitive reader, as a chain
whose bag is spelled the conventional way and which must still verify.

The signer's half cannot have a vector at all. The shared corpus records what a signer
EMITTED, and a row proving which covered set it CHOSE would still have to be replayed in
all three — but neither port can bind the entitlement header to begin with: both render a
fixed five-line base, so a name outside that list never reaches their signature base. A row
no port can consume is an orphan, and the corpus rule admits none. So this one is gated by a
Go internal test that signs over two field lines and asserts the emitted inner list names
the header. That is not a way around the tri-language rule; it is the honest answer for a
rule only the oracle can express today.

The chain corpus pins one thing more, which only a chain can express: **where** the
missing header is noticed. The oracle finds it while rebuilding a hop's base, which runs
after the hop budget and the structural chain are enforced — so an over-budget chain
still answers `hop_budget` and a reordered one still answers `broken_chain`, even with a
covered header removed. A port that tests for the header before those gates answers
`signature` to all three and silently diverges on two.

## SDK layering: a dial-free trust core, a vetted-client I/O tier

The three SDKs (`sdk/go`, `sdk/ts`, `sdk/python`) are split into a **pure trust
core** and a separate **I/O tier**, and the two obey opposite dependency rules. The
core — the RFC 9421 / 7638 crypto, JCS canonicalization, offer/acceptance verify, and
the transport-neutral `core` composition — imposes nothing beyond the platform
standard library and a small set of VETTED libraries, currently a crypto primitive, a
JCS/canonicalizer, and a JSON Schema engine (the registration-schema face, which is
pure computation over bytes and dials nothing). The list is closed by review rather
than by count: what the tier refuses is a DEPENDENCY THAT DIALS, not a dependency. It
takes no HTTP client and does not dial the network: `sdk/go/helpers`
never constructs an `http.Client`, `sdk/ts/core` imports neither `undici` nor a
framework, and `ramp_sdk.core` imports no `httpx`. The I/O tier is where a network fetch
lives, and there the rule inverts: it runs on a
**maintained HTTP client** (Go `net/http`, TS `undici`, Python `httpx`) rather than a
hand-rolled transport, because the client owns the response state machine (status,
redirects, 1xx, decompression) and the SDK should own only the SSRF check it injects
as a connection-level hook.

**The I/O tier is two trees per language, not one.** `sdk/{go,ts,python}/resolvers`
came first and carries the pre-auth fetches — well-known JWKS, WBA directory, `ramp.json`
endpoint, offer-key resolution. The client tree — `sdk/go/connect`, `sdk/ts/client`, and
`ramp_sdk/client` with `ramp_sdk/sync` as its blocking facade — is the second, and it is
IO-bearing for a different reason: it SENDS. Every leg it dials carries a credential, an
RFC 9421 signature or a proof of possession bound to one URL, which is why it refuses
redirects where the resolvers follow them under a cap, and why it splits its transport in
two — a plain one for the operator-configured home Exchange, an address-guarded one for
the legs whose host an offer named. The pure trees (`core`, `src`, the top-level
`ramp_sdk` modules) may import neither, and a structural guard in each language enforces
that: `sdk/ts/tests/resolvers-io-leaf.guard.test.ts`,
`sdk/python/tests/test_guards_resolvers_io_leaf.py`.

Worth stating here because this file is where it is stated. ADR-020, cited throughout this
repo for the L0/L1/L2 layering, lives in the reference implementation's repository rather
than this one, so a reader who has only this checkout has this document and nothing else.

The reasoning is a threat boundary, not an aesthetic one. The host a resolver fetches
is caller-supplied and reached **before** any signature is checked, so the fetch
surface is pre-auth-reachable network I/O — exactly the surface an attacker probes for
SSRF. Keeping every dial in one tier, behind one SSRF-guarded client, means the pure
verification code an edge worker or a broker links can never be tricked into dialing:
there is no client in it to trick. The split is enforced structurally by an **io-leaf
guard** in each SDK that fails the build if a core/pure file names a dialing surface
(`http.Client`, `net.Dial`, an `httpx`/`undici` import), so the maintained-client
dependency cannot leak back down into the trust core.

This is the resolution of an earlier terminology overload. The `core` package was once
described as "L2 CORE [that] must impose NOTHING … NO httpx", while the resolvers tier
— which legitimately *does* use `httpx`/`undici`/`net/http` — was *also* called "L2".
Read literally the two statements contradict; the fix is to name the split by kind
rather than by a single "L2" number: the **trust core** (pure, dependency-minimal, no
dial) and the **I/O resolvers tier** (vetted maintained client, SSRF-guarded) are
distinct tiers with opposite dependency policies, and "no httpx" is a property of the
core alone, never of the whole SDK above L1.

## The publisher's pre-check is the Exchange's check, lifted one tier down

A pushed entry passes two tiers at the Exchange. The wire tier is protovalidate: the
`ResourceEntry` envelope rules and the `LicenseTerm` structural and cross-field rules,
applied to the request exactly as received. The ingest tier runs afterwards, over the
canonicalised terms: restriction tokens are folded and alias-resolved to their
registered form, then a bare `Pricing.unit` or `Quota.metric` that is not a registered
token is rejected, while an unregistered restriction token and an `OBLIGATION_KIND_OTHER`
obligation without detail are accepted and reported in `PushResourcesResponse.warnings`.
The first tier was always in the contract. The second lived only inside the reference
Exchange, so a publisher learned what it would say by pushing and reading the refusal.

It moved into the L1 helpers, in all three languages, because it passes the inclusion
test on every count: the rules are protocol-defined (the token registry and, now, its
aliases are authored in the proto and generated into every SDK), each face is a pure
function over one message, and the code has more than one consumer — the Exchange at
ingest, a publisher pre-checking a feed, the reference catalog CLI. What did NOT move is
the Exchange's discovery-side term eligibility (which terms a requester's scopes cover):
that is a question the Exchange answers about a requester, not a check a publisher can
run before sending, and it stays where its state is.

The line between the tiers is where it is for a reason a CEL expression makes plain: a
rule that re-lists a vocabulary drifts from it, so membership cannot be a descriptor
rule. It is still reported to a publisher as a rule id, and those ids take the shape the
descriptor's CEL ids already have — the owning message in snake_case, then the rule
(`pricing.unit.registered`, `restriction.token.registered`). One namespace, and a
conformance guard reads the ids out of the committed corpus and holds them to it: every
id names a contract message, and none equals a CEL id.

The reject-versus-warn split is on the wire — `warnings[]` is a list of strings a
publisher reads — so the messages are pinned byte-for-byte across the three SDKs rather
than merely their shape. That is what lets an Exchange that imports the SDK emit the
same text a publisher's pre-check showed.

Folding is ASCII-only, and only RFC 8259's four whitespace bytes are trimmed. The reason
is the one the recipient-addressing rule records: several non-ASCII code points
lowercase or NFKC-fold INTO ASCII letters — U+212A KELVIN SIGN becomes "k" — so a port
that reached for its platform's Unicode lowercase would turn a homograph into a
registered token. A non-ASCII byte passes through a fold unchanged, a token padded with
a non-breaking space is not trimmed, and the corpus carries those inputs so the three
answers cannot drift on them.

The aliases had been a private Go map inside the Exchange, although the licensing core's
own vocabulary table had always listed them beside the tokens (`train-ai` is AIPREF's
spelling of `ai-train`, `generative-ai` the industry's spelling of `ai-input`), and the
user-type aliases had no record outside the code at all. They are now
`(ramp.v1.vocab_enum_alias)` entries on the enum values that carry the tokens, and the
vocabulary plugin emits an alias map and a canonical lookup per axis into every SDK — an
axis without aliases carries an empty map, so every axis has the same face. Codegen
refuses what the lookup could not honour: an alias that is itself a token, a canonical
that is not one, a duplicate, and a spelling that is not already trimmed and lowercase,
since the SDK folds before it looks up and any other spelling could never match. The
generated lookup does no folding of its own; which case an axis folds to is the SDK's
rule, implied by the case its registered tokens are authored in.

The composition order is the Exchange's, and it is not the friendly one. The wire tier
runs over the entry exactly as given; only then is a copy canonicalised for the ingest
tier. So a geography token spelled `" de "` is refused by the wire pattern — whitespace —
before any fold would have rescued it, and the SDK says so rather than quietly folding
first and reporting an entry the Exchange would refuse. Where the Exchange stops at the
first tier that fails, the SDK reports both, so a publisher fixes everything in one
round; that is the one deliberate difference. What the corpus's per-entry list pins is
narrower than "the composition", and the section below on language-local rule ids says
what it does pin, at three different strengths. The two JSON ports walk every message
reachable from an entry explicitly for the cross-field rules, because their composed
schemas attach per message and a top-level parse would never reach `terms[1].pricing`.

## A catalog client is its own constructor

The usage-report decision recorded above settled a rule that generalises: a client's
constructor takes its shape from where the address comes from. A report goes where a
signed offer says, so the report verb resolves its destination from the message and
takes no configured origin. A publisher pushing a catalog is the other case — it chose
the Exchange — so the origin is configuration and the leg runs on the plain signing
transport, the posture of the agent client's home Exchange rather than of its
offer-derived leg.

What it does not share with the home Exchange is the address itself, or the caller. An
Exchange advertises CatalogService at `WellKnownManifest.catalog_endpoint`, distinct
from the ExchangeService endpoint the agent dials, and the party pushing holds a
contributor key named by `caller_id`, never an agent key. Hanging the three catalog
verbs on the agent client would have carried every agent-only holder — the offer
Verifier, the requester, the delivery fetcher — into a client that uses none of them,
and pointed one of two roles at the wrong address. So the publisher role got a third
constructor, on the Broker's precedent, sharing the plumbing and nothing else. The
catalog messages carry no idempotency key, by the decision recorded under idempotency —
an upsert and a delete are naturally idempotent — and the client mints none; it stamps
`ver` when empty and refuses, before signing, a request that names no bare-domain
recipient, the same verdict a dispute with no `exchange` gets.

That refusal uses the SHAPE predicate, `IsBareDomain`, and not the routing one the
offer-derived legs use. The two are kept apart deliberately and the catalog leg is where
the difference bites: nothing dials this value — the address is configuration — so the
only question worth asking is whether the value is a form the contract admits, which is
the protovalidate pattern the field carries and the same rule the Exchange's own audience
check applies on arrival. The routing predicate is wider by design, because it answers
whether a value is safe to concatenate into a URL: an underscore, a trailing root dot and
a bracketed IPv6 literal are all usable hosts and none of them is a value `exchange` may
hold. Vetting with it signed and sent requests the recipient could only refuse — the
round trip this check exists to save. A port and a single-label host stay accepted, since
both are live in the deployment's own catalog and both are what the wire rule admits.

`catalog_endpoint` had carried no host binding while `endpoint` did. The predicate is the
same one, applied for the same reason: a publisher's push is a signed call to that
address, and a manifest naming an unrelated host would redirect it to a party the
signature never covered. The comment now states the MUST, the conformance guard that
holds `endpoint`'s comment to its clauses reads `catalog_endpoint`'s too, and absence
means the Exchange does not expose the service — a consumer does not fall back to
`endpoint`.

The envelope rules on `ResourceEntry` were checked against production data before their
strictness was chosen. `domain` reuses the shared bare-host rule, which admits a port and
a single-label host, because both are live in the reference deployment's catalog and
because the catalog URI is synthesised by concatenating `domain` and `path`: a value
carrying a scheme or a path would choose the URI rather than name the host. `path` is an
absolute URL path with no query or fragment delimiter and no whitespace or control byte,
for the same reason. `content_hash` is bounded but not format-checked, because a bare hex
digest and a `method:hexdigest` form both travel today and `hash_method` names the
algorithm. `terms` caps at 32, the limit the reference Exchange already enforced privately —
moved into the contract so every implementation refuses the same size. Moving it also
changed WHEN it is refused, and only that: an over-cap entry always refused the whole
submission, because a catalog push is all-or-nothing, so what a wire rule changes is that
the refusal happens at the boundary before any per-entry classification runs — which is
exactly why the rejection reason that named this cap is retired on that path.

One accounting decision belongs here because it is not visible from the code. The
parity allowlist is a shrink-only ratchet over documented divergences, and its only prior
growth was netted by a resolution in the same change. This work adds two rows of classes
the record already carries — a Go factory that folds into a Python constructor, and a
third Go-only Connect handler binding under the existing decision — with nothing left to
net against. The alternatives were to reclassify the ten existing factory-fold rows as
mappings, which re-opens a classification a review had verified, or to add unrelated
Python surface for the arithmetic, which is gaming. The baseline moved 14 to 16 as a
reviewed bump, and the gate now states the one growth it sanctions: a new Go symbol of an
already-recorded divergence class, arriving with that class's reason or anchor. Whether
the factory folds should be mappings at all is a separate question, left open on purpose.

## A bound belongs on the phase whose cost it models, and the catalog relearned it

The list caps on `ResourceEntry` and `LicenseTerm` were added to bound the work one push
can cost. They do not, and the comment that said they did was wrong for a reason worth
recording, because this contract has now met it twice.

protovalidate does not short-circuit. It walks every element it is handed and collects
every violation, and the cardinality rule is reported alongside the others rather than
instead of them. Measured on this contract: an entry carrying 100,000 terms costs 393ms
and allocates 100,001 violation objects — even though `terms` was already capped at 32,
and the cap fires. The list was fully traversed on its way to being refused. A cap of N
does not mean a validator handles at most N; it means a validator that has already handled
however many arrived will say so.

That is the same lesson the registration-schema work recorded above, in the same words: a
bound belongs on the phase whose cost it models, and the caps there bounded the document
rather than the work. So the caps here are kept and re-described for what they genuinely
control — how many terms one entry may carry, how many entries a push can store, and how
many paths a rejection has to name back — and the work is bounded where the work happens,
at the transport, by the maximum request size the recipient will read. The SDK's server
binding sets that cap on every handler and states the cost the default implies: a
full-cardinality push costs ~475ms to validate, and the worst conformant shape that still
fits under 4 MiB costs ~7.4s. Bounded, not small; an uncapped handler has no worst case at
all.

Three corrections arrived with the honest measurements, each a way a cost model can read as
tighter than it is. The published figure was ~1.6s, and it described the contract the author
intended rather than the one that shipped: with `Restriction.kind` open a term could carry
sixty-four distinct axes, and the real figure was an order of magnitude higher. A cost model
that assumes a bound the contract does not state is not a measurement of the contract. And
the transport cap bounds the decompressed message without bounding decompression: an
over-cap body is inflated to completion so the error can name its size, which is bounded
only by the RAW read — 4 MiB compressed is 4.32 GB inflated, ~850ms spent on a request that
is refused. A bound on a result is not a bound on the work that produced it, which is the
same lesson one layer further down.

They bound COUNTS and not bytes, which is worth saying plainly because the first
re-description overreached in the other direction. `Obligation.detail`, the `License`
strings and every `ResourceAttestation` member carry no length rule, so there is no
largest conformant entry and no largest conformant push — the transport cap can refuse a
conformant one. That is the intended trade rather than a gap: bytes are the recipient's
budget to set, and a deployment that must accept larger documents raises its own cap.

The third correction is the one that outlived the other two, because it says where the
argument above stops. Closing the axis was itself described as bounding the one-per-kind
rule — a list longer than the axis set must repeat a kind, so `all()` would short-circuit —
and that is wrong for the same reason the caps are: the rule refusing a number does not make
that number EQUAL to another, so each undefined kind stays distinct and the walk runs in
full. Measured: four thousand restrictions cost 17s to refuse, from 20 KB of wire and 56 KB
of proto-JSON.

Which is the limit of "bound the work at the transport". A read cap bounds work that is
LINEAR in bytes, and nothing else. A rule that walks its list against itself is bounded by
neither the cap on the list nor the cap on the request — 56 KB is far under any transport
cap anyone would set — and the only thing that bounds it is a size test inside the rule,
which short-circuits before the walk. The contract has exactly one such rule; it now carries
that test, refuses the same input in 26ms, and a conformance guard holds the test's threshold
equal to the field's own cap, because the rule stays silent above it and a cap raised alone
would leave the lists in between both unchecked and accepted.

Two details of that cap are load-bearing. It covers the RAW body as well as the decoded
message, because the verify face must buffer the whole body to check a signature over the
exact bytes and therefore runs before the caller is known — an unauthenticated caller
reaches only that read. And it is composed inside request-id, so a refusal still carries
the correlation id the reject-path logs are read by.

## The wire tier's rule ids are language-local, and the corpus says only what they share

The ingest-tier rule ids share one namespace, as recorded above. The tier ABOVE them does
not, and that is a property of where the ids come from rather than a choice anyone made:
Go reports protovalidate's ids, TypeScript reports Zod's issue codes, Python reports
Pydantic's error types. Three engines, three vocabularies, one behaviour.

So the per-entry corpus compares the three languages at three strengths, one per column,
and the split is not arbitrary — it is exactly what they can agree on. Field-level wire
violations are recorded as a BOOLEAN, because no id survives the crossing; coverage comes
instead from one case per rule, the same bargain the field-level validation corpus already
strikes and pays for the same way. Cross-field violations are recorded as IDS, because
message-level CEL ids are authored in the proto and all three ports emit those exact
strings. Ingest-tier violations are recorded as WHOLE FINDINGS — id, path, token and
message — because that tier is SDK-owned code in all three languages and its strings are
what an Exchange puts in `warnings[]`.

The cross-field column is the one that earns its keep. The two JSON ports cannot compose a
message-level rule the way protovalidate does, so each hand-enumerates the sites reachable
from an entry and walks them, and a hand-written walk fails by silently stopping short.
Before the column existed, deleting three of the five walk sites from the TypeScript port
left its entire suite green: no case isolated a `Restriction`, `Obligation` or nested
`scope_license` rule, so the boolean stayed true either way and a publisher would have been
told an overlapping term was fine. A conformance guard now derives the reachable rule set
from the descriptor and fails until every one of them has a case isolating it, which is
what makes the case list an obligation rather than a sample.

One limit belongs in the record rather than in a comment nobody reads. The corpus is
emitted by the Go oracle, so it can only carry inputs Go can construct and marshal. Legal
proto-JSON that Go never emits — a numeric enum, `null` for a repeated field — is outside
what this corpus can prove about the ports, and the ports do diverge there. That gap is
real, it is not closed here, and closing it needs a different instrument than a
Go-generated corpus.

Two halves of it turned out NOT to need one, and finding that was worth the search. The
null a real Exchange serves is on a singular MESSAGE field, which Go emits perfectly well
— EmitUnpopulated is the codec's own option set — so the entry corpus now carries the same
entries in that spelling beside the compact one, verdict taken from the message either
way. The camelCase refusal is the opposite case and genuinely cannot be vectored: protojson
ACCEPTS both spellings, so the oracle has no refusal to record, and the rule belongs to the
two JSON ports whose schemas strip what they do not recognise. It is held by a mirrored
test in each port instead. What remains outside the corpus is narrower than it looked: a
numeric enum, and a null on a repeated field.

## The license-term faces keep each language's idiom, and the map records only the name

Two of them differ in shape across the three languages, deliberately, and neither
difference belongs in `sdk/parity/symbol-map.json`. That map records whether a FACE exists
in each language; the allowlist beside it is a shrink-only ratchet over SYMBOLS, for a
face one language does not have. A symbol present in all three whose contract differs is
not that, and filing it there would say the opposite of what is true — the map's presence
check deliberately stops asserting an entry that carries an allowlist reason, so recording
these as divergences would have switched off the check that the names still exist. Same
treatment as the client defaults recorded further down, and as `SignAgentBinding`, whose
Go and Python faces take different custody and are mapped as plain counterparts.

**`NormalizeLicenseTerm` and `NormalizeResourceEntry` rewrite in place in Go and return a
copy in the ports.** Go takes a `*rampv1.LicenseTerm` and mutates it; the ports take a
proto-JSON object and hand back a new one, leaving the input alone. Each is the idiom of
its language, and the Go shape is load-bearing downstream rather than incidental: the
Exchange normalises the entry it is about to persist, so an in-place face is what lets the
canonical tokens reach the row and the offer projection without a second copy. The corpus
pins the OUTPUT, which is the part that must agree, and both port docstrings state the
contract they keep.

**`ValidateLicenseTerm` returns `([]RuleWarning, error)` in Go and a named `TermVerdict`
in the ports.** A term yields at most one hard violation, and in Go that is an error —
`RuleViolation` implements `error` precisely so the face can return it as one while a
caller still reads the typed fields back through `errors.As`. The ports have no comparable
idiom, so they name the pair. `EntryVerdict` is a struct in all three because an entry
yields MANY violations and a tuple would not carry them.

That leaves `TermVerdict` itself: a public name in two languages and absent from the third.
The surface gate walks Go to the ports and is complete in that direction, so a port-only
symbol is outside what it can see — by construction, not by oversight. Recording it here is
the available answer; making the gate walk both ways is a larger change and its own.

## A contract that describes its checks and not its verdict gets read wrong

`CatalogService`'s comment set out both validation tiers in detail — which rules run at the
boundary, how tokens are folded and aliases resolved, which checks reject and which only
warn — and never said what a rejection costs. Entry, or submission? The contract did not
answer, so readers answered it from the reference implementation, and the reference
implementation's own comments disagreed with each other: one described an over-cap entry as
dropped from a batch whose other entries still upsert, while its caller two files away
refuses everything and says so. Two consecutive readings of that code reached the wrong
answer, and one of them shipped into this repo's prose before it was caught.

The rule is now in the contract, where the question is settled once instead of re-derived:
a push is all-or-nothing at both tiers, and the per-entry detail a refusal carries is
reporting, not partial acceptance. The proto already did this for the other batch path —
`TransactionResponse` states that its per-item denials are partial results of a successful
request — so the pattern is established; catalog was the batch RPC that never used it.

Two things generalise. A message that carries per-item detail says nothing about whether
items are accepted per-item: naming what failed and applying what did not are different
questions, and `PushResourcesResponse.accepted` / `.rejected` and
`CatalogRejection.rejected_paths` are shaped for both answers while the contract permits
only one. And a behaviour stated nowhere in the contract will be inferred from whatever
implementation the reader has at hand — which makes an unstated verdict a defect in the
contract, not a gap in the docs.

## SSRF-guarded fetch: two flags, a corpus-locked transport

Every third-party-influenceable fetch across all three SDKs runs through a guarded
client governed by exactly two orthogonal environment flags and nothing else — no
deployment allow-list, no config file, no per-stack policy. `SKIP_SSRF` toggles the
dial-time **address** guard (default off: reserved / non-public addresses are
refused); `ALLOW_INSECURE` toggles the **scheme** guard (default off: https only).
An operator opts out of a guard by setting its flag; the production default is both
guards on.

Most fetches take that policy from the shared factory — `NewGuardedClientFromEnv`
in Go, `guarded_client` in Python, `guardedFetchFromEnv` in TS. The **WBA directory
fetch is the exception, and is deliberately stricter**: its host arrives in an
unauthenticated header and the GET runs *before* the signature is checked, so its
address guard is **not** opt-outable — `SKIP_SSRF` does not reach it. It honours
`ALLOW_INSECURE` for the scheme like everything else. A caller injecting its own
client into the resolver replaces that transport entirely and owns both policies
from then on, which is how the SDK's own tests reach loopback origins.

That asymmetry was not the original state, and the gap ran the other way. The
directory client was written before the scheme guard existed, and the change that
introduced the guard shared the address classifier with this resolver while leaving
the scheme policy behind — so for a period this section described a posture the most
exposed fetch in the SDK did not have. The lesson generalises: a guard introduced
after its callers has to be walked back through them, and a sentence beginning
"every fetch" is the easiest kind of claim to leave standing once it stops being
true.

The transport policy is fixed and identical in all three languages: redirect depth is
capped at **5** hops, well-known/JWKS response bodies are capped at **1 MiB**, and a
host resolving to multiple addresses **fails closed if any** resolved address is
reserved (never "the first address looked fine"). Python additionally imposes an
overall wall-clock deadline on one guarded GET, because `httpx`'s timeout is per-phase
and a hostile `getaddrinfo` could otherwise stall past every per-phase budget. The two
parts of the guard that are expressible as data — reserved-address classification and
the deny-by-default scheme allowlist — are **corpus-locked** to shared vectors
(`sdk/go/resolvers/testdata/ssrf-address-vectors.json`, `ssrf-scheme-vectors.json`,
`ssrf-hostset-vectors.json`, `ssrf-redirect-vectors.json`) that all three SDKs replay;
the residual wiring (that the guard is actually applied on each redirect hop and that a
non-2xx surfaces as a status rather than a crash) is covered behaviorally per language.

## Active-key selection: deterministic, non-normative, unbounded by default

The WBA directory can carry several simultaneously window-active signing keys during an
overlap rotation, and the protocol defines no "current" key among them. The SDK offers
a document-order selector (`ActiveEd25519Key` and its `…WithExpiry` / `…Screened`
variants) that returns the **first window-active key in document order** — a purely
deterministic tie-break, explicitly **not** a claim about which key is canonical.
Callers must not read normative meaning into the choice. Three conventions are
deliberate and shared byte-for-byte across the SDKs: the scan is **unbounded by
default** (a silent cap would make a valid key at a high document position permanently
unselectable *and* indistinguishable from "no active key" — a directory-padding
footgun — so a bound is opt-in via `MaxScan`, and an exhausted explicit bound is
**logged**); the `kty`/`crv` match ("OKP" / "Ed25519") is **case-insensitive** even
though RFC 7517/8037 specify exact case, so a case-varying directory resolves the same
key everywhere; and the bare selector screens *only* validity windows, so a
verification-path caller must use the revocation-aware `…Screened` form (or screen the
selected thumbprint themselves) — an emergency-revoked but still window-active key
would otherwise be selected.

## `ErrorDetail` is decoded cross-language, not just emitted

The typed `ErrorDetail` failure contract (see "Failure as a typed contract" above) is
now **read** in every SDK, not only produced by the Go server. The Go server binding
attaches a typed detail to a Connect error (`AttachErrorDetail` / `AttachDetail`), and
Python and TS ship symmetric **decoders** (`parse_error_detail` / `error_detail_from`;
`parseErrorDetail` / `errorDetailFrom`) so a TS or Python client branches on the typed
reason enum a Go exchange emitted, never on a human string. Emit and decode are pinned
to one shared oracle corpus (`error-detail-vectors.json`) replayed by all three
languages, so the typed-failure contract is verified end-to-end across the language
boundary rather than trusted to match by inspection.

## Discovery answers are grouped per URI, not flattened

A discovery call is per-URI: an agent asks about several resources at once, and both
`DiscoverResources` and the Broker's `Resolve` answer with one `OfferGroup` per
requested URI, each either carrying offers or carrying a typed `OfferAbsenceReason`
explaining why it carries none. The SDK returns that shape rather than a flat list,
with the fail-closed `{verified, rejected}` split preserved **inside** each group and
produced by the one `Verifier` — never a second verification path.

Flattening loses two things, and the second is unrecoverable. It drops the
attribution — which offer answers which URI — and it erases a REFUSED URI entirely,
because an empty group has no offer to carry its identity back. That matters because
the absence vocabulary is a set of different actions: `NOT_IN_CATALOG` means give up,
`SCOPE_INSUFFICIENT` means acquire an entitlement and retry, `CONTENT_BLOCKED` means
never retry. Flattened, all three read as "found nothing", which is the trial-and-error
the field exists to prevent.

Two consequences worth stating. The absence reasons are carried as POINTERS, because a
responder may legitimately withhold a reason where the existence of a resource must
itself stay hidden — so "absent" and "unspecified" have to stay distinguishable, and a
generated getter collapses them. And `ResourceResponse` carries a grouped list *and* a
flat one, with the flat one a single-URI convenience mirror; the two are read as
alternatives, never concatenated, because a responder that populates both would
otherwise have every offer counted twice.

## A signed leg refuses redirects; the guarded fetch follows them

The SSRF-guarded HTTP client follows up to five redirects, re-pinning the address and
re-vetting the scheme at each hop. That is correct for what it was built for: fetching
public well-known documents and key directories, where there is nothing to leak.

It is wrong for any request carrying a credential. A usage report, a dispute and a
delivery fetch all take only the guarded `.Transport` and install their own refusal.
For the RPC legs, following a redirect would re-sign the caller's request for a target
the peer chose — after the endpoint check had already passed, which is precisely the
window that check exists to close. For the delivery fetch it is worse: the proof of
possession covers `@target-uri`, so replaying it at a new location fails the edge's own
check, and re-signing per hop would hand a fresh proof of possession of the agent's key
to whatever host the first hop named. Redirect support on those legs would need per-hop
re-signing plus host anchoring, and is deliberately not attempted.

The transport error is rebuilt before it surfaces, because the HTTP client wraps every
failure in a value carrying the full URL it was dialing — query included. On a refused
redirect that is a credential belonging to a URL the *first hop* chose, so the wrapper
leaks even when the SDK's own message is already redacted.

## A usage report's destination comes off the message, not from configuration

A usage report must reach the Exchange that ISSUED the offer, and that Exchange's
address is read from its own `/.well-known/ramp.json` — never from configuration. A
signature covers the `exchange` DOMAIN; it says nothing about where that domain's
endpoint lives or where its DNS points.

The SDK takes the domain off `UsageReport.exchange` rather than as an argument, and
offers no option to supply an endpoint. Leaving no configuration slot for it is what
makes the rule structural instead of a convention someone can quietly reverse: there is
no parameter a configured origin could be passed as. (`Dispute` is the exception, and
only because `DisputeRequest` carries no `exchange` field to read — it takes the domain
as an argument and runs the identical checks.)

The destination is resolved from that host's own manifest, cached per host, and **six
checks** stand between the caller's message and the wire, in this order.

1. **It is a plain hostname.** The value is concatenated into a URL, so a smuggled path or
   query would choose what gets fetched.
2. **The advertised endpoint is that host or a subdomain of it.** The manifest is only as
   trustworthy as the host serving it, and a dial-time address guard has no objection to an
   unrelated PUBLIC host.
3. **The same rule again, on whatever the endpoint resolver handed back.** That resolver is
   an injectable seam, and this tier cannot make a SIGNED call conditional on a stranger's
   implementation having remembered the rule. The same predicate both times, deliberately.
4. **The scheme is one this SDK will dial.** Above the dial rather than inside it, so no
   injected transport can remove it and no signature rides plaintext.
5. **The dial goes through the address guard**, applied to the report itself and not only
   to the manifest fetch.
6. **A redirect is refused, never followed.** The per-origin client pool that
follows is bounded and evicts least-recently-used, because which Exchanges appear is
driven by incoming offers — an open-ended, caller-influenced key space.

## Three client defaults where the ports differ from Go on purpose

Go is the oracle and the ports mirror it, so a difference that survives review has to be
written down or it reads as drift. Three survive, and none is an API-surface divergence —
all are behaviour, so they live here rather than in `sdk/parity/symbol-map.json`, whose
allowlist is a shrink-only ratchet over SYMBOLS.

**Outbound request validation defaults ON in TypeScript and Python, and OFF in Go.** These
two SDKs are the ones handed to external partners; Go is what our own services run. A
missing recipient or idempotency key caught before anything is signed is worth more to a
partner than a matching default, and it costs nothing in safety — the Exchange enforces the
same rules whatever the client says, and the answer coming back is validated either way.
Worth knowing what "strict" buys, because it is not what it buys in Go: the generated
schema carries FIELD-level rules only, while the cross-field CEL rules stay
server-authoritative. The two checks share a name and not a scope.

**How much of the guard a caller may replace differs, and the scheme gate is the part
none of them may.** Go is strictest: `WithGuardedBaseTransport` takes what sits UNDER the
guard, and `NewGuardedTransport` says outright that the guard is not a default a caller may
replace — the only way out is the deployment-level `SKIP_SSRF` / `ALLOW_INSECURE` opt-out.
Both ports are more permissive: an injected `UnarySend` in TypeScript, or an injected
`httpx` client in Python, replaces the dial and takes the ADDRESS PIN with it. That is
deliberate — a caller who replaced the transport replaced it, and both languages need an
injectable dial far more than Go does, whose `httptest` seam is a `*http.Transport` — but it
is a real difference and it is why the scheme gate does not live in the dial. It sits above
it, in `unaryCall` and in the content leg's own pre-flight, so no injected send reaches a
plaintext endpoint carrying a signature. A signature over plaintext is not a latitude any
of the three offers.

**The two JSON clients bound how deep an answer may nest; Go does not.** A response body
is refused past 32 nested containers in TypeScript and Python — the number the protocol
already sets for a stranger's JSON in `AccountRegistration.data_schema`, so one value
covers how deep any document these SDKs did not write may be. Go's client inherits
protojson's own limit, which is around ten thousand, and is left alone.

The ports need a bound at all because their parsers descend into a document and answer for
a deep one in a way that is not a verdict: Python's raises `RecursionError`, which is
neither what a malformed document raises nor a failure the package says it raises, and how
much nesting it survives is a property of the interpreter release rather than a decision.
The lesson recorded above under the registration schema applies directly — a bound that
comes from a runtime's remaining stack is not a bound. TypeScript's parser does not
overflow, and takes the same number anyway: two clients answering differently about one
body is the state that produces the bugs, and which of them a caller happens to be holding
is not something a peer can know.

What it costs, stated plainly because the cost is real: `ext` is a
`google.protobuf.Struct` and nothing in the contract bounds its nesting, so an Exchange may
serve a conformant answer deeper than this. The Go client reads it and the other two refuse
it. Both readers of one wire is the shape this file exists to record, and moving the number
into the contract — which would make it one rule for every implementation rather than two —
is the change that would close it rather than document it.

**The client's transport splits in two, and which leg is guarded is the same in all
three.** A plain transport carries the configured home Exchange and the Broker — an
operator that points the SDK at a private origin chose that address — and an
address-guarded one carries the offer-derived legs and the delivery fetch, whose hosts
another party named. Python briefly guarded everything, which looked safer and was not: it
refused a home Exchange the other two reach, and a caller injecting a client to get that
back disarmed the guard on the leg that needed it. An injected client now carries both
legs, because a caller who replaced the transport replaced it.

## Host anchoring compares host and port, but not scheme

A value a remote document supplies — an Exchange's advertised endpoint, a WBA
directory's revocation URL — is checked against the host that served that document
before anything signed is sent to it: it may name itself or one of its own
subdomains, and nothing else. The match is on a full dot-delimited label boundary,
so `evil-a.com` is not a subdomain of `a.com`; a bare suffix comparison gets that
wrong, and it is the mistake an attacker registers a domain to exploit.

The rule is now normative and stated where an implementer will find it: the
`WellKnownManifest.endpoint` proto comment, and the manifest page on the docs site.
It was not always — for most of this work it lived only in one client's code,
inherited from a port rather than decided, which is why an Exchange advertising a
separate domain could be conformant and then stop being so. Enforcement sits in
the shared endpoint resolver, so every consumer of that resolver inherits it.

The anchor is the host that SERVED the manifest, not the `domain` member inside
it. That member is self-asserted, so anchoring to it would let a hostile manifest
name whatever endpoint it liked and validate itself. For a conformant Exchange the
two agree, which is exactly why the distinction only shows against a document
worth refusing.

All three SDKs enforce it now, and closing that gap is where the rule stopped
being a Go behaviour and became a contract. For a while one SDK enforced it while
Python and TypeScript shipped endpoint resolvers that did not, and the predicate
they would have needed did not exist in either — only private near-namesakes in
their WBA modules, neither of them a counterpart. TypeScript's compared
`URL.host`; Python's compared `netloc`, which keeps an explicit `:443` verbatim
and carries any userinfo along with it. The predicate is exported in all three
languages today, the private copies collapsed into it, and the rule is
corpus-locked rather than written down three times.

Neither near-namesake could simply be promoted, and the reason generalises past
this rule: **a platform URL parser answers a question adjacent to the one being
asked.** WHATWG's `URL` folds a scheme's default port away at PARSE time, which is
earlier than this rule decides which scheme is even in play, so a TypeScript port
built on it reports `x:443` and `http://x:80` as the same place. Python's
`urlsplit` strips tabs and newlines that Go refuses outright, lowercases its
`hostname` accessor, and keeps userinfo inside `netloc`. Each of those is one
value where two conformant-looking implementations disagree, so the ports parse
the authority themselves and the shared vectors carry every crossing.

Closing the gap also surfaced a hole in the rule that had been open the whole
time. The endpoint check refused userinfo by reading `url.Parse(endpoint).User`,
while the anchor half re-read the same string through the predicate's own parse —
and the two disagreed on exactly the shape the refusal exists to stop.
`u:p@exchange.example` names no scheme, so a plain URL parse takes `u` for one and
reports no userinfo and no host at all, while the anchor parse reads the value as
https, recovers `exchange.example` and matches it. A credential-bearing endpoint
was therefore accepted, and only the spelled-out `https://u:p@host` form was
refused — a spelling check where a credential check was intended. Both halves now
read the reference once, the same way, in all three languages: the ports keep that
single reading in a module of their own, because the alternative — the rule half
scanning the authority itself while the anchor half handed the whole string back to
be parsed again — is the same two-readings shape wearing different clothes. The lesson is the smaller half of the same
one above: a rule checked on one parse and enforced on another is two rules, and
the value that separates them is the value it was written for.

The comparison includes the PORT. An earlier version of this rule ignored it, on
the reasoning that TLS binds hostnames rather than ports, so a service on another
port of the same name is not another host. That was overruled deliberately: what
is being anchored is a place a signed call is sent, another port is another
service that the party publishing the anchor need not control, and having one rule
compare the port while another ignored it was the worse outcome of the two — the
predicate existed twice in Go and the copies had already drifted apart on exactly
this question. An Exchange reachable on a non-default port now names that port on
both sides.

One detail carries the whole decision: a DEFAULT port and an omitted port are the
same port. `url.Parse` does not materialize an implicit port, so a comparison of
raw authorities would refuse an operator who merely wrote `:443` out in full — a
spelling check wearing a security check's clothes. The folding is scheme-relative,
which is also what keeps it from becoming something it is not: the scheme is still
not compared here — that is the guarded transport's decision, in one place, driven
by one flag — and `http://x` and `https://x` both reduce to no port rather than
diverging on 80 versus 443.

Scheme-relative folding needs a scheme on both sides, and both ANCHORS in this SDK
arrive without one: a WBA directory's authority and an `Offer.exchange` host are
bare `host[:port]` values. Reading those as https — the assumption that lets a bare
domain be told apart from a path — quietly broke the rule for plaintext
deployments: an anchor of `a.example:80` kept its port, because 80 is not https's
default, while the candidate `http://a.example:80` folded the same port away, so
one authority reached two answers and every plaintext WBA directory that spelled
`:80` in full stopped anchoring its own revocation URL. A skipped revocation poll
leaves a revoked key resolving, which is a great deal worse than the spelling it
was refusing. A side that named no scheme therefore borrows the other's. That
decides only WHICH port is the default, never whether two different ports are
equal: an anchor of `x:443` still refuses `http://x:80`, since 443 is not http's
default.

## What the manifest fetch does not guarantee, and why that is bounded

The address a usage report goes to is read from the issuing Exchange's own
`/.well-known/ramp.json`. That fetch runs on the guarded client, which FOLLOWS up
to five redirects — re-pinning the address and re-vetting the scheme at each hop,
but not anchoring the host. So the party that answers for the manifest can be one
a redirect chose, and the answer is cached per host for the TTL.

That is deliberate and it is bounded, but the bound comes from somewhere else:
whatever the manifest says, the endpoint it advertises must still anchor to the
ORIGINAL offer domain before a signed call goes there. A redirect can therefore
change who answers the question, never where the report lands. What it can weaken
is the assumption that a manifest served over TLS from the provider's own domain
is thereby endorsed by it.

Refusing redirects on that one fetch was considered and not taken here. The
five-hop posture is stated as identical across all three languages, so a Go-only
refusal would create a divergence in the transport policy rather than remove a
risk — and the risk it removes is already contained by the anchoring above. Worth
revisiting as a three-language change.

## One agent identity, one key

The protocol carries a single agent identity and the SDK does not offer a second.
`agent_identity_hash` is defined as the RFC 7638 thumbprint of the agent's
request-signing key; an Exchange verifies the detached offer acceptance against the
key registered for whichever caller the request signature identified; and the
delivery URL is bound to that same thumbprint, which a later fetch must prove
possession of. A separately-custodied acceptance key would be refused at execute,
and any URL it did produce could never be fetched — the presented key would not
match the binding. So the client takes one Signer, and the public half of that
same key for the fetch header, which a Signer cannot yield.

One consequence for the cross-language surface: Go's `SignAgentBinding` takes a
`Signer` plus the public half, while Python's counterpart takes raw seed bytes.
The parity map records them as counterparts because the face exists in both, but
the custody posture differs — the Go seam exists precisely so the SDK never holds
key material, and closing that gap belongs with the TypeScript/Python client work.

## A delivery URL's own faults are malformed; the dial's refusals are unreachable

The content leg refuses a signed delivery URL for two quite different reasons, and a caller
acts on them oppositely: a fault in the VALUE will refuse identically forever and the
caller must fix it, while a refusal of the DIAL may not refuse next time. All three SDKs
had the split, and all three drew it in a different place — in both directions. One value
was a permanent verdict in one language and a retryable dial failure in the other two;
another was the reverse.

The cause was that the line had never been *stated*. Each language let its own URL parser
decide what "unparseable" meant, and the three disagree: Go's `net/url` rejects a malformed
percent-escape and accepts a reference naming no scheme, WHATWG `new URL` rejects the
schemeless reference and accepts the bad escape, and `httpx` accepts both — so Python
minted a proof and dialled for a URL Go refused locally, and its answer then depended on
whether the host resolved. A classification that changes with the resolver is not a
classification.

This is the same shape as the `Content-Type` reduction recorded earlier in this file, and
it takes the same fix. The rule is stated instead. A value fault is: the URL does not
parse, it names no scheme or no host, it names a port outside 1-65535, it carries a
malformed percent-escape where a parse would unescape one, or it does not re-serialize to
itself. Everything else — a scheme this SDK will not carry a proof over, an address the
guard refuses, a peer that never answers — is the dial's, and unreachable. The escape check
is read per component, admitting one in a query, exactly as the host rule already reads it:
a query is not unescaped at parse time, and a delivery URL's query is where the credential
lives.

The HOST rule is deliberately untouched. Its own corpus pins what a bare host may say, and
this is the delivery leg vetting a value it is about to dial — a different question about a
different value.

`sdk/go/resolvers/testdata/content-fetch-vectors.json` gained a second list for this, and
it is captured from the real fetcher rather than described, so the three answers are held
by the same mechanism that holds the reading of an answer.

**A refused dial carries no reason token.** TypeScript minted `ssrf_guard` on the delivery
leg, which no other language produced and which put the SDK's own verdict in a field
documented in all three as the peer's own refusal token —
`not_canonical_wire_naming` says outright that it is the one place that happens. It is
gone. The cost is worth naming: an address-pin refusal is a verdict about where a URL
points and a momentary blip is not, and nothing in the failure now tells those apart. None
of the three distinguished them, so the answer is the same everywhere rather than better in
one; distinguishing them means adding a value to the shared taxonomy, not a token in one
language.

## Bounds on a leg that dials wherever an offer points

`ReportUsage` and `Dispute` reach an Exchange named inside an offer, so the origin
is discovered at runtime and chosen by another party. Everything about that leg is
therefore bounded rather than open-ended: the response size (Connect treats an
unset cap as "any size" while compressing every exchange, so an unbounded read is
an unbounded decompression into the caller's memory), the call deadline (an
Exchange that accepts a connection and never answers would otherwise hold a call,
a goroutine and a socket indefinitely), the per-origin client pool, and the
endpoint cache beneath it. The key space for both caches is the same open-ended,
caller-influenced set of hosts, so both evict least-recently-used at a fixed cap.

The base-transport option cannot remove the guard on that leg. A caller can supply
a transport — its own connection tuning, its own client certificates — and it is
composed UNDERNEATH the address and scheme guards rather than in place of them.
The only opt-out through that seam is the deployment-level SKIP_SSRF /
ALLOW_INSECURE pair, which is one decision recorded in one place instead of a
per-caller copy of it. An option that could silently disarm the guard is exactly
how a security property becomes advisory.

Two settings on a supplied transport are dropped rather than carried, because
each would route the dial around the address check rather than under it: a proxy,
which would have the dialer resolve and vet the PROXY instead of the destination,
and a custom TLS dialer, which `net/http` prefers over the pinned dialer whenever
the scheme is https — which is every RAMP leg. The second is the more dangerous
of the two because it fails silently and on the ordinary path: a transport that
carries one dials wherever it likes and no error says the pin never ran. TLS
itself stays configurable through `TLSClientConfig`, which is kept, so the
customisation the seam exists for survives and only the dialer is refused.

The claim is scoped to that seam deliberately. A caller that injects a whole
`*http.Client` into a resolver, or supplies its own endpoint resolver, has taken
ownership of that fetch and the guard is that caller's to install — which is a
different bargain from an option that quietly weakens a fetch the SDK still
performs.
