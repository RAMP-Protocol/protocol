// The RAMP client: the six verbs an agent needs, over the Connect-unary JSON transport.
//
// TS port of sdk/go/connect (Client + BrokerClient). The transports differ — Go keeps
// full connect-go, this speaks the unary JSON form — but that is an implementation
// difference, not an API difference: the verbs carry the same names and the same
// contracts, and the fail-closed offer verification is the SAME Verifier the core ships,
// never a second verification path.
//
// It owns NO state. The signer, the keys, the dialing seam, the endpoint resolver and the
// verification policy are all injected.

import {
	createVerifier,
	type DiscoveryResult,
	type Mode,
	type OfferGroupResult,
	type VerifiedOffer,
	type Verifier,
} from "../core/verifier.ts";
import type { z } from "zod";

import { clockWindow, type Window } from "../core/window.ts";
import { fromWireOffer } from "../core/wire-canon.ts";
import { signOfferAcceptance, ACCEPTANCE_SIGNATURE_ALGORITHM } from "../src/acceptance.ts";
import { redactUserinfo } from "../src/host-ref.ts";
import { isBareHost } from "../src/hosts.ts";
import { generateIdempotencyKey } from "../src/idempotency.ts";
import { ProtocolVersion } from "../src/wire.ts";
import {
	DiscoveryRequestSchema,
	DiscoveryResponseSchema,
	DisputeRequestSchema,
	DisputeResponseSchema,
	PushResourcesRequestSchema,
	PushResourcesResponseSchema,
	RefreshCatalogRequestSchema,
	RefreshCatalogResponseSchema,
	RemoveResourcesRequestSchema,
	RemoveResourcesResponseSchema,
	ResourceQuerySchema,
	ResourceResponseSchema,
	TransactionRequestSchema,
	TransactionResponseSchema,
	UsageReportSchema,
	UsageReportResponseSchema,
} from "../../../gen/ts/wire/schemas.ts";
import { type Content, fetchContent } from "./content.ts";
import { malformed, notSent, RampCallError } from "./errors.ts";
import type { EndpointResolver } from "./route.ts";
import { vetExchangeEndpoint } from "./route.ts";
import { createUnarySend } from "./send.ts";
import {
	DEFAULT_CALL_TIMEOUT_MS,
	DEFAULT_MAX_RPC_READ_BYTES,
	parseMessage,
	unaryCall,
	validateRequest,
	type CallSigner,
	type UnarySend,
	type Validation,
} from "./transport.ts";

const EXCHANGE_SERVICE = "ramp.v1.ExchangeService";
const BROKER_SERVICE = "ramp.v1.BrokerService";
const CATALOG_SERVICE = "ramp.v1.CatalogService";

/** How long a delivery-fetch proof stays valid, in seconds.
 *
 * Short on purpose, and deliberately NOT the signed URL's own expiry, which can be hours:
 * the proof covers only the method and the URL, so for as long as the window is open
 * anyone who observes the request can repeat it. */
export const DEFAULT_PROOF_WINDOW_SEC = 30;

/** Everything a client is built from. Every field is injected; the client owns none of it. */
export interface ClientOptions {
	/** The RFC 9421 request signer. Custody stays with the application — the SDK receives
	 * a non-extractable CryptoKey and the keyid it signs under, never key bytes. */
	signer?: { privKey: CryptoKey; keyid: string };
	/** The PUBLIC half of the key `signer` signs with. A bound delivery fetch presents it
	 * in a header and derives the agent identity from it, and a non-extractable CryptoKey
	 * cannot yield it — custody keeps the private half, so the public half is supplied
	 * alongside. Without it the client can buy but cannot fetch what it bought.
	 *
	 * There is deliberately no option for a separate agent PRIVATE key. The protocol
	 * carries one agent identity: agent_identity_hash is the thumbprint of the agent's
	 * request-signing key, an Exchange verifies the detached acceptance against the key
	 * registered for the caller its request signature identified, and the delivery URL is
	 * bound to that same thumbprint. A second key would be refused at execute, and any URL
	 * it did produce could never be fetched. */
	agentPublicKey?: CryptoKey;
	/** The agent's own identity, forwarded on discovery and required on a purchase: both
	 * reference services resolve the calling agent from it and refuse a request naming
	 * none. */
	requester?: Record<string, unknown>;
	/** Offer-verification strictness. Defaults to "strict" — fail-closed. */
	verification?: Mode;
	/** Whether an outbound request is checked against its generated schema first.
	 * Defaults to "strict", which is deliberately stricter than Go — see the Validation
	 * type for why. Orthogonal to `verification`: this one is about the message going
	 * out, that one about the offers coming back. */
	validation?: Validation;
	/** Resolves an exchange identity to its raw 32-byte Ed25519 offer-signing key.
	 * Injected: the client owns no key state. */
	resolveOfferKey?: (exchange: string) => Promise<Uint8Array<ArrayBuffer> | undefined>;
	/** Turns an offer's exchange domain into that Exchange's own advertised origin. Never
	 * configuration — a usage report and a dispute go where the signed offer says. */
	endpointResolver?: EndpointResolver;
	/** The WBA directory origin this client signs as. */
	signatureAgent?: string;
	/** The RFC 9421 freshness window stamped on every outbound call. */
	signWindow?: Window;
	/** The freshness window stamped on a delivery-fetch proof. */
	proofWindow?: Window;
	/** Mints the X-Request-ID correlation value. Absent sends no header. */
	requestId?: () => string;
	/** The dialing seam for the configured (home Exchange / Broker) leg. */
	send?: UnarySend;
	/** The dialing seam for the OFFER-DERIVED leg. Defaults to the SSRF-guarded send,
	 * because the caller names a domain, the manifest it serves names an endpoint, and a
	 * signed call then goes there. */
	guardedSend?: UnarySend;
	maxRPCReadBytes?: number;
	callTimeoutMs?: number;
	contentTimeoutMs?: number;
	maxContentBytes?: number;
	/** The clock the offer Verifier reads, in epoch milliseconds. */
	now?: () => number;
}

/** Tunes a single state-mutating call. */
export interface CallOptions {
	/**
	 * Pins the idempotency key for this call. Reusing a key makes the call a deliberate
	 * replay: the server dedupes on it (a fresh key is minted per call by default). The
	 * SDK never tracks keys — the server owns dedup.
	 *
	 * Hold the key and pass the same one back when retrying, on every verb that takes
	 * this option. The key identifies the ACTION, not the attempt: a fresh key on a retry
	 * reads to the server as a second purchase, a second report, a second dispute.
	 */
	idempotencyKey?: string;
}

/**
 * The response types, inferred from the generated schemas rather than restated.
 *
 * A verb returning `Record<string, unknown>` hands a caller no help exactly where it is
 * needed: `transaction_id`, `report_id` and the retrieval endpoint are the links of the
 * dispute chain, and every read of one was an unchecked index. Python's verbs return the
 * generated models, so the two faces were the same verb names over materially different
 * ergonomics.
 */
export type TransactionResponse = z.infer<typeof TransactionResponseSchema>;
/** The answer to a usage report; carries the `report_id` a dispute is filed against. */
export type UsageReportResponse = z.infer<typeof UsageReportResponseSchema>;
/** The answer to a dispute. */
export type DisputeResponse = z.infer<typeof DisputeResponseSchema>;

/** The agent-facing Exchange client. */
export interface Client {
	discover(query: Record<string, unknown>): Promise<DiscoveryResult>;
	execute(offer: VerifiedOffer, opts?: CallOptions): Promise<TransactionResponse>;
	reportUsage(
		report: Record<string, unknown>,
		opts?: CallOptions,
	): Promise<UsageReportResponse>;
	dispute(request: Record<string, unknown>, opts?: CallOptions): Promise<DisputeResponse>;
	fetch(signedURL: string): Promise<Content>;
}

/** The Broker client. */
export interface BrokerClient {
	resolve(request: Record<string, unknown>): Promise<DiscoveryResult>;
}

// resolved holds what both faces are built from, so the exchange and broker clients
// cannot drift in how they sign, correlate, bound or verify.
interface Resolved {
	opts: ClientOptions;
	verifier: Verifier;
	send: UnarySend;
	guardedSend: UnarySend;
	signer: CallSigner | undefined;
}

function resolve(opts: ClientOptions): Resolved {
	const now = opts.now ?? (() => Date.now());
	const verifier = createVerifier(opts.verification ?? "strict", {
		// Fail-closed by default: with no resolver injected nothing resolves, so every
		// offer lands in `rejected` with a reason rather than being surfaced unchecked.
		resolve: opts.resolveOfferKey ?? (async () => undefined),
		now,
	});
	const signer: CallSigner | undefined =
		opts.signer === undefined
			? undefined
			: {
					privKey: opts.signer.privKey,
					keyid: opts.signer.keyid,
					...(opts.signatureAgent !== undefined
						? { signatureAgent: opts.signatureAgent }
						: {}),
					...(opts.signWindow !== undefined ? { window: opts.signWindow } : {}),
				};
	return {
		opts,
		verifier,
		send: opts.send ?? createUnarySend({ guarded: false }),
		guardedSend: opts.guardedSend ?? createUnarySend({ guarded: true }),
		signer,
	};
}

// call is the one place a verb reaches the wire, so every leg carries the same header
// set, the same bound and the same deadline.
async function call(
	r: Resolved,
	op: string,
	baseURL: string,
	service: string,
	method: string,
	message: unknown,
	guarded: boolean,
): Promise<unknown> {
	return unaryCall({
		target: { baseURL, service, method },
		op,
		message,
		// The leg decides the dial AND the gate together, so the two cannot drift apart.
		send: guarded ? r.guardedSend : r.send,
		guarded,
		...(r.signer !== undefined ? { signer: r.signer } : {}),
		...(r.opts.requestId !== undefined ? { requestId: r.opts.requestId } : {}),
		maxBytes: r.opts.maxRPCReadBytes ?? DEFAULT_MAX_RPC_READ_BYTES,
		timeoutMs: r.opts.callTimeoutMs ?? DEFAULT_CALL_TIMEOUT_MS,
	});
}

/**
 * createClient builds a client against baseURL — the agent's HOME Exchange, the one its
 * account lives on.
 *
 * Discovery and purchase go to baseURL. A usage report or a dispute does NOT: those reach
 * the Exchange that ISSUED the offer, resolved per call from that Exchange's own
 * manifest, over a separately guarded transport.
 */
export function createClient(baseURL: string, options: ClientOptions = {}): Client {
	const r = resolve(options);
	return {
		discover: (query) => discover(r, baseURL, query),
		execute: (offer, opts) => execute(r, baseURL, offer, opts ?? {}),
		reportUsage: (report, opts) => reportUsage(r, report, opts ?? {}),
		dispute: (request, opts) => dispute(r, request, opts ?? {}),
		fetch: (signedURL) => fetchVerb(r, signedURL),
	};
}

/**
 * createBrokerClient builds a client against a Broker's base URL.
 *
 * A SEPARATE constructor rather than a second surface on the exchange client because the
 * two speak to different parties. A Broker is not an Exchange: it fans a query out across
 * Exchanges it knows and relays back what they offered, so its address is the Broker's,
 * not any Exchange's. Hanging both off one base URL would mean one of the two was always
 * pointed at the wrong party.
 *
 * It takes the same options, but only the ones a discovery call has any use for do
 * anything, and two need care. A single pinned offer key is the wrong shape here: Broker
 * fan-out returns offers minted by different Exchanges, so inject a resolver that
 * resolves each issuing Exchange's own key. And `requester` is REQUIRED, not optional: a
 * Broker resolves the calling agent from it and declines a request naming none, so
 * resolve refuses locally rather than spending a round trip to be told.
 */
export function createBrokerClient(
	baseURL: string,
	options: ClientOptions = {},
): BrokerClient {
	const r = resolve(options);
	return { resolve: (request) => brokerResolve(r, baseURL, request) };
}

// ---------------------------------------------------------------------------
// The verbs
// ---------------------------------------------------------------------------

/**
 * discover issues DiscoverResources and returns one group per requested URI, each
 * carrying the fail-closed {verified, rejected} split.
 *
 * EVERY returned offer is verified against the exchange offer-signing key before it is
 * handed back. Neither an unverifiable nor a doctored offer is silently dropped — it
 * lands in `rejected` with a reason. A URI the responder GROUPED and left empty keeps its
 * group, carrying the typed reason, so a refusal is an answer rather than an absence.
 *
 * The query is CLONED before `ver` and the requester are filled in, so the message the
 * caller built stays untouched — it crossed a module boundary as an argument, not as a
 * buffer. Both are filled only when EMPTY: a value the caller set is theirs.
 *
 * `exchange` is NOT among them: the caller MUST set it to the bare host of the Exchange
 * being queried, because the contract requires every addressed request to name its
 * recipient. It is left to the caller rather than derived from the base URL on purpose —
 * the point of the field is to state whom the SENDER meant, and a value the transport
 * filled in from the address it was already dialling would restate the dial target
 * instead of checking it.
 */
async function discover(
	r: Resolved,
	baseURL: string,
	query: Record<string, unknown>,
): Promise<DiscoveryResult> {
	const op = "discover";
	const sent = stampDiscovery(op, query, r.opts.requester);
	validateRequest(op, sent, ResourceQuerySchema, r.opts.validation ?? "strict");
	const raw = await call(
		r,
		op,
		baseURL,
		EXCHANGE_SERVICE,
		"DiscoverResources",
		sent,
		false,
	);
	const msg = parseMessage<Record<string, unknown>>(op, raw, ResourceResponseSchema);
	return {
		// The offers are read from the RAW answer, not the parsed one. A schema parse is
		// the GATE — it proves the answer is well formed and that its field names are
		// canonical — but it also NORMALIZES: Zod fills every declared default, which adds
		// keys the signer never covered and would make a genuine offer fail verification.
		// A signature covers what the responder sent.
		groups: await discoveredGroups(r.verifier, sent, isRecord(raw) ? raw : {}),
		exchange: typeof msg["exchange"] === "string" ? msg["exchange"] : "",
		...(isRecord(msg["rate_limit"]) ? { rateLimit: msg["rate_limit"] } : {}),
	};
}

/**
 * discoveredGroups folds a ResourceResponse's two offer representations into the per-URI
 * form.
 *
 * The message carries a grouped list AND a flat one, and the contract says a responder
 * populating groups SHOULD leave the flat list empty "to avoid ambiguity" — but a real
 * Exchange populates both, the flat list mirroring the grouped offers as a single-URI
 * convenience. So the two are read as ALTERNATIVES, never concatenated: concatenating
 * would double every offer against such a server, and deduplicating would silently accept
 * a responder whose two lists disagree, which is precisely the ambiguity the contract
 * forbids.
 *
 * Groups win when present. The flat fallback becomes a single group; it carries no URI of
 * its own, so it takes the query's only URI when the query named exactly one, and none
 * otherwise — the SDK does not invent an attribution the wire did not make.
 */
async function discoveredGroups(
	verifier: Verifier,
	query: Record<string, unknown>,
	msg: Record<string, unknown>,
): Promise<OfferGroupResult[]> {
	const groups = msg["offer_groups"];
	if (Array.isArray(groups) && groups.length > 0) {
		return verifier.sortGroups(groups.map(canonicalizeGroupOffers));
	}
	const flat = msg["offers"];
	if (!Array.isArray(flat) || flat.length === 0) return [];
	const uris = query["uris"];
	const uri =
		Array.isArray(uris) && uris.length === 1 && typeof uris[0] === "string"
			? uris[0]
			: "";
	return [
		{ uri, result: await verifier.sort(canonicalize(flat)), restrictionFilters: [] },
	];
}

/**
 * canonicalize inverts the wire emission of each offer before it is verified.
 *
 * A RAMP Exchange serves proto-JSON with EmitUnpopulated, so a wire offer carries
 * zero-valued scalars, empty repeateds, null messages and *_UNSPECIFIED enums that the
 * SIGNED form does not — the signature covers the omit-unpopulated rendering. Verifying
 * the wire object as-is would fail every genuine offer, which is a fail-closed direction
 * but the wrong answer. fromWireOffer is the schema-aware inversion, byte-parity-pinned
 * against the Go oracle; a field newer than its pinned schema is kept verbatim, so an
 * offer this SDK cannot reconstruct still verifies FALSE rather than being waved through.
 *
 * The verified value is therefore the CANONICAL offer, which is what execute reflects
 * back: the Exchange verifies the presented bytes and re-renders them canonically either
 * way, so reflecting the canonical form is the same statement with none of the wire
 * emission's noise.
 */
function canonicalize(offers: unknown[]): unknown[] {
	return offers.map((offer) =>
		isRecord(offer) ? fromWireOffer(offer) : offer,
	);
}

/** canonicalizeGroupOffers applies the inversion to one group's offers, leaving the
 * group's own URI and typed reasons untouched. */
function canonicalizeGroupOffers(group: unknown): unknown {
	if (!isRecord(group)) return group;
	const offers = group["offers"];
	if (!Array.isArray(offers)) return group;
	return { ...group, offers: canonicalize(offers) };
}

/**
 * resolve runs discovery through the Broker, which fans out to the Exchanges it knows and
 * returns one group per requested URI.
 *
 * Every returned offer is verified through the SAME fail-closed Verifier discover uses —
 * not a second verification path. Broker-relayed offers are precisely the case that rule
 * exists for: the Broker forwards offers it did not mint, and an unverified relay can
 * steer an agent's selection with doctored terms that only fail later, at the purchase.
 *
 * A resolve that finds nothing is a SUCCESSFUL answer carrying a typed reason, not a
 * failure: the whole-call reason lands on the result and the per-URI ones on each group.
 *
 * It carries no idempotency key. Pure discovery buys nothing and changes nothing, so
 * there is nothing for a server to deduplicate — the request message has no such field.
 */
async function brokerResolve(
	r: Resolved,
	baseURL: string,
	request: Record<string, unknown>,
): Promise<DiscoveryResult> {
	const op = "resolve";
	const sent = stampDiscovery(op, request, r.opts.requester);
	// Refused locally rather than sent: a Broker resolves the calling agent from the
	// requester and declines a request that names none, so this is a verdict the client
	// already knows, and naming the remedy beats relaying "requester required" from a
	// round trip away. execute refuses the same way.
	if (sent["requester"] === undefined) {
		throw malformed(
			op,
			new Error("no requester configured; a Broker resolves who is asking"),
		);
	}
	validateRequest(op, sent, DiscoveryRequestSchema, r.opts.validation ?? "strict");
	const raw = await call(r, op, baseURL, BROKER_SERVICE, "Resolve", sent, false);
	const msg = parseMessage<Record<string, unknown>>(op, raw, DiscoveryResponseSchema);
	// Read from the RAW answer for the same reason discover does: a parse normalizes, and
	// a signature covers what the responder sent.
	const groups = isRecord(raw) ? raw["offer_groups"] : undefined;
	const absence = msg["absence_reason"];
	return {
		groups: await r.verifier.sortGroups(
			Array.isArray(groups) ? groups.map(canonicalizeGroupOffers) : [],
		),
		...(typeof absence === "string" ? { absenceReason: absence } : {}),
		// A DiscoveryResponse names no single Exchange and carries no rate-limit signal —
		// each offer carries its own issuing domain instead.
		exchange: "",
	};
}

/**
 * execute commits to a VERIFIED offer and returns the transaction response.
 *
 * It accepts ONLY a VerifiedOffer — the brand is module-private to the core, so passing a
 * rejected offer or a raw parsed one is a COMPILE error. A per-call idempotency key is
 * minted fresh unless one is pinned. execute builds the whole TransactionRequest, so it
 * also stamps `ver` from ProtocolVersion — the caller neither supplies nor overrides it.
 */
async function execute(
	r: Resolved,
	baseURL: string,
	offer: VerifiedOffer,
	opts: CallOptions,
): Promise<TransactionResponse> {
	const op = "execute";
	if (r.opts.requester === undefined) {
		throw malformed(
			op,
			new Error("no requester configured; an Exchange resolves who is buying from it"),
		);
	}
	if (r.opts.signer === undefined) {
		// not_signable, matching what fetch answers for the same missing holder: a caller
		// branching on the kind sees one condition under one class, whichever verb met it
		// first.
		throw new RampCallError({
			kind: "not_signable",
			op,
			cause: new Error(
				"no signer configured; a purchase carries a detached acceptance signed with the agent's own key",
			),
		});
	}
	const wire = offer.offer as Record<string, unknown>;
	const offerSig = typeof wire["signature"] === "string" ? wire["signature"] : "";
	// An acceptance floating free of a concrete offer is meaningless, and an unsigned
	// offer is reachable here: verification "off" and RejectedOffer.unsafe() both mint a
	// VerifiedOffer without a signature check.
	if (offerSig === "") {
		throw malformed(op, new Error("cannot accept an unsigned offer"));
	}
	// `??` would take an EMPTY pinned key as a value and send it, which fails the
	// message's own min(1). An empty string is the absence of a key, as Go and Python
	// both read it.
	const key =
		opts.idempotencyKey !== undefined && opts.idempotencyKey !== ""
			? opts.idempotencyKey
			: generateIdempotencyKey();
	const requester = r.opts.requester;
	// The acceptance covers the offer, the requester and the idempotency key, so a retry
	// that pins the same key reproduces byte-identical acceptance bytes. That is the
	// deliberate-replay semantic, not an accident.
	let signature: string;
	try {
		signature = await signOfferAcceptance(
			{
				offerSig,
				requesterId: stringField(requester, "id"),
				requesterDomain: stringField(requester, "domain"),
				idempotencyKey: key,
			},
			r.opts.signer.privKey,
		);
	} catch (cause) {
		throw new RampCallError({ kind: "not_signable", op, cause });
	}
	// Items-only wire shape: a single offer is the degenerate 1-element items list, each
	// item reflecting its signed Offer back exactly as received at discovery. The
	// authoritative identity is the reflected offer; the optional top-level offer_id
	// correlation scalar is left unset.
	const request = {
		ver: ProtocolVersion,
		idempotency_key: key,
		requester,
		items: [
			{
				offer: wire,
				agent_acceptance: {
					signature,
					signature_algorithm: ACCEPTANCE_SIGNATURE_ALGORITHM,
				},
			},
		],
	};
	validateRequest(op, request, TransactionRequestSchema, r.opts.validation ?? "strict");
	const raw = await call(
		r,
		op,
		baseURL,
		EXCHANGE_SERVICE,
		"ExecuteTransaction",
		request,
		false,
	);
	return parseMessage(op, raw, TransactionResponseSchema);
}

/**
 * reportUsage files a usage report with the Exchange that ISSUED the offer — never
 * through a Broker, and never to an address from configuration.
 *
 * The destination comes off the report itself: `exchange` carries the offer's signed
 * exchange domain, and the endpoint is then resolved from that Exchange's own well-known
 * manifest. Reading it off the message rather than taking it as an argument is what makes
 * the rule structural — there is no parameter a configured origin could be passed as, so
 * it cannot become the default by anyone's convenience.
 *
 * The report is CLONED before `ver` and the idempotency key are stamped, so the message
 * the caller built stays untouched. The key identifies the REPORT, not the attempt: a
 * fresh one is minted only when the caller supplied none, because an application that
 * mints its own key for its own dedup would otherwise have it silently discarded and see
 * every retry counted as a second report.
 */
async function reportUsage(
	r: Resolved,
	report: Record<string, unknown>,
	opts: CallOptions,
): Promise<UsageReportResponse> {
	const op = "report usage";
	const sent = stampEnvelope(op, report, opts);
	// The address is vetted BEFORE the schema: an unroutable recipient is a refusal to
	// send, which is a different verdict from a message the server would reject, and the
	// caller acts on them differently.
	const endpoint = await vetExchangeEndpoint(
		r.opts.endpointResolver,
		stringField(sent, "exchange"),
		op,
	);
	validateRequest(op, sent, UsageReportSchema, r.opts.validation ?? "strict");
	const raw = await call(
		r,
		op,
		endpoint,
		EXCHANGE_SERVICE,
		"ReportUsage",
		sent,
		true,
	);
	return parseMessage(op, raw, UsageReportResponseSchema);
}

/**
 * dispute files a dispute with the Exchange that issued the offer, over the same vetted
 * routing a usage report takes.
 *
 * The destination comes off the request, exactly as it does for a usage report. A
 * parameter is something a configured origin can be passed as; reading the destination
 * off the signed message leaves no such seam.
 *
 * The dispute chain is a structural invariant: an agent must have filed a usage report
 * and received a report_id before it can dispute, so `report_id` and `transaction_id`
 * both name links the Exchange already holds.
 */
async function dispute(
	r: Resolved,
	request: Record<string, unknown>,
	opts: CallOptions,
): Promise<DisputeResponse> {
	const op = "dispute";
	const sent = stampEnvelope(op, request, opts);
	const endpoint = await vetExchangeEndpoint(
		r.opts.endpointResolver,
		stringField(sent, "exchange"),
		op,
	);
	validateRequest(op, sent, DisputeRequestSchema, r.opts.validation ?? "strict");
	const raw = await call(
		r,
		op,
		endpoint,
		EXCHANGE_SERVICE,
		"DisputeTransaction",
		sent,
		true,
	);
	return parseMessage(op, raw, DisputeResponseSchema);
}

/**
 * fetch retrieves the content a signed delivery URL names, presenting proof of possession
 * of the agent key that URL is bound to.
 *
 * This is the LOW-TIER fetch: follow one signed URL, present the key, return the bytes. It
 * does not discover, select, buy or report — that orchestration is a separate, higher
 * tier.
 *
 * It takes no CallOptions: a fetch is a GET against an already-issued URL, so there is no
 * idempotency key to pin — nothing on this path mutates state.
 */
async function fetchVerb(r: Resolved, signedURL: string): Promise<Content> {
	const op = "fetch content";
	if (r.opts.signer === undefined) {
		throw new RampCallError({
			kind: "not_signable",
			op,
			cause: new Error(
				"no signer configured; a bound fetch proves possession of the agent key — " +
					"the same key the request is signed with",
			),
		});
	}
	if (r.opts.agentPublicKey === undefined) {
		throw new RampCallError({
			kind: "not_signable",
			op,
			cause: new Error(
				"no agent public key configured; a bound fetch presents it alongside the " +
					"proof, and a non-extractable signing key cannot yield it",
			),
		});
	}
	return fetchContent(signedURL, {
		// One private key, held by the signer. The public half rides alongside because
		// custody keeps the private one and a CryptoKey cannot be asked for its pair.
		keyPair: { privateKey: r.opts.signer.privKey, publicKey: r.opts.agentPublicKey },
		// The proof window is the client's, not the signer's. core/sign.ts defaults to the
		// 10-minute TTL a server-side proof uses; a delivery proof is minted for one GET
		// and wants the short window instead, so the default is set here rather than
		// inherited.
		window: r.opts.proofWindow ?? clockWindow(() => Date.now() / 1000, DEFAULT_PROOF_WINDOW_SEC),
		...(r.opts.contentTimeoutMs !== undefined
			? { timeoutMs: r.opts.contentTimeoutMs }
			: {}),
		...(r.opts.maxContentBytes !== undefined
			? { maxBytes: r.opts.maxContentBytes }
			: {}),
		...(r.opts.requestId !== undefined ? { requestId: r.opts.requestId } : {}),
	});
}

// ---------------------------------------------------------------------------
// Envelope stamping
// ---------------------------------------------------------------------------

/**
 * stampDiscovery fills the envelope a DISCOVERY call carries, which is the mutating
 * envelope minus the idempotency key: pure discovery buys nothing and changes nothing, so
 * there is no action for a key to identify.
 *
 * Both fills are only-when-empty. The caller's own value always wins — the message
 * crossed a module boundary as an argument, not as a buffer to fill in — and the
 * requester is filled because both reference services resolve the calling agent from it
 * and refuse a request that names none, while the client already holds that identity.
 */
function stampDiscovery(
	op: string,
	message: Record<string, unknown>,
	requester: Record<string, unknown> | undefined,
): Record<string, unknown> {
	const sent = clone(op, message);
	if (sent["ver"] === undefined || sent["ver"] === "") sent["ver"] = ProtocolVersion;
	if (sent["requester"] === undefined && requester !== undefined) {
		sent["requester"] = requester;
	}
	return sent;
}

/**
 * stampEnvelope fills the two envelope fields the protocol requires on a state-mutating
 * call, WITHOUT overwriting what the caller already set.
 *
 * Fill-when-empty is the whole rule. `ver` has a single owner, so the SDK supplies it
 * rather than making every caller reach for the constant. The idempotency key is REQUIRED
 * and identifies the action rather than the attempt, so a value the caller put there is
 * theirs — discarding it would turn each of their retries into a fresh action, which is
 * the double-counting the field exists to prevent. A pinned key overrides both.
 */
function stampEnvelope(
	op: string,
	message: Record<string, unknown>,
	opts: CallOptions,
): Record<string, unknown> {
	const sent = clone(op, message);
	if (sent["ver"] === undefined || sent["ver"] === "") sent["ver"] = ProtocolVersion;
	const onMessage = sent["idempotency_key"];
	// Each fallback is taken when the one before it is EMPTY, not merely absent: an empty
	// pinned key is no key, which is how Go and Python both read it.
	sent["idempotency_key"] =
		opts.idempotencyKey !== undefined && opts.idempotencyKey !== ""
			? opts.idempotencyKey
			: typeof onMessage === "string" && onMessage !== ""
				? onMessage
				: generateIdempotencyKey();
	return sent;
}

// clone copies a caller's message so the SDK can stamp its envelope without touching what
// the caller still holds. structuredClone is the runtime's own deep copy; a message that
// cannot survive it is one that cannot be serialized to the wire either.
function clone(op: string, message: Record<string, unknown>): Record<string, unknown> {
	try {
		return structuredClone(message);
	} catch (cause) {
		throw malformed(op, cause);
	}
}

function stringField(record: Record<string, unknown>, key: string): string {
	const value = record[key];
	return typeof value === "string" ? value : "";
}

function isRecord(v: unknown): v is Record<string, unknown> {
	return typeof v === "object" && v !== null && !Array.isArray(v);
}

// ---------------------------------------------------------------------------
// The publisher's verbs: CatalogService
// ---------------------------------------------------------------------------

/** The answer to a catalog push: accepted/rejected counts and the warnings the accepted terms carry. */
export type PushResourcesResponse = z.infer<typeof PushResourcesResponseSchema>;
/** The answer to a catalog removal. */
export type RemoveResourcesResponse = z.infer<typeof RemoveResourcesResponseSchema>;
/** The answer to a catalog refresh request. */
export type RefreshCatalogResponse = z.infer<typeof RefreshCatalogResponseSchema>;

/** The publisher-facing Catalog client. */
export interface CatalogClient {
	pushResources(request: Record<string, unknown>): Promise<PushResourcesResponse>;
	removeResources(request: Record<string, unknown>): Promise<RemoveResourcesResponse>;
	refreshCatalog(request: Record<string, unknown>): Promise<RefreshCatalogResponse>;
}

/**
 * createCatalogClient builds a client against an Exchange's CATALOG endpoint — the
 * publisher role's face: push, remove and refresh the catalog entries a publisher, or a
 * contributor it authorised, supplies.
 *
 * A SEPARATE constructor, as the Broker's is, and for a related reason: the address is a
 * different one. An Exchange advertises CatalogService at its manifest's
 * `catalog_endpoint`, distinct from the ExchangeService endpoint the agent client dials,
 * and the caller is a different party holding a different key — a contributor's, named
 * by `caller_id`, never an agent's. Hanging the catalog verbs on the agent client would
 * carry every agent-only holder into a client that uses none of them, and point one of
 * the two roles at the wrong address.
 *
 * The publisher chose the Exchange, so the origin is configuration and the leg runs on
 * the plain send — the posture of the agent client's home Exchange, not of its
 * offer-derived leg. It takes the same options; `signer` is what a real push needs (an
 * Exchange refuses an unsigned catalog call), and the agent-only ones — the requester,
 * the agent key, the offer-key resolver, the endpoint resolver, the guarded send — are
 * inert here rather than errors, so one option set can build every face.
 */
export function createCatalogClient(baseURL: string, options: ClientOptions = {}): CatalogClient {
	const r = resolve(options);
	return {
		pushResources: (request) =>
			catalogCall(r, baseURL, "push resources", "PushResources", PushResourcesRequestSchema, PushResourcesResponseSchema, request),
		removeResources: (request) =>
			catalogCall(r, baseURL, "remove resources", "RemoveResources", RemoveResourcesRequestSchema, RemoveResourcesResponseSchema, request),
		refreshCatalog: (request) =>
			catalogCall(r, baseURL, "refresh catalog", "RefreshCatalog", RefreshCatalogRequestSchema, RefreshCatalogResponseSchema, request),
	};
}

/**
 * catalogCall is the one shape all three catalog verbs share. The request is CLONED
 * before `ver` is stamped (fill-when-empty; the caller's value is theirs); no
 * idempotency key is stamped, because the messages carry none — a catalog push is an
 * upsert and naturally idempotent, so a key there would be ceremony. `exchange` is the
 * caller's to set, the bare domain of the Exchange the call is meant for; a request
 * that names none, or names something that is not a bare host, is refused before
 * anything is signed or sent — a refusal to send, the verdict a report with no
 * routable recipient gets, not a malformed message.
 */
async function catalogCall<T>(
	r: Resolved,
	baseURL: string,
	op: string,
	method: string,
	requestSchema: { safeParse: (v: unknown) => { success: boolean; data?: unknown } },
	responseSchema: { safeParse: (v: unknown) => { success: boolean; data?: unknown } },
	request: Record<string, unknown>,
): Promise<T> {
	const sent = stampVer(op, request);
	requireRecipient(op, stringField(sent, "exchange"));
	validateRequest(op, sent, requestSchema, r.opts.validation ?? "strict");
	const raw = await call(r, op, baseURL, CATALOG_SERVICE, method, sent, false);
	return parseMessage<T>(op, raw, responseSchema);
}

function stampVer(op: string, message: Record<string, unknown>): Record<string, unknown> {
	const sent = clone(op, message);
	if (sent["ver"] === undefined || sent["ver"] === "") sent["ver"] = ProtocolVersion;
	return sent;
}

// The refused value is redacted before it is named. isBareHost returns false for a
// reference carrying userinfo, so a mistyped credential reaches the message below
// verbatim; the routing check next door redacts for the same reason, and a tier
// that echoes is the drift redactUserinfo exists to prevent.
function requireRecipient(op: string, exchange: string): void {
	if (exchange === "") {
		throw notSent(op, new Error("request names no recipient; set exchange to the Exchange's bare domain"));
	}
	let bare = false;
	try {
		bare = isBareHost(exchange);
	} catch (cause) {
		throw notSent(op, cause);
	}
	if (!bare) {
		throw notSent(op, new Error(`exchange ${JSON.stringify(redactUserinfo(exchange))} is not a bare host`));
	}
}

export { RampCallError } from "./errors.ts";
export type { CallErrorKind } from "./errors.ts";
export type { Content } from "./content.ts";
export type { EndpointResolver } from "./route.ts";
export type { UnaryRequest, UnaryResponse, UnarySend, Validation } from "./transport.ts";
export {
	DEFAULT_CALL_TIMEOUT_MS,
	DEFAULT_MAX_RPC_READ_BYTES,
	NOT_CANONICAL_WIRE_NAMING,
} from "./transport.ts";
export {
	DEFAULT_CONTENT_TIMEOUT_MS,
	DEFAULT_MAX_CONTENT_BYTES,
} from "./content.ts";
