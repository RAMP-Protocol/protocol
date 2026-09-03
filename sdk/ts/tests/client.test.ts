// The RAMP client's verbs (TypeScript side) — mirror of the sdk/go connect suite.
//
// Driven through an INJECTED send rather than a socket: what is under test is the
// protocol behaviour — the URL, the envelope, the routing, the verification and the
// failure taxonomy — not undici. The default dialing seam is exercised where its own
// obligations live (redirects refused, the body bound), which is a different file's job.
import { createServer } from "node:http";
import { describe, expect, it } from "vitest";

import {
	createBrokerClient,
	createClient,
	NOT_CANONICAL_WIRE_NAMING,
	RampCallError,
	type UnaryRequest,
	type UnarySend,
} from "../client/index.ts";
import { createVerifier } from "../core/verifier.ts";
import { signOffer } from "../src/offer-sign.ts";
import { verifyOfferAcceptance, verifyRequestAcceptance } from "../src/acceptance.ts";

const REQUESTER = { id: "agent-1", domain: "agent.test", type: "REQUESTER_TYPE_AGENT" };

/** A send that records what it was given and answers a fixed body. */
function recordingSend(
	answer: unknown,
	status = 200,
): { send: UnarySend; seen: UnaryRequest[] } {
	const seen: UnaryRequest[] = [];
	const send: UnarySend = async (req) => {
		seen.push(req);
		return { status, body: JSON.stringify(answer) };
	};
	return { send, seen };
}

function bodyOf(req: UnaryRequest): Record<string, unknown> {
	return JSON.parse(new TextDecoder().decode(req.body)) as Record<string, unknown>;
}

async function agentKeys(): Promise<CryptoKeyPair> {
	return (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
		"sign",
		"verify",
	])) as CryptoKeyPair;
}

/** A signed offer plus the raw public key that verifies it. */
async function signedOffer(exchange = "exchange.test") {
	const kp = await agentKeys();
	const publicKey = new Uint8Array(
		await crypto.subtle.exportKey("raw", kp.publicKey),
	) as Uint8Array<ArrayBuffer>;
	const offer: Record<string, unknown> = {
		offer_id: "offer-1",
		exchange,
		expires_at: "2099-01-01T00:00:00Z",
	};
	const signature = await signOffer(offer, kp.privateKey);
	return {
		offer: { ...offer, signature, signature_algorithm: "EdDSA" } as Record<string, unknown>,
		publicKey,
	};
}

describe("discover", () => {
	it("addresses the Connect unary path and stamps the envelope it owns", async () => {
		const { send, seen } = recordingSend({ ver: "1.0", exchange: "exchange.test" });
		const client = createClient("https://exchange.test/", {
			requester: REQUESTER,
			send,
		});

		await client.discover({ exchange: "exchange.test", uris: ["https://site.test/a"] });

		expect(seen[0]?.url).toBe(
			"https://exchange.test/ramp.v1.ExchangeService/DiscoverResources",
		);
		expect(seen[0]?.headers["content-type"]).toBe("application/json");
		expect(seen[0]?.headers["Connect-Protocol-Version"]).toBe("1");
		const body = bodyOf(seen[0] as UnaryRequest);
		expect(body["ver"]).toBe("1.0");
		expect(body["requester"]).toEqual(REQUESTER);
		// The recipient is the caller's to state. A value the transport filled in from
		// the address it was already dialling would restate the dial target, not check it.
		expect(body["exchange"]).toBe("exchange.test");
	});

	it("leaves a value the caller set alone, and does not mutate the caller's message", async () => {
		const { send, seen } = recordingSend({ ver: "1.0", exchange: "exchange.test" });
		const mine = {
			id: "someone-else",
			domain: "other.test",
			type: "REQUESTER_TYPE_AGENT",
		};
		const query: Record<string, unknown> = {
			ver: "9.9",
			exchange: "exchange.test",
			requester: mine,
		};
		const client = createClient("https://exchange.test", { requester: REQUESTER, send });

		await client.discover(query);

		const body = bodyOf(seen[0] as UnaryRequest);
		expect(body["ver"]).toBe("9.9");
		expect(body["requester"]).toEqual(mine);
		expect(query).toEqual({
			ver: "9.9",
			exchange: "exchange.test",
			requester: mine,
		});
	});

	// The rate-limit standing had NO test in this language, which is how the two ports
	// drifted apart on it unnoticed. Every member but one is what the schema decoded — the
	// same two normalizations Go's decode performs, so all three agree — and reset_at is
	// the exception, because it is the one the Python parse cannot return unchanged and so
	// the one both ports take from the wire.
	it("reports the decoded rate limit, and the peer's own spelling of reset_at", async () => {
		const { send } = recordingSend({
			ver: "1.0",
			exchange: "exchange.test",
			rate_limit: {
				// proto3 JSON lets an int32 travel as a string, so this needs no hostile peer.
				limit: "300",
				remaining: 299,
				reset_at: "2099-01-01T00:00:00.123Z",
				vendor_extra: "x",
			},
		});
		const client = createClient("https://exchange.test", { requester: REQUESTER, send });

		const result = await client.discover({ exchange: "exchange.test" });

		expect(result.rateLimit).toBeDefined();
		expect(result.rateLimit?.["limit"], "a string-spelled int32 reached the caller").toBe(
			300,
		);
		expect(result.rateLimit?.["remaining"]).toBe(299);
		expect(
			result.rateLimit,
			"an undeclared member reached the caller",
		).not.toHaveProperty("vendor_extra");
		// Not ".123000Z", and not re-rendered to any other equivalent spelling.
		expect(result.rateLimit?.["reset_at"]).toBe("2099-01-01T00:00:00.123Z");
	});

	it("reports no rate limit when the responder sent none", async () => {
		const { send } = recordingSend({ ver: "1.0", exchange: "exchange.test" });
		const client = createClient("https://exchange.test", { requester: REQUESTER, send });

		expect((await client.discover({ exchange: "exchange.test" })).rateLimit).toBeUndefined();
	});

	it("keeps every requested URI's group and its typed reason", async () => {
		const { offer, publicKey } = await signedOffer();
		const { send } = recordingSend({
			ver: "1.0",
			exchange: "exchange.test",
			offer_groups: [
				{ uri: "https://site.test/a", offers: [offer] },
				{
					uri: "https://site.test/b",
					absence_reason: "OFFER_ABSENCE_REASON_SCOPE_INSUFFICIENT",
				},
			],
		});
		const client = createClient("https://exchange.test", {
			requester: REQUESTER,
			send,
			resolveOfferKey: async () => publicKey,
		});

		const result = await client.discover({ exchange: "exchange.test" });

		expect(result.groups).toHaveLength(2);
		expect(result.groups[0]?.result.verified).toHaveLength(1);
		expect(result.groups[1]?.absenceReason).toBe(
			"OFFER_ABSENCE_REASON_SCOPE_INSUFFICIENT",
		);
		expect(result.exchange).toBe("exchange.test");
	});

	it("reads the grouped and flat lists as alternatives, never both", async () => {
		const { offer, publicKey } = await signedOffer();
		const { send } = recordingSend({
			ver: "1.0",
			exchange: "exchange.test",
			offer_groups: [{ uri: "https://site.test/a", offers: [offer] }],
			offers: [offer], // the same offer, mirrored
		});
		const client = createClient("https://exchange.test", {
			requester: REQUESTER,
			send,
			resolveOfferKey: async () => publicKey,
		});

		const result = await client.discover({ exchange: "exchange.test" });

		expect(result.groups).toHaveLength(1);
		expect(result.groups[0]?.result.verified).toHaveLength(1);
	});

	it("attributes a flat-only answer only when the query named exactly one URI", async () => {
		const { offer, publicKey } = await signedOffer();
		const make = () =>
			createClient("https://exchange.test", {
				requester: REQUESTER,
				send: recordingSend({
					ver: "1.0",
					exchange: "exchange.test",
					offers: [offer],
				}).send,
				resolveOfferKey: async () => publicKey,
			});

		const single = await make().discover({
			exchange: "exchange.test",
			uris: ["https://site.test/a"],
		});
		expect(single.groups[0]?.uri).toBe("https://site.test/a");

		const multi = await make().discover({
			exchange: "exchange.test",
			uris: ["https://site.test/a", "https://site.test/b"],
		});
		// The SDK does not invent an attribution the wire never made.
		expect(multi.groups[0]?.uri).toBe("");
	});

	it("verifies fail-closed: an offer whose key does not resolve is rejected, not dropped", async () => {
		const { offer } = await signedOffer();
		const { send } = recordingSend({
			ver: "1.0",
			exchange: "exchange.test",
			offer_groups: [{ uri: "https://site.test/a", offers: [offer] }],
		});
		const client = createClient("https://exchange.test", { requester: REQUESTER, send });

		const result = await client.discover({ exchange: "exchange.test" });

		expect(result.groups[0]?.result.verified).toEqual([]);
		expect(result.groups[0]?.result.rejected).toHaveLength(1);
	});
});

describe("reading an answer", () => {
	it("refuses a lowerCamelCase body rather than parsing away every multiword field", async () => {
		// What a stock connect-go server serves: no snake_case codec registered. The
		// generated schema would strip offerGroups and answer an empty, successful result.
		const { send } = recordingSend({
			ver: "1.0",
			exchange: "exchange.test",
			offerGroups: [{ uri: "https://site.test/a", offers: [] }],
		});
		const client = createClient("https://exchange.test", { requester: REQUESTER, send });

		const err = await client
			.discover({ exchange: "exchange.test" })
			.catch((e: unknown) => e);

		expect(err).toBeInstanceOf(RampCallError);
		expect((err as RampCallError).kind).toBe("malformed");
		expect((err as RampCallError).reasonOf()).toBe(NOT_CANONICAL_WIRE_NAMING);
	});

	it("turns a Connect error envelope into the typed failure, reason included", async () => {
		const { send } = recordingSend(
			{
				code: "permission_denied",
				message: "balance too low",
				details: [
					{
						type: "ramp.v1.ErrorDetail",
						value: "aWdub3JlZA",
						debug: {
							domain: "ramp.v1.ExchangeService",
							message: "balance too low",
							transactionDenial: { reason: "DENIAL_REASON_INSUFFICIENT_BALANCE" },
						},
					},
				],
			},
			403,
		);
		const client = createClient("https://exchange.test", { requester: REQUESTER, send });

		const err = (await client
			.discover({ exchange: "exchange.test" })
			.catch((e: unknown) => e)) as RampCallError;

		expect(err.kind).toBe("refused");
		expect(err.status).toBe(403);
		expect(err.reasonOf()).toBe("permission_denied");
		expect(err.detail?.transaction_denial?.reason).toBe(
			"DENIAL_REASON_INSUFFICIENT_BALANCE",
		);
	});

	it("classifies a peer that never reached a verdict as unreachable", async () => {
		const { send } = recordingSend({ code: "unavailable", message: "draining" }, 503);
		const client = createClient("https://exchange.test", { requester: REQUESTER, send });

		const err = (await client
			.discover({ exchange: "exchange.test" })
			.catch((e: unknown) => e)) as RampCallError;

		expect(err.kind).toBe("unreachable");
	});

	it("reports a redirect as an answer rather than taking the hop", async () => {
		const { send } = recordingSend({ code: "unknown" }, 302);
		const client = createClient("https://exchange.test", { requester: REQUESTER, send });

		const err = (await client
			.discover({ exchange: "exchange.test" })
			.catch((e: unknown) => e)) as RampCallError;

		// Unreachable, not refused: this client did not follow the hop, so the call never
		// reached a server that could decline it — and a redirect body carries nothing to
		// read as a verdict, even when it happens to look like a Connect envelope.
		expect(err.kind).toBe("unreachable");
		expect(err.status).toBe(302);
	});
});

describe("execute", () => {
	async function verifiedOffer(publicKey: Uint8Array<ArrayBuffer>, offer: unknown) {
		const verifier = createVerifier("strict", {
			resolve: async () => publicKey,
			now: () => Date.parse("2024-01-01T00:00:00Z"),
		});
		const result = await verifier.sort([offer]);
		const first = result.verified[0];
		if (first === undefined) throw new Error(`offer did not verify: ${result.rejected[0]?.reason}`);
		return first;
	}

	it("sends the reflected offer and an acceptance that verifies", async () => {
		const { offer, publicKey } = await signedOffer();
		const accepted = await verifiedOffer(publicKey, offer);
		const keys = await agentKeys();
		const { send, seen } = recordingSend({ ver: "1.0" });
		const client = createClient("https://exchange.test", {
			requester: REQUESTER,
			signer: { privKey: keys.privateKey, keyid: "agent.v1" },
			send,
		});

		await client.execute(accepted, { idempotencyKey: "idem-1" });

		const body = bodyOf(seen[0] as UnaryRequest);
		expect(seen[0]?.url).toBe(
			"https://exchange.test/ramp.v1.ExchangeService/ExecuteTransaction",
		);
		expect(body["idempotency_key"]).toBe("idem-1");
		const items = body["items"] as Array<Record<string, unknown>>;
		expect(items[0]?.["offer"]).toEqual(offer);
		const acceptance = items[0]?.["agent_acceptance"] as Record<string, string>;
		// An Exchange checks this, so a request without a verifying one can only ever be
		// refused — asserting it here is what makes the verb useful rather than merely sent.
		await expect(
			verifyOfferAcceptance(
				{
					offerSig: offer["signature"] as string,
					requesterId: REQUESTER.id,
					requesterDomain: REQUESTER.domain,
					idempotencyKey: "idem-1",
				},
				acceptance["signature"] as string,
				keys.publicKey,
			),
		).resolves.toBe(true);
		// The request-level acceptance travels beside the per-item one. The wire
		// payload must spell exactly what was signed, and the signature must
		// verify the way a receiving Exchange would check it.
		const requestAcceptance = body["agent_request_acceptance"] as Record<string, unknown>;
		expect(requestAcceptance["payload"]).toEqual({
			items: [{ offer_sig: offer["signature"], exchange: "exchange.test" }],
			requester_id: REQUESTER.id,
			requester_domain: REQUESTER.domain,
			idempotency_key: "idem-1",
		});
		expect(requestAcceptance["signature_algorithm"]).toBe("EdDSA");
		await expect(
			verifyRequestAcceptance(
				{
					items: [{ offerSig: offer["signature"] as string, exchange: "exchange.test" }],
					requesterId: REQUESTER.id,
					requesterDomain: REQUESTER.domain,
					idempotencyKey: "idem-1",
				},
				requestAcceptance["signature"] as string,
				keys.publicKey,
			),
		).resolves.toBe(true);
	});

	it("omits the request acceptance when the offer names no exchange", async () => {
		// An offer with no exchange cannot appear in a request-acceptance item
		// (the item requires a recipient), so the client sends the request
		// without the field. A wire-valid offer always names its exchange, so
		// this path is reachable only through verification "off" — surfaced the
		// same way the unsigned-offer test does, with request validation off
		// for the same reason.
		const { offer } = await signedOffer("");
		const verifier = createVerifier("off", {
			resolve: async () => undefined,
			now: () => 0,
		});
		const surfaced = (await verifier.sort([offer])).verified[0];
		const keys = await agentKeys();
		const { send, seen } = recordingSend({ ver: "1.0" });
		const client = createClient("https://exchange.test", {
			requester: REQUESTER,
			signer: { privKey: keys.privateKey, keyid: "agent.v1" },
			send,
			validation: "off",
		});

		await client.execute(surfaced as NonNullable<typeof surfaced>, {
			idempotencyKey: "idem-1",
		});

		expect(bodyOf(seen[0] as UnaryRequest)).not.toHaveProperty("agent_request_acceptance");
	});

	it("mints a fresh idempotency key when none is pinned", async () => {
		const { offer, publicKey } = await signedOffer();
		const accepted = await verifiedOffer(publicKey, offer);
		const keys = await agentKeys();
		const { send, seen } = recordingSend({ ver: "1.0" });
		const client = createClient("https://exchange.test", {
			requester: REQUESTER,
			signer: { privKey: keys.privateKey, keyid: "agent.v1" },
			send,
		});

		await client.execute(accepted);
		await client.execute(accepted);

		const first = bodyOf(seen[0] as UnaryRequest)["idempotency_key"];
		const second = bodyOf(seen[1] as UnaryRequest)["idempotency_key"];
		expect(first).toBeTypeOf("string");
		// A fresh key per call: reusing one would read to the server as a replay of the
		// same purchase, which is a decision only the caller may make.
		expect(first).not.toBe(second);
	});

	it("refuses locally without a requester or a signer", async () => {
		const { offer, publicKey } = await signedOffer();
		const accepted = await verifiedOffer(publicKey, offer);
		const keys = await agentKeys();

		const noRequester = createClient("https://exchange.test", {
			signer: { privKey: keys.privateKey, keyid: "agent.v1" },
			send: recordingSend({}).send,
		});
		await expect(noRequester.execute(accepted)).rejects.toMatchObject({
			kind: "malformed",
		});

		const noSigner = createClient("https://exchange.test", {
			requester: REQUESTER,
			send: recordingSend({}).send,
		});
		await expect(noSigner.execute(accepted)).rejects.toMatchObject({
			kind: "not_signable",
		});
	});

	it("refuses an unsigned offer, which verification-off can still surface", async () => {
		const verifier = createVerifier("off", {
			resolve: async () => undefined,
			now: () => 0,
		});
		const unsigned = (await verifier.sort([{ offer_id: "no-signature" }])).verified[0];
		const keys = await agentKeys();
		const client = createClient("https://exchange.test", {
			requester: REQUESTER,
			signer: { privKey: keys.privateKey, keyid: "agent.v1" },
			send: recordingSend({}).send,
		});

		await expect(
			client.execute(unsigned as NonNullable<typeof unsigned>),
		).rejects.toMatchObject({ kind: "malformed" });
	});
});

describe("the offer-derived leg", () => {
	const resolver = {
		resolveEndpoint: async (host: string) => `https://api.${host}`,
	};

	it("routes a usage report to the Exchange the report itself names", async () => {
		const { send, seen } = recordingSend({ ver: "1.0", report_id: "r-1" });
		const client = createClient("https://home.test", {
			requester: REQUESTER,
			endpointResolver: resolver,
			guardedSend: send,
		});

		await client.reportUsage({ exchange: "issuer.test", transaction_id: "t-1" });

		// Never the configured home Exchange: the destination came off the signed message.
		expect(seen[0]?.url).toBe("https://api.issuer.test/ramp.v1.ExchangeService/ReportUsage");
		const body = bodyOf(seen[0] as UnaryRequest);
		expect(body["ver"]).toBe("1.0");
		expect(body["idempotency_key"]).toBeTypeOf("string");
	});

	it("keeps an idempotency key the caller already put on the message", async () => {
		const { send, seen } = recordingSend({ ver: "1.0" });
		const client = createClient("https://home.test", {
			endpointResolver: resolver,
			guardedSend: send,
		});

		await client.reportUsage({ exchange: "issuer.test", idempotency_key: "mine" });

		// Discarding it would turn each of the caller's retries into a fresh report, which
		// is the double-counting the field exists to prevent.
		expect(bodyOf(seen[0] as UnaryRequest)["idempotency_key"]).toBe("mine");
	});

	it("routes a dispute the same way", async () => {
		const { send, seen } = recordingSend({ ver: "1.0", dispute_id: "d-1" });
		const client = createClient("https://home.test", {
			endpointResolver: resolver,
			guardedSend: send,
		});

		await client.dispute({
			exchange: "issuer.test",
			transaction_id: "t-1",
			report_id: "r-1",
			reason: "DISPUTE_REASON_DELIVERY_FAILED",
		});

		expect(seen[0]?.url).toBe(
			"https://api.issuer.test/ramp.v1.ExchangeService/DisputeTransaction",
		);
	});

	it("refuses to resolve anything but a bare domain, before anything is sent", async () => {
		const { send, seen } = recordingSend({});
		const client = createClient("https://home.test", {
			endpointResolver: resolver,
			guardedSend: send,
		});

		for (const exchange of ["", "issuer.test/path", "https://issuer.test"]) {
			const err = (await client
				.reportUsage({ exchange })
				.catch((e: unknown) => e)) as RampCallError;
			expect(err.kind).toBe("not_sent");
		}
		expect(seen).toHaveLength(0);
	});

	it("tells a resolver's verdict from its transport failure", async () => {
		const verdictClient = createClient("https://home.test", {
			endpointResolver: {
				resolveEndpoint: async () => {
					const { NoEndpoint } = await import("../resolvers/errors.ts");
					throw new NoEndpoint("issuer.test advertises no endpoint");
				},
			},
			guardedSend: recordingSend({}).send,
		});
		await expect(
			verdictClient.reportUsage({ exchange: "issuer.test" }),
		).rejects.toMatchObject({ kind: "not_sent" });

		const flakyClient = createClient("https://home.test", {
			endpointResolver: {
				resolveEndpoint: async () => {
					throw new Error("dial tcp: connection refused");
				},
			},
			guardedSend: recordingSend({}).send,
		});
		// A momentary outage must not read as "we declined to send this, do not retry" —
		// that would permanently drop a usage report.
		await expect(
			flakyClient.reportUsage({ exchange: "issuer.test" }),
		).rejects.toMatchObject({ kind: "unreachable" });
	});
});

describe("the broker face", () => {
	it("refuses locally when no requester is configured", async () => {
		const client = createBrokerClient("https://broker.test", {
			send: recordingSend({}).send,
		});
		await expect(client.resolve({})).rejects.toMatchObject({ kind: "malformed" });
	});

	it("carries the whole-call absence reason as an answer, not a failure", async () => {
		const { send, seen } = recordingSend({
			ver: "1.0",
			absence_reason: "OFFER_ABSENCE_REASON_NOT_IN_CATALOG",
		});
		const client = createBrokerClient("https://broker.test", {
			requester: REQUESTER,
			send,
		});

		const result = await client.resolve({ uris: ["https://site.test/a"] });

		expect(seen[0]?.url).toBe("https://broker.test/ramp.v1.BrokerService/Resolve");
		expect(result.absenceReason).toBe("OFFER_ABSENCE_REASON_NOT_IN_CATALOG");
		expect(result.groups).toEqual([]);
		// A DiscoveryResponse names no single Exchange; each offer carries its own.
		expect(result.exchange).toBe("");
	});
});

describe("outbound validation", () => {
	it("refuses a request the server could only reject, before signing or sending it", async () => {
		const { send, seen } = recordingSend({ ver: "1.0", exchange: "exchange.test" });
		const client = createClient("https://exchange.test", { requester: REQUESTER, send });

		// ResourceQuery.exchange is required: the contract makes every addressed request
		// name its recipient, so a query without one has exactly one possible answer.
		await expect(client.discover({})).rejects.toMatchObject({ kind: "malformed" });
		expect(seen).toHaveLength(0);
	});

	it("sends it anyway when the caller turns validation off", async () => {
		const { send, seen } = recordingSend({ ver: "1.0", exchange: "exchange.test" });
		const client = createClient("https://exchange.test", {
			requester: REQUESTER,
			validation: "off",
			send,
		});

		await client.discover({});

		expect(seen).toHaveLength(1);
	});
});

describe("fetch", () => {
	it("refuses without the signer the delivery URL is bound to", async () => {
		const client = createClient("https://exchange.test", { requester: REQUESTER });
		await expect(client.fetch("https://edge.test/x")).rejects.toMatchObject({
			kind: "not_signable",
		});
	});

	it("refuses without the public half a bound fetch has to present", async () => {
		const keys = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
			"sign",
			"verify",
		])) as CryptoKeyPair;
		const client = createClient("https://exchange.test", {
			requester: REQUESTER,
			signer: { privKey: keys.privateKey, keyid: "agent.v1" },
		});
		await expect(client.fetch("https://edge.test/x")).rejects.toMatchObject({
			kind: "not_signable",
		});
	});

	// The protocol carries ONE agent identity: agent_identity_hash is the thumbprint of
	// the request-signing key and the delivery URL is bound to it, so a proof minted under
	// any other key presents an identity the URL was not issued to and the edge refuses
	// it. This drives a real fetch and reads the key the client actually presented.
	it("proves possession of the SIGNER's key, not a second one", async () => {
		const keys = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
			"sign",
			"verify",
		])) as CryptoKeyPair;
		const raw = new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey));

		let presented: string | undefined;
		const server = createServer((req, res) => {
			presented = req.headers["x-ramp-agent-key"] as string | undefined;
			res.writeHead(200, { "content-type": "text/plain" });
			res.end("body");
		});
		await new Promise<void>((done) => server.listen(0, "127.0.0.1", () => done()));
		const port = (server.address() as { port: number }).port;

		// Loopback and plaintext: the address pin and the scheme gate both refuse them by
		// default, which is the point of the two flags.
		const saved = [process.env["SKIP_SSRF"], process.env["ALLOW_INSECURE"]];
		process.env["SKIP_SSRF"] = "true";
		process.env["ALLOW_INSECURE"] = "true";
		try {
			const client = createClient("https://exchange.test", {
				requester: REQUESTER,
				signer: { privKey: keys.privateKey, keyid: "agent.v1" },
				agentPublicKey: keys.publicKey,
			});
			await client.fetch(`http://127.0.0.1:${port}/x`);
		} finally {
			if (saved[0] === undefined) delete process.env["SKIP_SSRF"];
			else process.env["SKIP_SSRF"] = saved[0];
			if (saved[1] === undefined) delete process.env["ALLOW_INSECURE"];
			else process.env["ALLOW_INSECURE"] = saved[1];
			server.close();
		}

		expect(presented, "no proof header reached the edge").toBeDefined();
		expect(presented).toBe(base64url(raw));
	});
});

/** Unpadded base64url, the encoding the agent-key header carries. */
function base64url(bytes: Uint8Array): string {
	return Buffer.from(bytes).toString("base64url");
}
