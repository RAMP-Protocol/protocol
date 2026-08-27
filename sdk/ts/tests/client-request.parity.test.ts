// Client-request parity (TypeScript side) — replay of the shared Go-oracle corpus.
//
// Mirrors the sdk/python sibling test_client_request_parity.py and the Go leg
// sdk/go/connect/client_request_corpus_test.go.
//
// "The same verbs, with the same names" is the whole claim the three clients make to each
// other, and neither half of it is visible from the exported surface the parity map
// compares. A client can export `reportUsage` and address the wrong RPC — a Connect unary
// path is `/<fully-qualified service>/<method>`, so a different method name reaches a
// different endpoint, or none. And it can overwrite an idempotency key the caller
// supplied, which turns each of their retries into a second report; the key identifies
// the ACTION, not the attempt.
//
// The body's BYTES are deliberately not pinned. Go serializes through protojson and this
// client builds the object directly, so the same message legitimately renders
// differently. What the corpus records is the envelope PROJECTION, which is the part that
// is a decision rather than an encoding.
import { describe, expect, it } from "vitest";

import {
	createBrokerClient,
	createCatalogClient,
	createClient,
	type UnaryRequest,
	type UnarySend,
} from "../client/index.ts";
import { createVerifier, type VerifiedOffer } from "../core/verifier.ts";
import { validateIdempotencyKey } from "../src/idempotency.ts";
import { signOffer } from "../src/offer-sign.ts";
import vectorsFile from "../../go/connect/testdata/client-request-vectors.json";

type ClientRequestVector = {
	name: string;
	verb: string;
	path: string;
	ver: string;
	idempotency_key: string;
	key_minted: boolean;
	requester_id: string;
};
const vectors = (vectorsFile as { vectors: ClientRequestVector[] }).vectors;

const REQUESTER = { id: "agent-1", domain: "agent.test", type: "REQUESTER_TYPE_AGENT" };
const ISSUER = "issuer.test";
/** The one key the corpus records verbatim; a minted key is fresh per call. */
const PINNED = "idem-pinned-1";

function capture(): { send: UnarySend; seen: UnaryRequest[] } {
	const seen: UnaryRequest[] = [];
	return {
		seen,
		send: async (req) => {
			seen.push(req);
			return {
				status: 200,
				body: JSON.stringify({ ver: "1.0", exchange: "exchange.test" }),
			};
		},
	};
}

async function agentKeys(): Promise<CryptoKeyPair> {
	return (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
		"sign",
		"verify",
	])) as CryptoKeyPair;
}

async function verifiedOffer(): Promise<VerifiedOffer> {
	const kp = await agentKeys();
	const publicKey = new Uint8Array(
		await crypto.subtle.exportKey("raw", kp.publicKey),
	) as Uint8Array<ArrayBuffer>;
	const offer: Record<string, unknown> = {
		offer_id: "offer-good",
		exchange: "exchange.test",
		expires_at: "2099-01-01T00:00:00Z",
	};
	const signature = await signOffer(offer, kp.privateKey);
	const signed = { ...offer, signature, signature_algorithm: "EdDSA" };
	const sorted = await createVerifier("strict", {
		resolve: async () => publicKey,
		now: () => Date.parse("2024-01-01T00:00:00Z"),
	}).sort([signed]);
	const first = sorted.verified[0];
	if (first === undefined) {
		throw new Error(`fixture offer did not verify: ${sorted.rejected[0]?.reason}`);
	}
	return first;
}

const endpointResolver = { resolveEndpoint: async (host: string) => `https://api.${host}` };

/** Run the verb a vector names and return what went on the wire. */
async function call(name: string): Promise<UnaryRequest> {
	const { send, seen } = capture();
	const keys = await agentKeys();
	const options = {
		requester: REQUESTER,
		signer: { privKey: keys.privateKey, keyid: "agent.v1" },
		agentPublicKey: keys.publicKey,
		endpointResolver,
		send,
		guardedSend: send,
	};
	const client = createClient("https://exchange.test", options);

	if (name.startsWith("discover")) {
		const query: Record<string, unknown> = { exchange: "exchange.test" };
		if (name === "discover_caller_ver_wins") query["ver"] = "9.9";
		await client.discover(query);
	} else if (name.startsWith("report_usage")) {
		const report: Record<string, unknown> = { exchange: ISSUER, transaction_id: "t-1" };
		if (name === "report_usage_caller_key_wins") report["idempotency_key"] = PINNED;
		await client.reportUsage(report);
	} else if (name.startsWith("dispute")) {
		await client.dispute(
			{
				exchange: ISSUER,
				transaction_id: "t-1",
				report_id: "r-1",
				reason: "DISPUTE_REASON_DELIVERY_FAILED",
			},
			{ idempotencyKey: PINNED },
		);
	} else if (name.startsWith("execute")) {
		await client.execute(await verifiedOffer(), { idempotencyKey: PINNED });
	} else if (name === "resolve") {
		await createBrokerClient("https://broker.test", options).resolve({});
	} else if (name === "push_resources") {
		await createCatalogClient("https://exchange.test", options).pushResources({
			exchange: "exchange.test",
			tenant_id: "tenant-1",
			caller_id: "publisher.test",
			entries: [
				{
					domain: "publisher.test",
					path: "/x",
					terms: [
						{
							semantics: "TERM_SEMANTICS_ENUMERATED",
							pricing: { model: "PRICING_MODEL_FREE", rate: "0" },
						},
					],
				},
			],
		});
	} else if (name === "remove_resources") {
		await createCatalogClient("https://exchange.test", options).removeResources({
			exchange: "exchange.test",
			tenant_id: "tenant-1",
			paths: ["/x"],
		});
	} else if (name === "refresh_catalog") {
		await createCatalogClient("https://exchange.test", options).refreshCatalog({
			exchange: "exchange.test",
			tenant_id: "tenant-1",
		});
	} else {
		throw new Error(`no TypeScript driver for vector ${name}`);
	}
	const first = seen[0];
	if (first === undefined) throw new Error(`${name} sent nothing`);
	return first;
}

describe("sdk/ts addresses the same RPCs and stamps the same envelope as the oracle", () => {
	it("client-request vector set is non-empty", () => {
		expect(vectors.length).toBeGreaterThan(0);
	});

	for (const v of vectors) {
		it(`${v.verb}: ${v.name}`, async () => {
			const request = await call(v.name);
			const body = JSON.parse(new TextDecoder().decode(request.body)) as Record<
				string,
				unknown
			>;

			// A different method name reaches a different RPC, or none.
			expect(new URL(request.url).pathname).toBe(v.path);
			expect(body["ver"]).toBe(v.ver);
			expect(((body["requester"] as { id?: string }) ?? {}).id ?? "").toBe(
				v.requester_id,
			);

			const key = (body["idempotency_key"] as string) ?? "";
			if (v.key_minted) {
				// A minted key's VALUE is fresh per call and so is not recorded; what the
				// corpus pins is that one was minted, and it must be a key the protocol
				// accepts.
				expect(key).not.toBe("");
				expect(() => validateIdempotencyKey(key)).not.toThrow();
				return;
			}
			expect(key).toBe(v.idempotency_key);
		});
	}
});
