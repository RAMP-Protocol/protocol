// The details this SDK BUILDS rather than receives, replayed against the Go oracle.
//
// Decoding a peer's ErrorDetail is already pinned elsewhere. These two are different:
// nothing on the wire says what they should contain, so the domain, the sentence and the
// typed reason are AUTHORED — three times, in three languages, from three copies of one
// decision. That is the shape that drifts silently, and it had: this port derived each
// edge reason's enum name by uppercasing the token, which is right for two of the eleven
// tokens the protocol records and wrong for the rest.
//
// Field errors are compared by PATH and never by text. The constraint prose comes from a
// different validator library in each language and the contract calls it
// non-authoritative, so pinning it here would pin an accident.
import { createServer } from "node:http";
import { describe, expect, it } from "vitest";

import { createClient, RampCallError } from "../client/index.ts";
import type { UnaryRequest, UnarySend } from "../client/index.ts";
import type { RegistrationRequirements } from "../resolvers/index.ts";
import { REASON_FIELDS, reason } from "../src/errordetail.ts";
import { compileRegistrationSchema } from "../src/regschema.ts";
import vectorsFile from "../../go/connect/testdata/synthesized-detail-vectors.json";

interface PrecheckVector {
	name: string;
	schema: string;
	data: Record<string, unknown>;
	domain: string;
	message: string;
	reason_field: string;
	reason_enum: string;
	field_error_paths: string[];
}

interface EdgeRefusalVector {
	name: string;
	reason_token: string;
	domain: string;
	message: string;
	reason_field: string;
	reason_enum: string;
}

const { registration_precheck: precheckVectors, edge_refusal: edgeVectors } =
	vectorsFile as unknown as {
		registration_precheck: PrecheckVector[];
		edge_refusal: EdgeRefusalVector[];
	};

const ENDPOINT = "https://exchange.test";

function noSend(): UnarySend {
	return async (_req: UnaryRequest) => {
		throw new Error("the pre-check refusal must never reach the wire");
	};
}

/** Assert the detail on `err` matches what the oracle recorded for `v`. */
function expectsRecordedDetail(
	err: RampCallError,
	v: { domain: string; message: string; reason_field: string; reason_enum: string },
): void {
	expect(err.detail).toBeDefined();
	const detail = err.detail as NonNullable<typeof err.detail>;
	expect(detail.domain ?? "").toBe(v.domain);
	expect(detail.message ?? "").toBe(v.message);
	// Exactly the recorded oneof member is populated, and only it.
	const record = detail as unknown as Record<string, unknown>;
	expect(REASON_FIELDS.filter((f) => record[f] != null)).toEqual([v.reason_field]);
	const got = reason(detail);
	expect(got?.field).toBe(v.reason_field);
	expect(got?.value).toBe(v.reason_enum);
}

describe("the registration pre-check's synthesized detail", () => {
	for (const v of precheckVectors) {
		it(v.name, async () => {
			const { schema, verdict } = compileRegistrationSchema(v.schema);
			expect(verdict, "the row's own schema does not compile").toBe("accepted");
			const requirements: RegistrationRequirements = {
				termsDigest: undefined,
				schema,
				verdict,
			};
			const client = createClient("https://home.invalid", {
				endpointResolver: { resolveEndpoint: async () => ENDPOINT },
				send: noSend(),
				guardedSend: noSend(),
				registrationRequirements: {
					resolveRegistrationRequirements: async () => requirements,
				},
			});

			const err = (await client
				.register({ exchange: "exchange.test", registration_data: v.data })
				.catch((e: unknown) => e)) as RampCallError;

			expect(err).toBeInstanceOf(RampCallError);
			expect(err.kind).toBe("malformed");
			expectsRecordedDetail(err, v);
			const paths = (err.detail?.registration_failure?.field_errors ?? []).map(
				(f) => f.path ?? "",
			);
			expect(paths).toEqual(v.field_error_paths);
		});
	}
});

describe("the content leg's synthesized detail", () => {
	/** One loopback edge that refuses with whatever token the path asks for. A real
	 * socket, because this port has no seam to inject the content fetch through — the
	 * guard and the scheme gate both refuse loopback and plaintext by default, which is
	 * what the two flags are for. */
	async function refusedByTheEdge(token: string): Promise<RampCallError> {
		const server = createServer((_req, res) => {
			res.writeHead(403, { "content-type": "application/json" });
			res.end(JSON.stringify({ error: "denied", reason: token }));
		});
		await new Promise<void>((done) => server.listen(0, "127.0.0.1", () => done()));
		const port = (server.address() as { port: number }).port;

		const saved = [process.env["SKIP_SSRF"], process.env["ALLOW_INSECURE"]];
		process.env["SKIP_SSRF"] = "true";
		process.env["ALLOW_INSECURE"] = "true";
		try {
			const keys = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
				"sign",
				"verify",
			])) as CryptoKeyPair;
			const client = createClient("https://exchange.test", {
				signer: { privKey: keys.privateKey, keyid: "agent.v1" },
				agentPublicKey: keys.publicKey,
			});
			return (await client
				.fetch(`http://127.0.0.1:${port}/doc`)
				.catch((e: unknown) => e)) as RampCallError;
		} finally {
			if (saved[0] === undefined) delete process.env["SKIP_SSRF"];
			else process.env["SKIP_SSRF"] = saved[0];
			if (saved[1] === undefined) delete process.env["ALLOW_INSECURE"];
			else process.env["ALLOW_INSECURE"] = saved[1];
			server.close();
		}
	}

	for (const v of edgeVectors) {
		it(v.name, async () => {
			const err = await refusedByTheEdge(v.reason_token);

			expect(err).toBeInstanceOf(RampCallError);
			// The raw token reaches the caller either way; only the typed reason is at
			// stake, so a row that records none must still carry the refusal.
			expect(err.reasonOf()).toBe(v.reason_token);

			if (v.reason_field === "") {
				// The protocol records no reason for this token, or records two and so
				// cannot say which check ran. Promoting one would attribute a failure the
				// wire never attributed.
				expect(err.detail).toBeUndefined();
				return;
			}
			expectsRecordedDetail(err, v);
		});
	}
});
