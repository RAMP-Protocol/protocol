// Content-leg parity (TypeScript side) — replay of the shared Go-oracle corpus.
//
// Mirrors the sdk/python sibling test_content_fetch_parity.py and the Go leg
// sdk/go/resolvers/content_fetch_corpus_test.go.
//
// The delivery fetch is the one leg where the peer's own words are promoted over the
// SDK's classification: an edge that refuses a bound GET answers a small JSON object, and
// the token in it becomes the reason a caller branches on. Three things therefore have to
// agree across the languages — which answers are a refusal, which tokens the SDK is
// willing to repeat, and what a Content-Type reduces to — and none of them is obvious
// from reading one side alone.
//
// Go folds this leg into its own FetchError; TypeScript and Python fold it into the
// client's RampCallError, so a caller branches on one failure type for every verb. The
// projection the corpus records is the same either way, which is what makes the fold a
// spelling difference rather than a divergence.
import { describe, expect, it } from "vitest";
import { MockAgent, setGlobalDispatcher } from "undici";

import { fetchContent, mimeTypeOf } from "../client/content.ts";
import type { CallErrorKind } from "../client/errors.ts";
import { RampCallError } from "../client/errors.ts";
import vectorsFile from "../../go/resolvers/testdata/content-fetch-vectors.json";

type ContentFetchVector = {
	name: string;
	status: number;
	body: string;
	content_type: string;
	ok: boolean;
	failure: string;
	reason: string;
	reason_of: string;
	mime_type: string;
};
const vectors = (vectorsFile as { vectors: ContentFetchVector[] }).vectors;

// The Go failure classes this leg produces, and the shared kind each is spelled as.
const FAILURE_KINDS: Record<string, CallErrorKind> = {
	refused: "refused",
	unreachable: "unreachable",
	too_large: "too_large",
	not_signable: "not_signable",
	malformed: "malformed",
};

const ORIGIN = "https://edge.test";
const PATH = "/asset";

async function agentKeys(): Promise<CryptoKeyPair> {
	return (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
		"sign",
		"verify",
	])) as CryptoKeyPair;
}

describe("sdk/ts reads a delivery answer the way the sdk/go oracle does", () => {
	it("content-fetch vector set is non-empty", () => {
		expect(vectors.length).toBeGreaterThan(0);
	});

	for (const v of vectors) {
		it(`extracts the Go projection: ${v.name}`, async () => {
			// An intercepted dispatcher rather than a socket: what is under test is the
			// READING of an answer, and the address rule has its own corpus.
			const agent = new MockAgent();
			agent.disableNetConnect();
			setGlobalDispatcher(agent);
			agent
				.get(ORIGIN)
				.intercept({ path: PATH, method: "GET" })
				.reply(v.status, v.body, {
					headers: v.content_type !== "" ? { "content-type": v.content_type } : {},
				});

			const call = fetchContent(`${ORIGIN}${PATH}`, {
				keyPair: await agentKeys(),
				dispatcher: agent,
			});

			if (v.ok) {
				const content = await call;
				expect(new TextDecoder().decode(content.body)).toBe(v.body);
				// The charset belongs to whoever decodes the bytes; the content carries
				// the media type alone, and a header with no usable one is labelled
				// rather than sniffed.
				expect(content.mimeType).toBe(v.mime_type);
				return;
			}

			const err = (await call.catch((e: unknown) => e)) as RampCallError;
			expect(err).toBeInstanceOf(RampCallError);
			expect(err.kind).toBe(FAILURE_KINDS[v.failure]);
			// The empty token is the SDK declining to repeat what the publisher wrote.
			expect(err.reason ?? "").toBe(v.reason);
			expect(err.reasonOf()).toBe(v.reason_of);
		});
	}

	// The media-type rule, exercised directly as well as through a fetch: it is the one
	// part of this leg a caller can reach without a socket, and the corpus's own edges are
	// what made it worth stating rather than delegating to a parser.
	it("reduces a Content-Type by the stated rule", () => {
		for (const v of vectors.filter((x) => x.ok)) {
			expect(mimeTypeOf(v.content_type === "" ? undefined : v.content_type)).toBe(
				v.mime_type,
			);
		}
	});
});
