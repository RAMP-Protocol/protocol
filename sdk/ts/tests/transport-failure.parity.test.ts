// Transport-failure parity (TypeScript side) — replay of the shared Go-oracle corpus.
//
// Mirrors sdk/python/tests/test_transport_failure_parity.py and the Go leg
// sdk/go/connect/transport_failure_corpus_test.go.
//
// The connect-error corpus records what a RAMP SERVICE says when it refuses. This one
// records the other half: what reaches a client when the answer did not come from the
// service at all — a load balancer draining, a gateway with no upstream, a proxy returning
// its own HTML page. None of those is a Connect envelope.
//
// The distinction is the point. "The Exchange declined this" is final; "nothing answered"
// is transient. Report a momentary 502 as a refusal and a caller stops retrying a usage
// report that would have succeeded a second later — the outcome route.ts argues at length
// must not happen. connect-go already decides this by deriving the code from the HTTP
// status, and the corpus is captured from a real client rather than transcribing that
// table.
import { describe, expect, it } from "vitest";

import { RampCallError } from "../client/errors.ts";
import { decodeResponse } from "../client/transport.ts";
import vectorsFile from "../../go/connect/testdata/transport-failure-vectors.json";

type TransportFailureVector = {
	name: string;
	status: number;
	body: string;
	content_type: string;
	kind: string;
	reason: string;
	retryable: boolean;
};
const vectors = (vectorsFile as { transport_failures: TransportFailureVector[] })
	.transport_failures;

describe("an answer that did not come from the service", () => {
	it("covers both sides of the distinction", () => {
		expect(vectors.length).toBeGreaterThan(0);
		expect(vectors.some((v) => v.kind === "unreachable")).toBe(true);
		expect(vectors.some((v) => v.kind !== "unreachable")).toBe(true);
	});

	for (const v of vectors) {
		it(`${v.name}: ${v.status} is ${v.kind}`, () => {
			let thrown: unknown;
			try {
				decodeResponse("discover", { status: v.status, body: v.body });
			} catch (e) {
				thrown = e;
			}
			expect(thrown).toBeInstanceOf(RampCallError);
			const failure = thrown as RampCallError;
			expect(failure.kind, `${v.name}: oracle says ${v.kind}`).toBe(v.kind);
			expect(failure.reason).toBe(v.reason);
			// The label and the consequence are pinned together: comparing only the string
			// would still pass if the two classes swapped meanings.
			expect(failure.kind === "unreachable").toBe(v.retryable);
		});
	}
});
