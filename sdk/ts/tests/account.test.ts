import { describe, expect, it } from "vitest";

import { createClient, RampCallError } from "../client/index.ts";
import type { UnaryRequest, UnarySend } from "../client/index.ts";
import type { RegistrationRequirements } from "../resolvers/index.ts";

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

const ENDPOINT = "https://exchange.test";
const endpointResolver = { resolveEndpoint: async () => ENDPOINT };

const publishesNothing: RegistrationRequirements = {
  termsDigest: undefined,
  schema: null,
  verdict: "not_published",
};

function client(
  send: UnarySend,
  reqs: RegistrationRequirements | (() => Promise<never>) = publishesNothing,
) {
  return createClient("https://home.invalid", {
    endpointResolver,
    send,
    guardedSend: send,
    registrationRequirements: {
      resolveRegistrationRequirements: async () => {
        if (typeof reqs === "function") return reqs();
        return reqs;
      },
    },
  });
}

describe("register", () => {
  it("addresses the RPC, stamps ver and keeps the caller's recipient", async () => {
    const { send, seen } = recordingSend({ ver: "1.0", billing_ref: "acct-1", active: true });
    const resp = await client(send).register({
      exchange: "exchange.test",
      registration_data: { legal_entity: "Acme" },
    });
    expect(resp.billing_ref).toBe("acct-1");
    const req = seen[0] as UnaryRequest;
    expect(req.url).toBe(`${ENDPOINT}/ramp.v1.ExchangeService/Register`);
    const body = bodyOf(req);
    expect(body["ver"]).toBe("1.0");
    expect(body["exchange"]).toBe("exchange.test");
    // No idempotency key is minted: the message carries none.
    expect(body["idempotency_key"]).toBeUndefined();
  });

  it("echoes the freshly fetched terms digest", async () => {
    const digest = `sha256:${"ab".repeat(32)}`;
    const { send, seen } = recordingSend({ ver: "1.0", billing_ref: "acct-1" });
    await client(send, { ...publishesNothing, termsDigest: digest }).register({
      exchange: "exchange.test",
    });
    expect(bodyOf(seen[0] as UnaryRequest)["terms_digest"]).toBe(digest);
  });

  it("leaves a caller-supplied digest alone", async () => {
    const mine = `sha256:${"cd".repeat(32)}`;
    const { send, seen } = recordingSend({ ver: "1.0", billing_ref: "acct-1" });
    // The reader would throw if it were consulted, which is how this asserts that a
    // caller managing its own requirements suppresses the read.
    await client(send, async () => {
      throw new Error("the requirements read must not happen");
    }).register({ exchange: "exchange.test", terms_digest: mine });
    expect(bodyOf(seen[0] as UnaryRequest)["terms_digest"]).toBe(mine);
  });

  it("refuses an out-of-bounds payload before signing", async () => {
    const tooMany: Record<string, unknown> = {};
    for (let i = 0; i <= 64; i++) tooMany[`m${i}`] = "v";
    const { send, seen } = recordingSend({});
    await expect(
      client(send).register({ exchange: "exchange.test", registration_data: tooMany }),
    ).rejects.toBeInstanceOf(RampCallError);
    expect(seen).toHaveLength(0);
  });

  it("refuses an unaddressed request before signing", async () => {
    const { send, seen } = recordingSend({});
    for (const exchange of ["", "https://exchange.test", "exchange.test/path"]) {
      await expect(client(send).register({ exchange })).rejects.toBeInstanceOf(RampCallError);
    }
    expect(seen).toHaveLength(0);
  });
});

describe("getAccountStatus", () => {
  it("addresses the RPC and reads an accountless answer as a normal one", async () => {
    const { send, seen } = recordingSend({ ver: "1.0", billing_ref: "", active: false });
    const resp = await client(send).getAccountStatus({ exchange: "exchange.test" });
    expect(resp.billing_ref).toBe("");
    expect(resp.active).toBe(false);
    expect((seen[0] as UnaryRequest).url).toBe(
      `${ENDPOINT}/ramp.v1.ExchangeService/GetAccountStatus`,
    );
    expect(bodyOf(seen[0] as UnaryRequest)["ver"]).toBe("1.0");
  });

  it("refuses an unaddressed request before signing", async () => {
    const { send, seen } = recordingSend({});
    await expect(client(send).getAccountStatus({ exchange: "" })).rejects.toBeInstanceOf(
      RampCallError,
    );
    expect(seen).toHaveLength(0);
  });
});

describe("the peer's own sentence", () => {
  it("comes back as a value when the peer sent a typed reason", async () => {
    const { send } = recordingSend(
      {
        code: "failed_precondition",
        message: "envelope prose",
        details: [
          {
            type: "ramp.v1.ErrorDetail",
            debug: {
              domain: "ramp.v1.ExchangeService",
              message: "terms have moved",
              registrationFailure: { reason: "REGISTRATION_FAILURE_REASON_TERMS_DIGEST_STALE" },
            },
          },
        ],
      },
      412,
    );
    const err = await client(send)
      .register({ exchange: "exchange.test" })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(RampCallError);
    expect((err as RampCallError).peerMessage).toBe("terms have moved");
    // The token stays a token: prose never leaks into the field a caller branches on.
    expect((err as RampCallError).reason).not.toContain(" ");
  });

  it("is empty when the answer carried no typed reason", async () => {
    const { send } = recordingSend({ code: "unavailable", message: "draining" }, 503);
    const err = await client(send)
      .getAccountStatus({ exchange: "exchange.test" })
      .catch((e: unknown) => e);
    expect((err as RampCallError).peerMessage).toBe("");
    // The transport's own account is not lost, only kept out of the field that
    // claims to hold the peer's words.
    expect((err as RampCallError).message).toContain("draining");
  });
});
