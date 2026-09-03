import { describe, expect, it } from "vitest";

import {
  createRegistrationRequirementsReader,
  ExchangeNotPermitted,
  ManifestNotExchange,
} from "../resolvers/index.ts";

const SCHEMA = `{"type":"object","required":["legal_entity"],"properties":{"legal_entity":{"type":"string"}}}`;

/** serve builds a fetch that answers one manifest body and counts calls. */
function serve(body: string): { fetch: typeof fetch; hits: () => number } {
  let hits = 0;
  const fetchFn = (async () => {
    hits++;
    return new Response(body, { status: 200, headers: { "content-type": "application/json" } });
  }) as unknown as typeof fetch;
  return { fetch: fetchFn, hits: () => hits };
}

function manifest(extra: Record<string, unknown> = {}, role: unknown = "ROLE_EXCHANGE"): string {
  return JSON.stringify({ role, endpoint: "https://exchange.test", ...extra });
}

const reader = (body: string, allow?: (d: string) => boolean) => {
  const s = serve(body);
  return {
    r: createRegistrationRequirementsReader({
      fetch: s.fetch,
      scheme: "http",
      ...(allow !== undefined ? { allow } : {}),
    }),
    hits: s.hits,
  };
};

describe("the registration-requirements reader", () => {
  it("reads the digest and compiles the published schema", async () => {
    const digest = `sha256:${"ab".repeat(32)}`;
    const { r } = reader(
      manifest({ terms_digest: digest, account_registration: { data_schema: JSON.parse(SCHEMA) } }),
    );
    const got = await r.resolveRegistrationRequirements("exchange.test");
    expect(got.termsDigest).toBe(digest);
    expect(got.verdict).toBe("accepted");
    // The schema is the one that was served, not merely present.
    expect(got.schema?.validate({}).length).toBeGreaterThan(0);
    expect(got.schema?.validate({ legal_entity: "Acme" })).toEqual([]);
  });

  it("fetches afresh on every read", async () => {
    const { r, hits } = reader(manifest({ terms_digest: `sha256:${"ab".repeat(32)}` }));
    await r.resolveRegistrationRequirements("exchange.test");
    await r.resolveRegistrationRequirements("exchange.test");
    expect(hits()).toBe(2);
  });

  it("treats publishing neither member as a normal answer", async () => {
    const { r } = reader(manifest());
    const got = await r.resolveRegistrationRequirements("exchange.test");
    expect(got.termsDigest).toBeUndefined();
    expect(got.schema).toBeNull();
    expect(got.verdict).toBe("not_published");
  });

  it("reports a refused schema as a verdict, never as a throw", async () => {
    const { r } = reader(
      manifest({
        account_registration: {
          data_schema: { $schema: "https://json-schema.org/draft/2019-09/schema", type: "object" },
        },
      }),
    );
    const got = await r.resolveRegistrationRequirements("exchange.test");
    expect(got.verdict).toBe("wrong_dialect");
    expect(got.schema).toBeNull();
  });

  // The cap is defined over the bytes AS SERVED. A schema padded past the cap on
  // the wire that would minify under it must be refused here exactly as the
  // Exchange refuses it, or a client pre-checks against a schema nobody enforces.
  it("measures the schema over the served bytes, not a re-encoding", async () => {
    const padded = `{"type":"object",${" ".repeat(20_000)}"title":"x"}`;
    const body = `{"role":"ROLE_EXCHANGE","account_registration":{"data_schema":${padded}}}`;
    const { r } = reader(body);
    const got = await r.resolveRegistrationRequirements("exchange.test");
    expect(got.verdict).toBe("too_large");
  });

  it("refuses before dialling", async () => {
    const bad = reader(manifest());
    await expect(bad.r.resolveRegistrationRequirements("exchange.test/path")).rejects.toThrow();
    expect(bad.hits()).toBe(0);

    const blocked = reader(manifest(), () => false);
    await expect(blocked.r.resolveRegistrationRequirements("exchange.test")).rejects.toBeInstanceOf(
      ExchangeNotPermitted,
    );
    expect(blocked.hits()).toBe(0);
  });

  it("refuses a manifest that is not an Exchange", async () => {
    for (const body of [
      manifest({}, "ROLE_BROKER"),
      manifest({}, "ROLE_AGENT"),
      manifest({}, "ROLE_PUBLISHER"),
      // No role at all. The contract makes the field required, so reading silence
      // as assent would leave the check advisory.
      `{"endpoint":"https://exchange.test"}`,
    ]) {
      const { r } = reader(body);
      await expect(r.resolveRegistrationRequirements("exchange.test")).rejects.toBeInstanceOf(
        ManifestNotExchange,
      );
    }
  });

  it("accepts the role as a proto-JSON number", async () => {
    const { r } = reader(manifest({}, 2));
    await expect(r.resolveRegistrationRequirements("exchange.test")).resolves.toBeDefined();
  });
});
