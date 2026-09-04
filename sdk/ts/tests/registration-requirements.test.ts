import { createServer } from "node:http";
import type { AddressInfo } from "node:net";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  createWellKnownRequirementsReader,
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
    r: createWellKnownRequirementsReader({
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

// The transport default, dialled for real.
//
// The domain this reader fetches comes off a RegisterRequest, so it is chosen by the
// caller at runtime rather than by the operator at start-up. That is the provenance
// that takes the SSRF-guarded transport — the same rule the Go oracle states in the
// options struct these readers mirror, and the same threat shape as the offer-derived
// legs. A reader that dialled a caller-named host unguarded would turn `register` into
// a blind GET aimed wherever that value pointed, and `isBareDomain` accepts `localhost`
// and `169.254.169.254` because they are well-formed domains.
//
// Real-dial rather than a stubbed fetch, mirroring resolvers-ssrf-gate.test.ts: a stub
// would assert which function was referenced, and what matters is which addresses the
// process will actually connect to.
describe("the reader's default transport", () => {
  // Both guards are env-driven, so the flags are cleared here rather than inherited
  // from whatever shell ran the suite — the same isolation resolvers-ssrf-gate.test.ts
  // uses, and without it a developer with SKIP_SSRF set sees this fail for the wrong
  // reason.
  const TOUCHED = ["SKIP_SSRF", "ALLOW_INSECURE", "HTTP_PROXY", "HTTPS_PROXY"];
  let saved: Record<string, string | undefined>;
  beforeEach(() => {
    saved = {};
    for (const k of TOUCHED) {
      saved[k] = process.env[k];
      delete process.env[k];
    }
  });
  afterEach(() => {
    for (const k of TOUCHED) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  });

  it("refuses a loopback origin the injected transport reaches", async () => {
    const server = createServer((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(manifest());
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const { port } = server.address() as AddressInfo;
    const host = `127.0.0.1:${port}`;
    try {
      // The default: no fetch injected, so the guarded transport, which refuses a
      // reserved address at dial time.
      const guarded = createWellKnownRequirementsReader({ scheme: "http" });
      await expect(guarded.resolveRegistrationRequirements(host)).rejects.toThrow();

      // The same host, same server, through an injected transport — so the refusal
      // above is the guard's verdict and not an unreachable server.
      const injected = createWellKnownRequirementsReader({
        scheme: "http",
        fetch: (async (url: string) => {
          const r = await fetch(url);
          return { status: r.status, text: () => r.text() };
        }) as never,
      });
      const got = await injected.resolveRegistrationRequirements(host);
      expect(got.verdict).toBe("not_published");
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});
