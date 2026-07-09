// Transport-WIRING coverage for the SSRF-guarded default transport (guardedFetch).
// The ADDRESS decision is corpus-locked in resolvers-ssrf.parity.test.ts; this
// file proves the non-address wiring the corpus can't express as data: a non-2xx
// is surfaced as a status (not a crash / misclassification), and the transport
// follows NO redirects (so a 3xx to an internal Location is never dialed). Cross-
// language parity: sdk/go TestGuardedWBAClientSurfacesNon2xx / …RefusesRedirect*
// and sdk/python test_guarded_fetch_non_2xx_returns_status_not_crash / …redirect*.
//
// The guard blocks loopback, so — to exercise the wiring against a live in-process
// origin — blockedAddress is mocked to allow every address (the address policy is
// tested elsewhere). allowedScheme stays REAL, so the deny-by-default scheme
// allowlist is still genuinely enforced.
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import { describe, expect, it, vi } from "vitest";

vi.mock("../resolvers/ssrf.ts", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../resolvers/ssrf.ts")>();
  return { ...actual, blockedAddress: () => false };
});

import { DirectoryUnavailable } from "../resolvers/errors.ts";
import { fetchSoft, fetchStrict, guardedFetch } from "../resolvers/http.ts";

async function listen(server: Server): Promise<string> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return `http://127.0.0.1:${port}/.well-known/x`;
}

async function close(server: Server): Promise<void> {
  await new Promise<void>((resolve) => server.close(() => resolve()));
}

describe("guardedFetch transport wiring", () => {
  it("surfaces a non-2xx as a status, and the taxonomy classifies it (no crash)", async () => {
    // Regression parity with Python's opener bug: a non-2xx must not throw an
    // unmapped error. guardedFetch returns the status; fetchStrict maps it to a
    // fail-closed outage; fetchSoft drops the refresh (revocation poller safe).
    const server = createServer((_req, res) => {
      res.writeHead(404);
      res.end("nope");
    });
    const url = await listen(server);
    try {
      const resp = await guardedFetch(url);
      expect(resp.status).toBe(404);
      await expect(fetchStrict(guardedFetch, url)).rejects.toBeInstanceOf(DirectoryUnavailable);
      expect(await fetchSoft(guardedFetch, url)).toBeUndefined();
    } finally {
      await close(server);
    }
  });

  it("follows no redirects — returns the 3xx verbatim, never dialing the Location", async () => {
    // The Location points at cloud-metadata (169.254.169.254). TS's transport uses
    // raw http.request (no auto-follow), so the 302 is returned as-is and the
    // internal target is never contacted — the strongest of the three mechanisms.
    const server = createServer((_req, res) => {
      res.writeHead(302, { location: "http://169.254.169.254/latest/meta-data/" });
      res.end();
    });
    const url = await listen(server);
    try {
      const resp = await guardedFetch(url);
      expect(resp.status).toBe(302); // the redirect itself, not a followed 200
      // The unfollowed 3xx is a non-200, so fetchStrict fails closed without ever
      // dialing the internal Location.
      await expect(fetchStrict(guardedFetch, url)).rejects.toBeInstanceOf(DirectoryUnavailable);
    } finally {
      await close(server);
    }
  });
});
