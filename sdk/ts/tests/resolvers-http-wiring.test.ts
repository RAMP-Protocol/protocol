// Transport-WIRING coverage for the SSRF-guarded default transport (guardedFetch).
// The ADDRESS decision is corpus-locked in resolvers-ssrf.parity.test.ts; this
// file proves the non-address wiring the corpus can't express as data: a non-2xx
// is surfaced as a status (not a crash / misclassification), and — now that the
// transport runs on undici — every REDIRECT hop is re-vetted through the same
// guarded connector (a redirect to an internal address is refused mid-chain, and
// a redirect into a non-http(s) scheme is refused deny-by-default). Cross-language
// parity: sdk/go TestGuardedWBAClientSurfacesNon2xx / …RefusesRedirect* and sdk/
// python test_guarded_client_non_2xx… / …refuses_redirect_to_{ftp,internal}.
//
// The guard blocks loopback, so — to exercise the wiring against a live in-process
// origin — blockedAddress is mocked (a reconfigurable spy). allowedScheme stays
// REAL, so the deny-by-default scheme allowlist is still genuinely enforced.
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import { beforeEach, describe, expect, it, vi } from "vitest";

const { blockedAddressMock } = vi.hoisted(() => ({
  blockedAddressMock: vi.fn((_ip: string) => false),
}));

vi.mock("../resolvers/ssrf.ts", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../resolvers/ssrf.ts")>();
  return { ...actual, blockedAddress: (ip: string) => blockedAddressMock(ip) };
});

import { DirectoryUnavailable } from "../resolvers/errors.ts";
import { fetchSoft, fetchStrict, guardedFetch, SsrfBlockedError } from "../resolvers/http.ts";

async function listen(server: Server): Promise<string> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return `http://127.0.0.1:${port}/.well-known/x`;
}

async function close(server: Server): Promise<void> {
  await new Promise<void>((resolve) => server.close(() => resolve()));
}

beforeEach(() => {
  blockedAddressMock.mockReset();
  blockedAddressMock.mockImplementation(() => false); // allow the loopback origin
});

describe("guardedFetch transport wiring", () => {
  it("surfaces a non-2xx as a status, and the taxonomy classifies it (no crash)", async () => {
    // Regression parity with Python's opener bug: a non-2xx must not throw an
    // unmapped error. undici owns the status machine, so guardedFetch returns the
    // status; fetchStrict maps it to a fail-closed outage; fetchSoft drops the
    // refresh (revocation poller safe).
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

  it("re-vets every redirect hop — a 302 to an internal address is refused mid-chain", async () => {
    // Allow the loopback origin but block ONLY 169.254/16, so the refusal can only
    // come from re-checking the redirect target: undici follows the 302 and
    // re-dials 169.254.169.254 through the SAME guarded connector, which refuses
    // the IMDS hop. Proves the rebinding window is closed on the redirect host too.
    blockedAddressMock.mockImplementation((ip: string) => ip.startsWith("169.254"));
    const server = createServer((_req, res) => {
      res.writeHead(302, { location: "http://169.254.169.254/latest/meta-data/" });
      res.end();
    });
    const url = await listen(server);
    try {
      await expect(guardedFetch(url)).rejects.toBeInstanceOf(SsrfBlockedError);
      await expect(fetchStrict(guardedFetch, url)).rejects.toBeInstanceOf(DirectoryUnavailable);
    } finally {
      await close(server);
    }
  });

  it("refuses a redirect into a non-http(s) scheme (deny-by-default)", async () => {
    // undici has no transport for ftp/telnet/gopher/…, so following such a redirect
    // is a WHATWG-fetch network error — the maintained-client form of the scheme
    // allowlist, no hand-rolled redirect handler. The ftp target is never dialed.
    const server = createServer((_req, res) => {
      res.writeHead(302, { location: "ftp://ftp.example.com/secret" });
      res.end();
    });
    const url = await listen(server);
    try {
      await expect(fetchStrict(guardedFetch, url)).rejects.toBeInstanceOf(DirectoryUnavailable);
    } finally {
      await close(server);
    }
  });
});
