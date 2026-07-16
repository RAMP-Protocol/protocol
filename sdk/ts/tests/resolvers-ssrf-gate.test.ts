// Real-dial tests for the ONE env-driven best-effort guarded fetch factory,
// TypeScript side (mirror of the Go reference guardedclient_fromenv_internal_test.go).
//
// The SDK exposes EXACTLY ONE public guarded-fetch construction path —
// guardedFetchFromEnv() — driven by two orthogonal env flags:
//
//   - SKIP_SSRF toggles the dial-time ADDRESS guard (default: on).
//   - ALLOW_INSECURE toggles the SCHEME guard (default: https-only).
//
// The two dimensions are independent, so each pillar sets the OTHER flag to the
// permissive value to isolate the dimension under test. These are the TypeScript
// mirror of the four Go reference pillars, 1:1.
//
// Real-dial ONLY — an in-process 127.0.0.1 server (node:http createServer),
// mirroring resolvers-http-wiring.test.ts.

import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { guardedFetchFromEnv, SsrfBlockedError } from "../resolvers/http.ts";

const ENV_SKIP_SSRF = "SKIP_SSRF";
const ENV_ALLOW_INSECURE = "ALLOW_INSECURE";
const TOUCHED = [ENV_SKIP_SSRF, ENV_ALLOW_INSECURE, "HTTP_PROXY", "HTTPS_PROXY"];

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

async function listen(server: Server): Promise<string> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return `http://127.0.0.1:${port}/`;
}

async function close(server: Server): Promise<void> {
  await new Promise<void>((resolve) => server.close(() => resolve()));
}

function okServer(): Server {
  return createServer((_req, res) => {
    res.writeHead(200);
    res.end("ok");
  });
}

describe("guardedFetchFromEnv (the one env-driven guarded fetch factory)", () => {
  it("guarded fetch blocks loopback by default", async () => {
    // Pillar 1: address guard on (SKIP_SSRF unset); ALLOW_INSECURE set so the http
    // scheme is not the refuser — the ADDRESS guard is isolated.
    process.env[ENV_ALLOW_INSECURE] = "true";
    const server = okServer();
    const url = await listen(server);
    try {
      const fetchFn = guardedFetchFromEnv();
      await expect(fetchFn(url)).rejects.toBeInstanceOf(SsrfBlockedError);
    } finally {
      await close(server);
    }
  });

  it("SKIP_SSRF reaches loopback", async () => {
    // Pillar 2: SKIP_SSRF drops the address guard; ALLOW_INSECURE permits http.
    process.env[ENV_SKIP_SSRF] = "true";
    process.env[ENV_ALLOW_INSECURE] = "true";
    const server = okServer();
    const url = await listen(server);
    try {
      const resp = await guardedFetchFromEnv()(url);
      expect(resp.status).toBe(200);
    } finally {
      await close(server);
    }
  });

  it("refuses http by default", async () => {
    // Pillar 3: ALLOW_INSECURE unset → https-only refuses http for scheme;
    // SKIP_SSRF set so the address guard cannot be the refuser.
    process.env[ENV_SKIP_SSRF] = "true";
    const server = okServer();
    const url = await listen(server); // http://127.0.0.1:<port>/
    try {
      const fetchFn = guardedFetchFromEnv();
      await expect(fetchFn(url)).rejects.toBeInstanceOf(SsrfBlockedError);
      await expect(fetchFn(url)).rejects.toThrow(/scheme|https/i);
    } finally {
      await close(server);
    }
  });

  it("ALLOW_INSECURE permits http", async () => {
    // Pillar 4: ALLOW_INSECURE permits the http scheme; SKIP_SSRF set so the
    // address guard is out of the way.
    process.env[ENV_SKIP_SSRF] = "true";
    process.env[ENV_ALLOW_INSECURE] = "true";
    const server = okServer();
    const url = await listen(server);
    try {
      const resp = await guardedFetchFromEnv()(url);
      expect(resp.status).toBe(200);
    } finally {
      await close(server);
    }
  });

  it("a set HTTP(S)_PROXY does not tunnel a loopback target past the guard", async () => {
    // Mirror of Go TestGuardedClientNoProxyTunnel: address guard on + proxy set;
    // ALLOW_INSECURE set so the http scheme reaches the transport and the
    // address/proxy dimension is isolated.
    process.env[ENV_ALLOW_INSECURE] = "true";
    process.env.HTTP_PROXY = "http://127.0.0.1:9";
    process.env.HTTPS_PROXY = "http://127.0.0.1:9";
    const server = okServer();
    const url = await listen(server);
    try {
      const fetchFn = guardedFetchFromEnv();
      await expect(fetchFn(url)).rejects.toBeInstanceOf(SsrfBlockedError);
    } finally {
      await close(server);
    }
  });
});
