import assert from "node:assert/strict";
import { afterEach, beforeEach, mock, test } from "node:test";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { buildToolContext } from "../src/config.js";
import { allTools } from "../src/protocol/tools.js";
import { checkReadiness } from "../src/meta/readiness.js";
import { vulnersSearch, vulnersId, vulnersExploit } from "../src/vulners/index.js";
import { RateLimiter } from "../src/utils/rate-limiter.js";
import { apiFetch } from "../src/utils/http.js";
import { btcAbuseCheck } from "../src/blockchain/index.js";
import { abuseipdbCheck } from "../src/abuseipdb/index.js";
import { otxDomain } from "../src/otx/index.js";
import { phishingCheck } from "../src/phishing/index.js";
import { pulsediveIndicator } from "../src/pulsedive/index.js";
import { abusechTools } from "../src/abusech/index.js";
import net from "node:net";
import { checkTorStatus } from "../src/utils/tor-fetch.js";

beforeEach(() => {
  mock.method(RateLimiter.prototype, "acquire", async () => {});
  mock.method(globalThis, "fetch", async () => { throw new Error("Unexpected provider network request"); });
});
afterEach(() => mock.restoreAll());

test("Vulners uses POST header authentication and flattens official search hits", async () => {
  mock.method(globalThis, "fetch", async (input: string, init: RequestInit) => {
    assert.equal(String(input), "https://vulners.com/api/v3/search/lucene/");
    assert.equal(init.method, "POST");
    assert.equal(new Headers(init.headers).get("X-Api-Key"), "fixture-search-key");
    assert.deepEqual(JSON.parse(String(init.body)).query, "release-test-query");
    return Response.json({ result: "OK", data: { search: [{ _id: "source-id", _source: { id: "CVE-2025-0001", title: "Fixture" } }], total: 4 } });
  });
  const value = await vulnersSearch("release-test-query", 2, "fixture-search-key");
  assert.equal(value.data.search[0]?.id, "CVE-2025-0001");
  assert.equal(value.complete, false);
  assert.equal(value.data.total, 4);
});

test("Vulners document lookups send an ID array and suppress external references", async () => {
  mock.method(globalThis, "fetch", async (input: string, init: RequestInit) => {
    assert.equal(String(input), "https://vulners.com/api/v3/search/id/");
    const body = JSON.parse(String(init.body));
    assert.deepEqual(body.id, ["CVE-2025-0002"]);
    assert.equal(body.references, false);
    return Response.json({ result: "OK", data: { documents: { "CVE-2025-0002": { id: "CVE-2025-0002" } }, references: { ignored: "large content" } } });
  });
  const value = await vulnersId("CVE-2025-0002", "fixture-id-key");
  assert.ok(value.data.documents["CVE-2025-0002"]);
  assert.deepEqual(value.data.references, {});
});

test("Vulners exploit queries include the entire exploit family", async () => {
  mock.method(globalThis, "fetch", async (_input: string, init: RequestInit) => {
    assert.equal(JSON.parse(String(init.body)).query, 'bulletinFamily:exploit AND "CVE-2025-0003"');
    return Response.json({ result: "OK", data: { search: [], total: 0 } });
  });
  assert.equal((await vulnersExploit("cve-2025-0003", 5, "fixture-exploit-key")).complete, true);
});

test("Vulners never treats malformed or unsuccessful envelopes as negative results", async () => {
  for (const [index, payload] of [{ result: "ERROR", data: {} }, { result: "OK", data: { error: "denied" } }, { result: "OK", data: {} }, { result: "OK", data: { search: ["invalid"] } }].entries()) {
    mock.method(globalThis, "fetch", async () => Response.json(payload));
    await assert.rejects(vulnersSearch("invalid-envelope-" + index, 5, "fixture-invalid-key"), /Vulners/);
  }
});

test("Vulners authenticated caches cannot bypass missing or different keys", async () => {
  let calls = 0;
  mock.method(globalThis, "fetch", async () => { calls++; return Response.json({ result: "OK", data: { search: [], total: 0 } }); });
  await vulnersSearch("cache-scope-release", 5, "fixture-key-one");
  await vulnersSearch("cache-scope-release", 5, "fixture-key-one");
  await assert.rejects(vulnersSearch("cache-scope-release", 5), /VULNERS_API_KEY/);
  await vulnersSearch("cache-scope-release", 5, "fixture-key-two");
  assert.equal(calls, 2);
});

test("readiness tests configuration and local SOCKS without querying providers", async () => {
  const context = buildToolContext({ HIBP_API_KEY: "  fixture-key  ", VULNERS_API_KEY: " ", RANSOMWARELIVE_API_KEY: "fixture-pro-key" });
  const value = await checkReadiness(context, allTools, async (host, port) => ({ socksAvailable: false, socksHost: host!, socksPort: port! }));
  assert.equal(context.config.hibpApiKey, "fixture-key");
  assert.equal(value.summary.live_verified, false);
  assert.equal(value.checks.find(check => check.name === "Vulners")?.configuration_status, "missing_key");
  assert.equal(value.checks.find(check => check.name === "Have I Been Pwned")?.health_status, "not_checked");
  assert.equal(value.checks.find(check => check.name === "Ransomware.live")?.configuration_status, "configured");
  assert.equal(value.checks.find(check => check.name === "Tor Network")?.health_status, "unavailable");
  assert.doesNotMatch(JSON.stringify(value), /fixture-key|fixture-pro-key/);
});

test("SOCKS handshake readiness does not claim provider or onion health", async () => {
  const value = await checkReadiness(buildToolContext({}), allTools, async (host, port) => ({ socksAvailable: true, socksHost: host!, socksPort: port! }));
  const tor = value.checks.find(check => check.name === "Tor Network")!;
  assert.equal(tor.health_status, "reachable");
  assert.match(tor.detail, /Onion reachability is still unverified/);
  assert.equal(value.summary.live_verified, false);
});

test("doctor CLI emits a readiness report without entering MCP stdio", () => {
  const entrypoint = fileURLToPath(new URL("../src/index.js", import.meta.url));
  const result = spawnSync(process.execPath, [entrypoint, "--doctor"], { encoding: "utf8", timeout: 8000, env: { ...process.env, TOR_SOCKS_HOST: "127.0.0.1", TOR_SOCKS_PORT: "65534" } });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).summary.live_verified, false);
  assert.doesNotMatch(result.stderr, /started on stdio/);
});

test("cancelled provider spacing releases the waiting timer immediately", async () => {
  mock.restoreAll();
  const limiter = new RateLimiter(60_000);
  await limiter.acquire();
  const cancel = new AbortController();
  const queued = limiter.acquire(cancel.signal);
  cancel.abort(new Error("cancelled"));
  await assert.rejects(queued, /cancelled/);
  await new Promise(resolve => setTimeout(resolve, 0));
  assert.equal((limiter as unknown as { processing: boolean; wake?: () => void }).processing, false);
  assert.equal((limiter as unknown as { wake?: () => void }).wake, undefined);
});

test("HTTP refuses provider redirects before credentials can cross origins", async () => {
  mock.method(globalThis, "fetch", async (_input: string, init: RequestInit) => {
    assert.equal(init.redirect, "error");
    return Response.json({ ok: true });
  });
  await apiFetch("https://provider.test", { headers: { "X-Api-Key": "fixture" }, redirect: "follow" });
});

test("provider error bodies never expose echoed Basic credentials", async () => {
  const key = "encoded-private-fixture-key";
  const secret = Buffer.from(key + ":" + key).toString("base64");
  mock.method(globalThis, "fetch", async () => new Response(JSON.stringify({ Authorization: "Basic " + secret, personal: "sensitive-upstream-body" }), { status: 401 }));
  await assert.rejects(btcAbuseCheck("1BoatSLRHtKNngkdXEeobR76b53LETtpyT", key), error => {
    const message = (error as Error).message;
    assert.match(message, /HTTP 401/);
    assert.doesNotMatch(message, /encoded-private|sensitive-upstream-body/);
    assert.equal(message.includes(secret), false);
    return true;
  });
});

test("provider caches partition authenticated and anonymous access", async () => {
  let calls = 0;
  mock.method(globalThis, "fetch", async () => { calls++; return Response.json({ fixture: true }); });
  const operations = [
    (key?: string) => abuseipdbCheck("192.0.2.119", 90, false, key!),
    (key?: string) => otxDomain("release-cache.example", key),
    (key?: string) => phishingCheck("https://release-cache.example/path", key),
    (key?: string) => pulsediveIndicator("release-cache.example", key),
  ];
  for (const operation of operations) {
    const before: number = calls;
    await operation("cache-fixture-a"); await operation("cache-fixture-a");
    await operation("cache-fixture-b");
    assert.equal(calls - before, 2);
  }
  for (const operation of operations.slice(1)) await operation();
  assert.equal(calls, 11);
  for (const [name, args] of [
    ["threatfoxSearch", { searchTerm: "release-cache.example" }],
    ["urlhausLookup", { host: "release-cache.example" }],
    ["bazaarHash", { hash: "c".repeat(64) }],
  ] as const) {
    const tool = abusechTools.find(candidate => candidate.name === name)!;
    const ctx = (key?: string) => buildToolContext({ ABUSECH_AUTH_KEY: key });
    const before: number = calls;
    await tool.execute(args, ctx("cache-fixture-a"));
    await tool.execute(args, ctx("cache-fixture-a"));
    await tool.execute(args, ctx("cache-fixture-b"));
    await assert.rejects(tool.execute(args, ctx()), /ABUSECH_AUTH_KEY/);
    assert.equal(calls - before, 2);
  }
});

test("ChainAbuse HTTP 404 remains an error rather than a clean reputation claim", async () => {
  mock.method(globalThis, "fetch", async () => new Response("route not found", { status: 404 }));
  await assert.rejects(btcAbuseCheck("release-404-fixture", "404-fixture-key"), /HTTP 404/);
});

test("rate limiter rechecks spacing after cancellation immediately followed by new work", async () => {
  mock.restoreAll();
  const limiter = new RateLimiter(50);
  await limiter.acquire();
  const admitted = Date.now();
  const cancel = new AbortController();
  const cancelled = limiter.acquire(cancel.signal);
  cancel.abort(new Error("cancelled"));
  const next = limiter.acquire();
  await assert.rejects(cancelled, /cancelled/);
  await next;
  assert.ok(Date.now() - admitted >= 40);
});

test("local SOCKS readiness handles fragmented greetings and prompt socket closure", async () => {
  for (const fragments of [true, false]) {
    const server = net.createServer(socket => {
      socket.once("data", () => {
        if (!fragments) { socket.end(); return; }
        socket.write(Buffer.from([0x05]));
        setTimeout(() => socket.end(Buffer.from([0x00])), 10);
      });
    });
    await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
    try {
      const port = (server.address() as net.AddressInfo).port;
      const value = await checkTorStatus("127.0.0.1", port);
      assert.equal(value.socksAvailable, fragments);
    } finally { await new Promise<void>(resolve => server.close(() => resolve())); }
  }
});
