import assert from "node:assert/strict";
import { test } from "node:test";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { VERSION } from "../src/version.js";
import { buildToolContext } from "../src/config.js";
import { allTools } from "../src/protocol/tools.js";
import { listSources } from "../src/meta/sources.js";
import { TTLCache } from "../src/utils/cache.js";
import { RateLimiter } from "../src/utils/rate-limiter.js";
import { apiFetch, withRequestSignal } from "../src/utils/http.js";
import { safeErrorMessage } from "../src/utils/errors.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { z } from "zod";
import { executeCliTool } from "../src/cli.js";

const entrypoint = fileURLToPath(new URL("../src/index.js", import.meta.url));
const context = buildToolContext({});

test("catalog matches public registry and distinguishes optional keys from health", () => {
  const sources = listSources(context.config, allTools);
  const names = allTools.map(tool => tool.name);
  assert.equal(names.length, 68);
  assert.equal(new Set(names).size, names.length);
  const catalog = sources.flatMap(source => source.tools);
  assert.equal(new Set(catalog).size, catalog.length);
  assert.deepEqual([...catalog].sort(), names.filter(name => !name.startsWith("darknet_")).sort());
  const hibp = sources.find(source => source.envVar === "HIBP_API_KEY")!;
  assert.equal(hibp.configured, true);
  assert.equal(hibp.keyPresent, false);
  assert.ok(hibp.blockedTools.includes("breachSearch"));
  assert.ok(hibp.availableTools.includes("breachPassword"));
  assert.equal(sources.find(source => source.envVar === "OTX_API_KEY")!.configured, true);
  assert.equal(sources.find(source => source.requiresTor)!.health, "not_checked");
  assert.equal(sources.find(source => source.envVar === "ABUSECH_AUTH_KEY")!.configured, false);
});

test("configuration validates ports and accepts the blockchain key", () => {
  assert.equal(buildToolContext({ CHAINABUSE_API_KEY: "test-key" }).config.chainabuseApiKey, "test-key");
  for (const value of ["0", "65536", "9050garbage", "1.5", ""]) assert.throws(() => buildToolContext({ TOR_SOCKS_PORT: value }));
});

test("tool schemas reject invalid formats and numeric bounds", () => {
  for (const [name, args] of [
    ["otx_ip", { ip: "not-an-ip" }], ["otx_hash", { hash: "abc" }],
    ["otx_cve", { cve: "CVE-bad" }], ["intelx_phonebook", { term: "example.test", target: 999 }],
    ["intelx_search_results", { id: "case", offset: -1 }], ["tor_search_onion", { query: "test", limit: 1.5 }],
    ["btc_tx", { txhash: "a".repeat(32) }],
  ] as const) {
    const tool = allTools.find(tool => tool.name === name)!;
    assert.equal(z.object(tool.schema).safeParse(args).success, false, name);
  }
});

test("CLI executes documented single-tool syntax without entering stdio", () => {
  const run = spawnSync(process.execPath, [entrypoint, "--tool", "darknet_list_sources", "{}"], { encoding: "utf8", timeout: 5000 });
  assert.equal(run.status, 0, run.stderr);
  const result = JSON.parse(run.stdout);
  assert.equal(result.tool_count, 68);
  assert.equal(result.version, VERSION);
  assert.ok(result.sources.some((source: { name: string }) => source.name === "Ransomware.live"));
  assert.doesNotMatch(run.stderr, /started on stdio/);
});

test("CLI reports invalid arguments and unknown options without network", () => {
  for (const args of [["--bogus"], ["--tool", "missing", "{}"], ["--tool", "otx_ip", "{"], ["--tool", "otx_ip", '{"ip":"bad"}'], ["--gui", "--port", "65536"]]) {
    const run = spawnSync(process.execPath, [entrypoint, ...args], { encoding: "utf8", timeout: 5000 });
    assert.equal(run.status, 1, args.join(" "));
    assert.match(run.stderr, /Error:/);
    assert.equal(run.stdout, "");
  }
});

test("a real MCP client completes handshake, discovery and an offline tool call", async () => {
  const client = new Client({ name: "offline-test", version: "1.0.0" });
  const transport = new StdioClientTransport({ command: process.execPath, args: [entrypoint], stderr: "pipe" });
  try {
    await client.connect(transport);
    assert.equal(client.getServerVersion()?.version, VERSION);
    const listed = await client.listTools();
    assert.equal(listed.tools.length, 68);
    assert.ok(listed.tools.some(tool => tool.name === "darknet_investigate" && tool.annotations?.readOnlyHint));
    const result = await client.callTool({ name: "darknet_list_sources", arguments: {} });
    assert.equal(result.isError, undefined);
    assert.equal((result.structuredContent as { tool_count: number }).tool_count, 68);
    const missing = await client.callTool({ name: "abuseipdb_check", arguments: { ip: "192.0.2.1" } });
    assert.equal(missing.isError, true);
  } finally { await client.close(); }
});

test("cache evicts old entries, enforces bytes and expires values", t => {
  let now = 100;
  t.mock.method(Date, "now", () => now);
  const cache = new TTLCache<string>(10, 2, 12);
  cache.set("a", "aa"); cache.set("b", "bb"); cache.get("a"); cache.set("c", "cc");
  assert.equal(cache.get("b"), undefined);
  assert.equal(cache.get("a"), "aa");
  cache.set("huge", "x".repeat(30));
  assert.equal(cache.has("huge"), false);
  now = 110;
  assert.equal(cache.size, 0);
});

test("rate limiter removes cancelled queued work", async () => {
  const limiter = new RateLimiter(20);
  await limiter.acquire();
  const cancel = new AbortController();
  const queued = limiter.acquire(cancel.signal);
  cancel.abort(new Error("cancelled"));
  await assert.rejects(queued, /cancelled/);
  await limiter.acquire();
});

test("HTTP retries only GET and respects response size limits", async t => {
  let calls = 0;
  t.mock.method(globalThis, "fetch", async () => {
    calls++;
    return calls === 1 ? new Response("busy", { status: 429, headers: { "Retry-After": "0" } }) : Response.json({ ok: true });
  });
  assert.deepEqual(await (await apiFetch("https://provider.test", {}, { retryDelayMs: 0 })).json(), { ok: true });
  assert.equal(calls, 2);
  calls = 0;
  assert.equal((await apiFetch("https://provider.test", { method: "POST" })).status, 429);
  assert.equal(calls, 1);
  t.mock.restoreAll();
  t.mock.method(globalThis, "fetch", async () => new Response("12345"));
  await assert.rejects(apiFetch("https://provider.test", {}, { maxBodyBytes: 4 }), /size limit/);
});

test("HTTP deadline propagates cancellation to the fetch and rate-limiter context", async t => {
  let signal: AbortSignal | undefined;
  t.mock.method(globalThis, "fetch", async (_url: string, init: RequestInit) => new Promise<Response>((_resolve, reject) => {
    signal = init.signal!;
    signal.addEventListener("abort", () => reject(signal!.reason), { once: true });
  }));
  await assert.rejects(apiFetch("https://provider.test", {}, { timeoutMs: 15 }), /deadline/);
  assert.equal(signal?.aborted, true);
  const cancel = new AbortController(); cancel.abort(new Error("parent cancelled"));
  await assert.rejects(withRequestSignal(cancel.signal, () => apiFetch("https://provider.test")), /parent cancelled/);
  await assert.rejects(withRequestSignal(cancel.signal, () => new RateLimiter(1).acquire()), /parent cancelled/);
});

test("HTTP buffers body under deadline instead of stopping timeout at headers", async t => {
  t.mock.method(globalThis, "fetch", async (_url: string, init: RequestInit) => new Response(new ReadableStream({
    start(controller) { init.signal!.addEventListener("abort", () => controller.error(init.signal!.reason), { once: true }); },
  })));
  await assert.rejects(apiFetch("https://provider.test", {}, { timeoutMs: 15 }), /deadline/);
});

test("error reporting strips configured credentials", () => {
  const ctx = buildToolContext({ HIBP_API_KEY: "private-credential" });
  const message = safeErrorMessage(new Error("upstream private-credential token=another-secret"), ctx);
  assert.doesNotMatch(message, /private-credential|another-secret/);
  assert.match(message, /REDACTED/);
});

test("CLI execution never reflects bare configured keys from an upstream exception", async () => {
  const ctx = buildToolContext({ HIBP_API_KEY: "bare-private-key" });
  await assert.rejects(executeCliTool({ name: "test", description: "test", schema: {}, execute: async () => { throw new Error("Bare value bare-private-key came from upstream"); } }, {}, ctx), error => {
    assert.doesNotMatch((error as Error).message, /bare-private-key/);
    return true;
  });
});

test("HTTP retries reacquire provider spacing, including concurrent queued calls", async t => {
  const limiter = new RateLimiter(20);
  const times: number[] = [];
  let concurrent: Promise<void> | undefined;
  let concurrentAt = 0;
  t.mock.method(globalThis, "fetch", async () => {
    times.push(Date.now());
    if (times.length === 1) concurrent = limiter.acquire().then(() => { concurrentAt = Date.now(); });
    return times.length === 1 ? new Response("busy", { status: 502 }) : Response.json({ ok: true });
  });
  await limiter.acquire();
  await apiFetch("https://provider.test", {}, { retryDelayMs: 0, beforeRetry: signal => limiter.acquire(signal) });
  await concurrent;
  assert.equal(times.length, 2);
  assert.ok(concurrentAt - times[0]! >= 15, "Concurrent requests must respect provider spacing");
  assert.ok(times[1]! - concurrentAt >= 15, "Retry must wait for the admitted concurrent request");
});
