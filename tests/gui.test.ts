import assert from "node:assert/strict";
import { request } from "node:http";
import { test } from "node:test";
import { z } from "zod";
import { startGuiServer } from "../src/gui/server.js";
import type { ToolContext, ToolDef } from "../src/types/index.js";
import { getRequestSignal } from "../src/utils/http.js";
import type { ReadinessReport } from "../src/meta/readiness.js";
import { INVESTIGATION_SOURCES } from "../src/investigation/types.js";

const context: ToolContext = {
  config: { torSocksHost: "127.0.0.1", torSocksPort: 9050, hibpApiKey: "never-send-this-key-to-browser" },
};
const report = {
  schema_version: "1.0", target: { value: "example.test", type: "domain" },
  checks: [], evidence: [], correlations: [], coverage: { selected: 0 }, limitations: [],
};
const schema = {
  target: z.string().min(1).max(2048).describe("Indicator to investigate"),
  target_type: z.enum(["auto", "domain", "email", "ip", "hash", "url", "onion", "bitcoin", "cve"]).default("auto").describe("Indicator type"),
  max_results: z.number().int().min(1).max(50).default(10).describe("Evidence limit"),
  sources: z.array(z.enum(INVESTIGATION_SOURCES)).min(1).max(INVESTIGATION_SOURCES.length).optional().describe("Selected source categories"),
  fetch_onion: z.boolean().default(false).describe("Explicitly fetch supplied onion page"),
};
const readinessReport: ReadinessReport = {
  schema_version: "1.0", checked_at: "2026-10-14T00:00:00.000Z",
  checks: [{ name: "Tor", tools: ["tor_check_connection"], configuration_status: "available_without_key", health_status: "unavailable", detail: "Local proxy unavailable", missing_env: null, requires_tor: true }],
  tor: { socksAvailable: false, socksHost: "127.0.0.1", socksPort: 9050 },
  summary: { configured_sources: 0, partial_sources: 0, blocked_sources: 0, tor_available: false, live_verified: false },
};
function testTool(execute: ToolDef["execute"]): ToolDef {
  return { name: "darknet_investigate", description: "Offline test", schema, execute };
}
async function withGui(
  tool: ToolDef,
  run: (url: string) => Promise<void>,
  readinessResolver: (context: ToolContext, registry: ToolDef[]) => Promise<ReadinessReport> = async () => readinessReport,
): Promise<void> {
  const { server, url } = await startGuiServer(context, { port: 0, investigationTool: tool, readinessResolver });
  try { await run(url); }
  finally {
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
}
function rawRequest(url: string, body: string, headers: Record<string, string> = {}, path = "/api/investigate"): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = request(url + path, { method: "POST", headers: {
      Origin: url, "Content-Type": "application/json", ...headers,
    } }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (chunk: Buffer) => chunks.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
    });
    req.on("error", reject);
    req.end(body);
  });
}

test("GUI serves only its local assets and safe source configuration", async () => {
  await withGui(testTool(async () => { throw new Error("Unexpected execution"); }), async (url) => {
    for (const [path, contentType] of [["/", "text/html"], ["/app.js", "text/javascript"], ["/app.css", "text/css"]]) {
      const response = await fetch(url + path);
      assert.equal(response.status, 200);
      assert.match(response.headers.get("content-type") ?? "", new RegExp(contentType!));
      assert.match(response.headers.get("content-security-policy") ?? "", /script-src 'self'/);
      assert.equal(response.headers.get("x-frame-options"), "DENY");
      assert.equal(response.headers.get("cache-control"), "no-store");
    }
    const response = await fetch(url + "/api/sources");
    const body = await response.text();
    assert.equal(response.status, 200);
    assert.doesNotMatch(body, /never-send-this-key-to-browser/);
    const data = JSON.parse(body);
    assert.ok(data.sources.some((source: { configured: boolean; envVar: string | null }) => source.envVar === "HIBP_API_KEY" && source.configured));
    assert.equal((await fetch(url + "/unknown")).status, 404);
    assert.equal((await fetch(url + "/../../package.json")).status, 404);
  });
});

test("GUI rejects nonlocal Host and cross-origin investigation requests", async () => {
  let calls = 0;
  await withGui(testTool(async () => { calls++; return { content: [], structuredContent: report }; }), async (url) => {
    const invalidHeaders: Record<string, string>[] = [
      { Host: "attacker.example" }, { Origin: "https://attacker.example" },
      { Origin: "null" }, { "Sec-Fetch-Site": "cross-site" },
    ];
    for (const headers of invalidHeaders) {
      const response = await rawRequest(url, '{"target":"example.test"}', headers);
      assert.equal(response.status, 403);
    }
    const noOrigin = await fetch(url + "/api/investigate", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: '{"target":"example.test"}',
    });
    assert.equal(noOrigin.status, 403);
    assert.equal(calls, 0);
  });
});

test("GUI strictly validates JSON and caps request bodies before executing", async () => {
  let calls = 0;
  await withGui(testTool(async () => { calls++; return { content: [], structuredContent: report }; }), async (url) => {
    for (const body of ["{", '[]', '{"target":""}', '{"target":"example.test","max_results":51}', '{"target":"example.test","tool":"tor_fetch_onion"}']) {
      assert.equal((await rawRequest(url, body)).status, 400);
    }
    assert.equal((await rawRequest(url, '{"target":"example.test"}', { "Content-Type": "text/plain" })).status, 415);
    assert.equal((await rawRequest(url, JSON.stringify({ target: "x".repeat(17 * 1024) }))).status, 413);
    // Also enforce the bound for a streaming body without Content-Length.
    assert.equal((await rawRequest(url, JSON.stringify({ target: "x".repeat(17 * 1024) }), { "Transfer-Encoding": "chunked" })).status, 413);
    assert.equal((await fetch(url + "/api/tool", { method: "POST" })).status, 405);
    assert.equal(calls, 0);
  });
});

test("GUI applies defaults and prefers structured report content", async () => {
  let received: Record<string, unknown> | undefined;
  await withGui(testTool(async (args, ctx) => {
    received = args;
    assert.equal(ctx, context);
    assert.ok(getRequestSignal());
    return { content: [{ type: "text", text: "Not JSON" }], structuredContent: report };
  }), async (url) => {
    const response = await rawRequest(url, '{"target":"example.test"}');
    assert.equal(response.status, 200);
    assert.deepEqual(JSON.parse(response.body), { report });
    assert.deepEqual(received, { target: "example.test", target_type: "auto", max_results: 10, fetch_onion: false });
  });
});

test("GUI can read a legacy text JSON result", async () => {
  await withGui(testTool(async () => ({ content: [{ type: "text", text: JSON.stringify(report) }] })), async (url) => {
    assert.deepEqual(JSON.parse((await rawRequest(url, '{"target":"example.test"}')).body), { report });
  });
});

test("GUI never reflects provider exceptions containing secrets", async () => {
  await withGui(testTool(async () => { throw new Error("key=never-send-this-key-to-browser private@example.test"); }), async (url) => {
    const response = await rawRequest(url, '{"target":"example.test"}');
    assert.equal(response.status, 502);
    assert.doesNotMatch(response.body, /never-send|private@example/);
  });
});

test("GUI limits active investigations and releases slots after completion", { timeout: 5_000 }, async () => {
  let started = 0;
  const releases: (() => void)[] = [];
  let twoStarted!: () => void;
  const ready = new Promise<void>((resolve) => { twoStarted = resolve; });
  await withGui(testTool(async () => {
    const blocked = new Promise<void>((resolve) => releases.push(resolve));
    if (++started === 2) twoStarted();
    if (started <= 2) await blocked;
    return { content: [], structuredContent: report };
  }), async (url) => {
    const first = rawRequest(url, '{"target":"example.test"}');
    const second = rawRequest(url, '{"target":"example.test"}');
    await ready;
    assert.equal((await rawRequest(url, '{"target":"example.test"}')).status, 429);
    for (const release of releases) release();
    assert.equal((await first).status, 200);
    assert.equal((await second).status, 200);
    assert.equal((await rawRequest(url, '{"target":"example.test"}')).status, 200);
  });
});

test("GUI cancels the scoped provider signal when a browser disconnects", { timeout: 5_000 }, async () => {
  let started!: () => void;
  let cancelled!: () => void;
  const ready = new Promise<void>((resolve) => { started = resolve; });
  const aborted = new Promise<void>((resolve) => { cancelled = resolve; });
  let calls = 0;
  await withGui(testTool(async () => {
    if (++calls === 1) {
      const signal = getRequestSignal();
      assert.ok(signal);
      const finished = new Promise<never>((_resolve, reject) => {
        signal.addEventListener("abort", () => { cancelled(); reject(signal.reason); }, { once: true });
      });
      started();
      return finished;
    }
    return { content: [], structuredContent: report };
  }), async (url) => {
    const client = request(url + "/api/investigate", {
      method: "POST", headers: { Origin: url, "Content-Type": "application/json" },
    });
    client.on("error", () => {}); // Deliberate client disconnect.
    client.end('{"target":"example.test"}');
    await ready;
    client.destroy();
    await aborted;
    assert.equal((await rawRequest(url, '{"target":"example.test"}')).status, 200);
  });
});

test("GUI rejects invalid port settings", async () => {
  for (const port of [-1, 65536, 1.5]) {
    await assert.rejects(startGuiServer(context, { port, investigationTool: testTool(async () => ({ content: [] })) }), /GUI port/);
  }
});

test("GUI supports all eight target types and source categories with explicit onion options", async () => {
  const received: Record<string, unknown>[] = [];
  await withGui(testTool(async (args) => {
    received.push(args);
    return { content: [], structuredContent: report };
  }), async (url) => {
    const targets = {
      domain: "example.test", email: "analyst@example.test", ip: "192.0.2.10", hash: "a".repeat(64),
      url: "https://example.test/path", onion: `${"a".repeat(56)}.onion`, bitcoin: "1BoatSLRHtKNngkdXEeobR76b53LETtpyT", cve: "CVE-2024-12345",
    };
    for (const [target_type, target] of Object.entries(targets)) {
      const args = { target_type, target, sources: [...INVESTIGATION_SOURCES], fetch_onion: target_type === "onion", max_results: 50 };
      assert.equal((await rawRequest(url, JSON.stringify(args))).status, 200);
      assert.deepEqual(received.at(-1), args);
    }
    for (const args of [
      { target: "example.test", target_type: "unknown" },
      { target: "example.test", sources: [] },
      { target: "example.test", sources: ["made-up-provider"] },
      { target: "example.test", fetch_onion: "true" },
      { target: "x".repeat(2049) },
    ]) assert.equal((await rawRequest(url, JSON.stringify(args))).status, 400);
    const html = await (await fetch(url)).text();
    for (const type of Object.keys(targets)) assert.match(html, new RegExp(`<option value="${type}">`));
    assert.match(html, /id="fetch-onion" type="checkbox"/);
    assert.doesNotMatch(html, /id="fetch-onion"[^>]*checked/);
    assert.match(html, /id="stop-investigation"/);
  });
});

test("GUI readiness coalesces concurrent requests and caches local checks", async () => {
  let calls = 0;
  let release!: () => void;
  let started!: () => void;
  const blocked = new Promise<void>((resolve) => { release = resolve; });
  const ready = new Promise<void>((resolve) => { started = resolve; });
  await withGui(testTool(async () => ({ content: [] })), async (url) => {
    const first = fetch(url + "/api/readiness");
    await ready;
    const second = fetch(url + "/api/readiness");
    assert.equal((await rawRequest(url, "{}", {}, "/api/readiness")).status, 429);
    release();
    for (const pending of [first, second]) {
      const response = await pending;
      assert.equal(response.status, 200);
      assert.deepEqual(await response.json(), { readiness: readinessReport });
    }
    assert.equal((await fetch(url + "/api/readiness")).status, 200);
    assert.equal(calls, 1);
    assert.equal((await rawRequest(url, "{}", {}, "/api/readiness")).status, 429);
  }, async (ctx, registry) => {
    assert.equal(ctx, context);
    assert.ok(registry.some((tool) => tool.name === "darknet_investigate"));
    calls++;
    started();
    await blocked;
    return readinessReport;
  });
});

test("GUI readiness refresh is same-origin, bounded, and rejects arbitrary operations", async () => {
  let calls = 0;
  await withGui(testTool(async () => ({ content: [] })), async (url) => {
    const invalidHeaders: Record<string, string>[] = [{ Host: "attacker.example" }, { Origin: "https://attacker.example" }, { Origin: "null" }, { "Sec-Fetch-Site": "cross-site" }];
    for (const headers of invalidHeaders) {
      assert.equal((await rawRequest(url, "{}", headers, "/api/readiness")).status, 403);
    }
    assert.equal((await fetch(url + "/api/readiness", { headers: { Origin: "https://attacker.example" } })).status, 403);
    assert.equal((await fetch(url + "/api/readiness", { headers: { "Sec-Fetch-Site": "cross-site" } })).status, 403);
    for (const body of ["{", "[]", '{"live":true}', '{"tor_host":"attacker.example"}']) {
      assert.equal((await rawRequest(url, body, {}, "/api/readiness")).status, 400);
    }
    assert.equal((await rawRequest(url, "{}", { "Content-Type": "text/plain" }, "/api/readiness")).status, 415);
    assert.equal((await rawRequest(url, "x".repeat(17 * 1024), {}, "/api/readiness")).status, 413);
    assert.equal(calls, 0);
    const response = await rawRequest(url, "{}", {}, "/api/readiness");
    assert.equal(response.status, 200);
    assert.deepEqual(JSON.parse(response.body), { readiness: readinessReport });
    assert.equal(calls, 1);
  }, async () => { calls++; return readinessReport; });
});

test("GUI readiness failure never leaks credentials or becomes a health success", async () => {
  let calls = 0;
  await withGui(testTool(async () => ({ content: [] })), async (url) => {
    const response = await fetch(url + "/api/readiness");
    assert.equal(response.status, 503);
    const body = await response.text();
    assert.doesNotMatch(body, /never-send|private@example/);
    assert.equal((await fetch(url + "/api/readiness")).status, 429);
    assert.equal(calls, 1);
  }, async () => {
    calls++;
    throw new Error("never-send-this-key-to-browser private@example.test");
  });
});
