import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import http from "node:http";
import https from "node:https";
import { afterEach, beforeEach, mock, test } from "node:test";
import { abusechTools } from "../src/abusech/index.js";
import { btcAbuseCheck } from "../src/blockchain/index.js";
import { breachTools } from "../src/breach/index.js";
import {
  intelxPhonebook,
  intelxPhonebookResults,
  intelxSearch,
  intelxSearchResults,
} from "../src/intelx/index.js";
import type { ToolContext, ToolDef } from "../src/types/index.js";
import { RateLimiter } from "../src/utils/rate-limiter.js";
import { withRequestSignal } from "../src/utils/http.js";
import { fetchOnion } from "../src/utils/tor-fetch.js";

const context: ToolContext = {
  config: { torSocksHost: "127.0.0.1", torSocksPort: 9050 },
};
const authenticated: ToolContext = {
  config: { ...context.config, hibpApiKey: "test-hibp-key", abusechAuthKey: "test-abuse-key" },
};

function tool(tools: ToolDef[], name: string): ToolDef {
  const result = tools.find((item) => item.name === name);
  assert.ok(result, `Missing ${name}`);
  return result;
}

beforeEach(() => {
  // Tests exercise provider semantics; the production limiter remains enabled.
  mock.method(RateLimiter.prototype, "acquire", async () => {});
  mock.method(globalThis, "fetch", async () => {
    throw new Error("Unexpected network request in provider test");
  });
});
afterEach(() => mock.restoreAll());

test("HIBP sends explicit false query flags when the caller omits them", async () => {
  let requested: URL | undefined;
  mock.method(globalThis, "fetch", async (input: string | URL | Request, init?: RequestInit) => {
    requested = new URL(String(input));
    assert.equal(new Headers(init?.headers).get("hibp-api-key"), "test-hibp-key");
    return Response.json([{ Name: "ExampleBreach" }]);
  });
  await tool(breachTools, "breachSearch").execute({ account: "defaults@example.test" }, authenticated);
  assert.equal(requested?.searchParams.get("truncateResponse"), "false");
  assert.equal(requested?.searchParams.get("includeUnverified"), "false");
});

test("HIBP preserves explicit true query flags", async () => {
  let requested: URL | undefined;
  mock.method(globalThis, "fetch", async (input: string | URL | Request) => {
    requested = new URL(String(input));
    return Response.json([{ Name: "ExampleBreach" }]);
  });
  await tool(breachTools, "breachSearch").execute({
    account: "explicit@example.test", truncateResponse: true, includeUnverified: true,
  }, authenticated);
  assert.equal(requested?.searchParams.get("truncateResponse"), "true");
  assert.equal(requested?.searchParams.get("includeUnverified"), "true");
});

test("authenticated HIBP caches cannot bypass missing or different credentials", async () => {
  let requests = 0;
  mock.method(globalThis, "fetch", async () => {
    ++requests;
    return Response.json([{ Name: "CacheScopeTest" }]);
  });
  const firstContext: ToolContext = { config: { ...context.config, hibpApiKey: "first-test-key" } };
  const secondContext: ToolContext = { config: { ...context.config, hibpApiKey: "second-test-key" } };
  for (const [name, args] of [
    ["breachSearch", { account: "cache-scope@example.test" }],
    ["breachPastes", { email: "cache-scope@example.test" }],
  ] as const) {
    const definition = tool(breachTools, name);
    await definition.execute(args, firstContext);
    await definition.execute(args, firstContext);
    await assert.rejects(definition.execute(args, context), /HIBP_API_KEY/);
    await definition.execute(args, secondContext);
  }
  assert.equal(requests, 4);
});

test("IntelligenceX polling sees later results instead of cached pending data", async () => {
  let requests = 0;
  mock.method(globalThis, "fetch", async () => Response.json({
    id: "test-search", status: ++requests === 1 ? 3 : 1,
    selectors: [], records: requests === 1 ? [] : [{ systemid: "new-result" }], statistics: {},
  }));
  const pending = await intelxSearchResults("test-search", 0, 100, "test-intelx-key");
  const later = await intelxSearchResults("test-search", 0, 100, "test-intelx-key");
  assert.equal(pending.records.length, 0);
  assert.equal(later.records[0]?.systemid, "new-result");
  assert.equal(requests, 2);
});

test("IntelligenceX phonebook polling also stays fresh", async () => {
  let requests = 0;
  mock.method(globalThis, "fetch", async () => Response.json({
    id: "test-phonebook", status: 1,
    selectors: [{ value: `result-${++requests}` }],
  }));
  const first = await intelxPhonebookResults("test-phonebook", 0, 100, "test-intelx-key");
  const later = await intelxPhonebookResults("test-phonebook", 0, 100, "test-intelx-key");
  assert.equal(first.selectors[0]?.value, "result-1");
  assert.equal(later.selectors[0]?.value, "result-2");
});

test("IntelligenceX repeated searches receive fresh IDs", async () => {
  let requests = 0;
  mock.method(globalThis, "fetch", async () => Response.json({ id: `search-${++requests}`, status: 0 }));
  const first = await intelxSearch("example.test", 100, "test-intelx-key");
  const second = await intelxSearch("example.test", 100, "other-test-key");
  const phonebookFirst = await intelxPhonebook("example.test", 0, 100, "test-intelx-key");
  const phonebookSecond = await intelxPhonebook("example.test", 0, 100, "test-intelx-key");
  assert.notEqual(first.id, second.id);
  assert.notEqual(phonebookFirst.id, phonebookSecond.id);
  assert.equal(requests, 4);
});

test("every abuse.ch tool reports a missing key before network or cache access", async () => {
  for (const providerTool of abusechTools) {
    await assert.rejects(providerTool.execute({}, context), /ABUSECH_AUTH_KEY/);
  }
});

test("abuse.ch tools authenticate requests and hash search uses its dedicated endpoint", async () => {
  const requests: { url: string; body: string }[] = [];
  mock.method(globalThis, "fetch", async (input: string | URL | Request, init?: RequestInit) => {
    assert.equal(new Headers(init?.headers).get("Auth-Key"), "test-abuse-key");
    requests.push({ url: String(input), body: String(init?.body) });
    return Response.json({ query_status: "ok", data: [] });
  });
  const hash = "a".repeat(64);
  await tool(abusechTools, "threatfoxSearch").execute({ searchTerm: hash }, authenticated);
  await tool(abusechTools, "urlhausLookup").execute({ host: "provider-tests.example.test" }, authenticated);
  await tool(abusechTools, "bazaarHash").execute({ hash }, authenticated);
  assert.deepEqual(JSON.parse(requests[0]!.body), { query: "search_hash", hash });
  assert.match(requests[1]!.url, /urlhaus-api\.abuse\.ch\/v1\/host\//);
  assert.equal(new URLSearchParams(requests[1]!.body).get("host"), "provider-tests.example.test");
  assert.equal(new URLSearchParams(requests[2]!.body).get("query"), "get_info");
  // Cached public results still require the user to configure authentication.
  await assert.rejects(tool(abusechTools, "threatfoxSearch").execute({ searchTerm: hash }, context), /ABUSECH_AUTH_KEY/);
});

test("ThreatFox enforces the documented 1 to 7 day range", async () => {
  const definition = tool(abusechTools, "threatfoxGetIocs");
  assert.throws(() => definition.schema.days!.parse(30));
  assert.equal(definition.schema.days!.parse(7), 7);
  await assert.rejects(definition.execute({ days: 8 }, authenticated), /between 1 and 7/);
});

test("URLhaus and MalwareBazaar reject empty or ambiguous alternatives", async () => {
  for (const args of [{}, { url: " ", host: " " }, { url: "http://example.test", host: "example.test" }]) {
    await assert.rejects(tool(abusechTools, "urlhausLookup").execute(args, authenticated), /exactly one/);
  }
  for (const args of [{}, { tag: " ", signature: " " }, { tag: "Emotet", signature: "Emotet" }]) {
    await assert.rejects(tool(abusechTools, "bazaarTag").execute(args, authenticated), /exactly one/);
  }
});

test("ChainAbuse authenticates with the key in both Basic fields", async () => {
  let requests = 0;
  mock.method(globalThis, "fetch", async (input: string | URL | Request, init?: RequestInit) => {
    ++requests;
    assert.equal(new URL(String(input)).searchParams.get("address"), "test-address-auth");
    assert.equal(new Headers(init?.headers).get("Authorization"),
      `Basic ${Buffer.from("test-chain-key:test-chain-key").toString("base64")}`);
    return Response.json({ reports: [], count: 0 });
  });
  await assert.rejects(btcAbuseCheck("test-address-auth"), /CHAINABUSE_API_KEY/);
  assert.equal(requests, 0);
  assert.deepEqual(await btcAbuseCheck("test-address-auth", "test-chain-key"), { reports: [], count: 0 });
  await assert.rejects(btcAbuseCheck("test-address-auth"), /CHAINABUSE_API_KEY/);
});

test("ChainAbuse caches are isolated between API keys", async () => {
  let requests = 0;
  mock.method(globalThis, "fetch", async () => {
    ++requests;
    return Response.json({ reports: [], count: 0 });
  });
  await btcAbuseCheck("test-address-cache-scope", "first-test-key");
  await btcAbuseCheck("test-address-cache-scope", "first-test-key");
  await btcAbuseCheck("test-address-cache-scope", "second-test-key");
  assert.equal(requests, 2);
});

class MockRequest extends EventEmitter {
  destroyed = false;
  destroy(error?: Error): this {
    this.destroyed = true;
    if (error) queueMicrotask(() => this.emit("error", error));
    return this;
  }
}

function mockTorClient(
  client: typeof http | typeof https,
  reply: (response: EventEmitter, request: MockRequest) => void,
  statusCode = 200,
): () => number {
  let calls = 0;
  const get = (url: URL, options: http.RequestOptions, callback: (response: http.IncomingMessage) => void): http.ClientRequest => {
    ++calls;
    assert.ok(url.hostname.endsWith(".onion"));
    assert.ok(options.agent, "Tor requires a SOCKS agent");
    assert.equal(options.timeout, 60_000);
    const request = new MockRequest();
    queueMicrotask(() => {
      const response = Object.assign(new EventEmitter(), {
        statusCode, headers: { location: "https://clearnet.example.test/" },
      });
      callback(response as unknown as http.IncomingMessage);
      reply(response, request);
    });
    return request as unknown as http.ClientRequest;
  };
  mock.method(client, "get", get as unknown as typeof http.get);
  return () => calls;
}

test("Tor selects HTTPS for https onion URLs without following redirects", async () => {
  const calls = mockTorClient(https, (response) => {
    response.emit("data", Buffer.from("redirect response"));
    response.emit("end");
  }, 302);
  mock.method(http, "get", () => { throw new Error("Unexpected HTTP request"); });
  const result = await fetchOnion("https://test.onion/");
  assert.deepEqual(result, { html: "redirect response", statusCode: 302 });
  assert.equal(calls(), 1);
});

test("Tor still selects HTTP for http onion URLs", async () => {
  const calls = mockTorClient(http, (response) => {
    response.emit("data", Buffer.from("<title>Test</title>"));
    response.emit("end");
  });
  mock.method(https, "get", () => { throw new Error("Unexpected HTTPS request"); });
  assert.equal((await fetchOnion("http://test.onion/")).html, "<title>Test</title>");
  assert.equal(calls(), 1);
});

test("Tor rejects clearnet and unsupported protocols before requesting", async () => {
  mock.method(http, "get", () => { throw new Error("Unexpected HTTP request"); });
  mock.method(https, "get", () => { throw new Error("Unexpected HTTPS request"); });
  await assert.rejects(fetchOnion("https://example.test/"), /Only \.onion/);
  await assert.rejects(fetchOnion("ftp://test.onion/"), /Only http/);
});

test("Tor enforces its response size bound", async () => {
  let request: MockRequest | undefined;
  mockTorClient(http, (response, req) => {
    request = req;
    response.emit("data", Buffer.alloc(10 * 1024 * 1024 + 1));
    response.emit("end");
  });
  await assert.rejects(fetchOnion("http://test.onion/large"), /Response exceeded/);
  assert.equal(request?.destroyed, true);
});

test("Tor reports timeouts and destroys the request", async () => {
  let request: MockRequest | undefined;
  mockTorClient(http, (_response, req) => {
    request = req;
    req.emit("timeout");
  });
  await assert.rejects(fetchOnion("http://test.onion/slow"), /timed out after 60000ms/);
  assert.equal(request?.destroyed, true);
});

test("Tor propagates client cancellation and destroys the socket request", async () => {
  const controller = new AbortController();
  let request: MockRequest | undefined;
  mockTorClient(http, (_response, req) => {
    request = req;
    controller.abort(new Error("Cancelled by client"));
  });
  await assert.rejects(withRequestSignal(controller.signal,
    () => fetchOnion("http://test.onion/cancel")), /Cancelled by client/);
  assert.equal(request?.destroyed, true);
});

test("Tor refuses already-cancelled requests without opening a socket", async () => {
  const controller = new AbortController();
  controller.abort(new Error("Already cancelled"));
  mock.method(http, "get", () => { throw new Error("Unexpected HTTP request"); });
  await assert.rejects(withRequestSignal(controller.signal,
    () => fetchOnion("http://test.onion/cancel")), /Already cancelled/);
});
