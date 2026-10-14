import assert from "node:assert/strict";
import { afterEach, beforeEach, mock, test } from "node:test";
import { ransomlookGroups, ransomlookRecent, ransomwareRecent, ransomwareSearch, ransomwareGroups, ransomwareGroup, ransomwareGroupVictims, ransomwareByCountry, ransomwareBySector } from "../src/ransomware/index.js";
import { onionLookup } from "../src/onionlookup/index.js";
import { stealerDomain, stealerEmail, stealerIp } from "../src/hudsonrock/index.js";
import { malwareFeed, malwareOverview, malwareSearch } from "../src/hybrid/index.js";
import { RateLimiter } from "../src/utils/rate-limiter.js";
import { TTLCache } from "../src/utils/cache.js";
import { withRequestSignal } from "../src/utils/http.js";
import type { ToolContext, ToolResult } from "../src/types/index.js";

const context: ToolContext = { config: { torSocksHost: "127.0.0.1", torSocksPort: 9050 } };
const onion = `${"a".repeat(56)}.onion`;
const sha256 = "a".repeat(64);
const stealerFixture = {
  stealer: "fixture-machine-001", date_compromised: "2026-01-02T10:30:00.000Z",
  date_uploaded: "2026-01-03T10:30:00.000Z", stealer_family: "fixture-family",
  ip: "192.0.2.12", computer_name: "fixture-device", operating_system: "Windows",
  credentials: [{ url: "https://example.test/login", domain: "example.test", username: "test@example.test", password: "fixture-only-password", type: "employee" }],
};
function body(result: ToolResult): any { return JSON.parse(result.content[0]!.text); }

beforeEach(() => {
  const entries = new Map<string, unknown>();
  mock.method(TTLCache.prototype, "get", (key: string) => entries.get(key));
  mock.method(TTLCache.prototype, "set", (key: string, value: unknown) => { entries.set(key, value); });
  mock.method(RateLimiter.prototype, "acquire", async () => {});
  mock.method(globalThis, "fetch", async () => { throw new Error("Unexpected real network in adapter contract test"); });
});
afterEach(() => mock.restoreAll());

// Official contracts: RansomLook/website/web/api/genericapi.py and ransomlook/ransomlook.py.
test("RansomLook groups preserve actual string names without fabricated URL profiles", async () => {
  mock.method(globalThis, "fetch", async (input: string | URL | Request) => {
    assert.equal(String(input), "https://www.ransomlook.io/api/groups");
    return Response.json(["lockbit3", "clop"]);
  });
  assert.deepEqual(body(await ransomlookGroups.execute({}, context)), { total: 2, groups: [{ name: "lockbit3" }, { name: "clop" }] });
});
test("RansomLook recent keeps link and discovery metadata and states feed coverage", async () => {
  mock.method(globalThis, "fetch", async () => Response.json([{ group_name: "fixture-group", post_title: "example.test", link: "/post/123", discovered: "2026-01-02 10:30:00", published: "2026-01-01", slug: "fixture-site" }]));
  const result = body(await ransomlookRecent.execute({}, context));
  assert.equal(result.posts[0].post_url, "/post/123");
  assert.equal(result.posts[0].link, "/post/123");
  assert.equal(result.posts[0].published, "2026-01-01");
  assert.equal(result.complete, false);
  assert.equal(result.coverage, "latest_posts");
});
test("RansomLook empty feeds are valid but malformed groups/posts cannot look clear", async () => {
  mock.method(globalThis, "fetch", async () => Response.json([]));
  assert.equal(body(await ransomlookRecent.execute({}, context)).total, 0);
  mock.method(TTLCache.prototype, "get", () => undefined);
  mock.method(globalThis, "fetch", async () => Response.json({ error: "unavailable" }));
  await assert.rejects(ransomlookGroups.execute({}, context), /invalid groups/);
  await assert.rejects(ransomlookRecent.execute({}, context), /invalid recent/);
});

// Official route and {} behavior: ail-project/onion-lookup/app.py.
test("CIRCL public lookup validates v3 and uses current public route", async () => {
  mock.method(globalThis, "fetch", async (input: string | URL | Request) => {
    assert.equal(String(input), `https://onion.ail-project.org/api/lookup/${onion}`);
    return Response.json({ tags: ["fixture-tag"], first_seen: "2026-01-01", last_seen: "2026-01-02" });
  });
  const result = await onionLookup(`HTTPS://${onion.toUpperCase()}/path?q=1`);
  assert.equal(result.address, onion);
  assert.equal(result.lookup_status, "known");
  assert.deepEqual(result.metadata.tags, ["fixture-tag"]);
});
test("CIRCL empty metadata is unknown rather than a negative reputation finding", async () => {
  mock.method(globalThis, "fetch", async () => Response.json({}));
  const result = await onionLookup(onion);
  assert.equal(result.lookup_status, "unknown");
  assert.deepEqual(result.metadata, {});
  assert.equal(result.found, undefined);
});
test("CIRCL invalid onion formats fail before network", async () => {
  for (const invalid of ["example.test", "a".repeat(16) + ".onion", "a".repeat(56) + ".onion.evil.test", "0".repeat(56) + ".onion", `ftp://${onion}`, `http://user:secret@${onion}/`]) {
    await assert.rejects(onionLookup(invalid));
  }
});
test("CIRCL malformed/error bodies and HTTP failures never mean unknown", async () => {
  for (const invalid of [[], null, { error: "Incorrect onion format" }]) {
    mock.method(globalThis, "fetch", async () => Response.json(invalid));
    await assert.rejects(onionLookup(onion), /invalid metadata|provider error/);
  }
  mock.method(globalThis, "fetch", async () => new Response("not found", { status: 404 }));
  await assert.rejects(onionLookup(onion), /HTTP 404/);
});

// Official v3 guides: docs.hudsonrock.com/docs/{domain-search,email-search,ipcidr-search}.
test("Hudson Rock domain search uses authenticated v3 POST and truthful page metadata", async () => {
  mock.method(globalThis, "fetch", async (input: string | URL | Request, init?: RequestInit) => {
    assert.equal(String(input), "https://api.hudsonrock.com/json/v3/search-by-domain");
    assert.equal(init?.method, "POST");
    assert.equal(new Headers(init?.headers).get("api-key"), "fixture-api-key");
    assert.deepEqual(JSON.parse(String(init?.body)), { domains: ["example.test"], filter_credentials: true });
    return Response.json({ data: [stealerFixture], nextCursor: "cGFnZS0y" });
  });
  const result = await stealerDomain("Example.Test", "fixture-api-key");
  assert.deepEqual(result.stealers, [stealerFixture]);
  assert.equal(result.total, null);
  assert.equal(result.result_count, 1);
  assert.equal(result.nextCursor, "cGFnZS0y");
  assert.equal(result.complete, false);
});
test("Hudson Rock email and IP lookups use current payloads and support cursor pages", async () => {
  const urls: string[] = [];
  mock.method(globalThis, "fetch", async (input: string | URL | Request, init?: RequestInit) => {
    urls.push(String(input));
    const payload = JSON.parse(String(init?.body));
    assert.deepEqual(payload, urls.length === 1 ? { logins: ["test@example.test"], filter_credentials: true, cursor: "cGFnZS0y" } : { ips: ["192.0.2.1"], filter_credentials: true });
    return Response.json({ data: [], nextCursor: null });
  });
  const email = await stealerEmail("Test@Example.Test", "fixture-api-key", "cGFnZS0y");
  const ip = await stealerIp("192.0.2.1", "fixture-api-key");
  assert.deepEqual(urls, ["https://api.hudsonrock.com/json/v3/search-by-login/emails", "https://api.hudsonrock.com/json/v3/search-by-ip"]);
  assert.equal(email.complete, true);
  assert.equal(ip.result_count, 0);
});
test("Hudson Rock rejects missing auth or invalid inputs before requests", async () => {
  await assert.rejects(stealerDomain("example.test", ""), /HUDSONROCK_API_KEY/);
  await assert.rejects(stealerDomain("https://example.test", "fixture-api-key"));
  await assert.rejects(stealerEmail("not-an-email", "fixture-api-key"));
  await assert.rejects(stealerIp("999.1.2.3", "fixture-api-key"), /valid IPv4/);
  await assert.rejects(stealerDomain("example.test", "fixture-api-key", "bad\nvalue"));
});
test("Hudson Rock cache cannot reuse another account's stealer results", async () => {
  let calls = 0;
  mock.method(globalThis, "fetch", async () => { calls++; return Response.json({ data: [], nextCursor: null }); });
  await stealerDomain("cache.example.test", "account-a");
  await stealerDomain("cache.example.test", "account-a");
  await assert.rejects(stealerDomain("cache.example.test", ""), /HUDSONROCK_API_KEY/);
  await stealerDomain("cache.example.test", "account-b");
  await stealerDomain("cache.example.test", "account-a", "cGFnZS0y");
  assert.equal(calls, 3);
});
test("Hudson Rock malformed and error responses do not become zero exposure", async () => {
  for (const invalid of [{ error: "denied" }, {}, { data: [{}] }, { data: [], nextCursor: 12 }, { data: [], error: "quota" }]) {
    mock.method(globalThis, "fetch", async () => Response.json(invalid));
    await assert.rejects(stealerDomain("example.test", "fixture-api-key"), /invalid search response/);
  }
});
test("Hudson Rock POST errors are not replayed or echoed into reports", async () => {
  for (const status of [401, 403, 429]) {
    let calls = 0;
    mock.method(globalThis, "fetch", async () => { calls++; return new Response("SECRET_PROVIDER_BODY", { status }); });
    await assert.rejects(stealerDomain("example.test", "fixture-api-key"), (error: Error) => { assert.match(error.message, new RegExp(`HTTP ${status}`)); assert.doesNotMatch(error.message, /SECRET/); return true; });
    assert.equal(calls, 1);
  }
});

// Official migration notice: hybrid-analysis.com/docs/api/v2-changelog (v2.35/v2.33).
test("Hybrid hash search uses GET query and current authentication headers", async () => {
  mock.method(globalThis, "fetch", async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(String(input));
    assert.equal(url.pathname, "/api/v2/search/hash");
    assert.equal(url.searchParams.get("hash"), sha256);
    assert.equal(init?.method ?? "GET", "GET");
    assert.equal(init?.body, undefined);
    assert.equal(new Headers(init?.headers).get("api-key"), "fixture-hybrid-key");
    return Response.json([{ sha256, verdict: "malicious", threat_score: 100 }]);
  });
  assert.equal((await malwareSearch(sha256.toUpperCase(), "fixture-hybrid-key"))[0]?.verdict, "malicious");
});
test("Hybrid detonation feed normalizes envelope while preserving array tool output", async () => {
  mock.method(globalThis, "fetch", async (input: string | URL | Request) => {
    assert.equal(String(input), "https://hybrid-analysis.com/api/v2/feed/detonation");
    return Response.json({ count: 1, data: [{ sha256, verdict: "malicious", submit_name: "fixture.exe" }] });
  });
  const result = await malwareFeed("fixture-hybrid-key");
  assert.equal(result.length, 1);
  assert.equal(result[0]?.sha256, sha256);
});
test("Hybrid empty search is valid; malformed payloads and feed wrappers are errors", async () => {
  mock.method(globalThis, "fetch", async () => Response.json([]));
  assert.deepEqual(await malwareSearch(sha256, "fixture-hybrid-key"), []);
  mock.method(TTLCache.prototype, "get", () => undefined);
  mock.method(globalThis, "fetch", async () => Response.json({ error: "API key denied" }));
  await assert.rejects(malwareSearch(sha256, "fixture-hybrid-key"), /invalid hash search/);
  await assert.rejects(malwareFeed("fixture-hybrid-key"), /invalid detonation feed/);
  await assert.rejects(malwareOverview(sha256, "fixture-hybrid-key"), /invalid overview/);
});
test("Hybrid auth scopes all cached operations and validates hashes", async () => {
  let calls = 0;
  mock.method(globalThis, "fetch", async (input: string | URL | Request) => { calls++; return Response.json(String(input).includes("overview") ? { sha256 } : [{ sha256 }]); });
  for (const operation of [(key: string) => malwareSearch(sha256, key), (key: string) => malwareOverview(sha256, key), (key: string) => malwareFeed(key)]) {
    await operation("account-a"); await operation("account-a");
    await assert.rejects(operation(""), /HYBRID_API_KEY/);
    await operation("account-b");
  }
  assert.equal(calls, 6);
  await assert.rejects(malwareSearch("bad-hash", "account-a"), /MD5, SHA1, or SHA256/);
  await assert.rejects(malwareOverview("a".repeat(32), "account-a"), /requires a SHA256/);
});
test("Migrated adapter requests retain cancellation", async () => {
  const controller = new AbortController();
  controller.abort(new Error("Fixture request cancelled"));
  await assert.rejects(withRequestSignal(controller.signal, () => stealerDomain("cancel.example.test", "fixture-api-key")), /Fixture request cancelled/);
  await assert.rejects(withRequestSignal(controller.signal, () => onionLookup(onion)), /Fixture request cancelled/);
  await assert.rejects(withRequestSignal(controller.signal, () => malwareSearch(sha256, "fixture-hybrid-key")), /Fixture request cancelled/);
});

// API v2 is listed on ransomware.live/api; field variants retain source evidence.
test("Ransomware.live normalizes modern victim aliases and encoded search identifiers", async () => {
  mock.method(globalThis, "fetch", async (input: string | URL | Request) => {
    assert.equal(String(input), "https://api.ransomware.live/v2/searchvictims/example.test");
    return Response.json([{ victim: "Example", group: "fixture-group", activity: "Technology", country: "US", attackdate: "2026-01-01", discovered: "2026-01-02", claim_url: "http://claim.onion/post", website: "example.test" }]);
  });
  const result = body(await ransomwareSearch.execute({ keyword: "example.test" }, context));
  assert.equal(result.victims[0].name, "Example");
  assert.equal(result.victims[0].sector, "Technology");
  assert.equal(result.victims[0].url, "http://claim.onion/post");
  assert.equal(result.victims[0].published, "2026-01-01");
});
test("Ransomware.live legacy victim aliases remain compatible", async () => {
  mock.method(globalThis, "fetch", async () => Response.json([{ post_title: "Example Legacy", group_name: "fixture-group", activity: "Technology", published: "2026-01-01", discovered: "2026-01-02", post_url: "http://claim.onion/post" }]));
  const result = body(await ransomwareRecent.execute({}, context));
  assert.equal(result.total, 1);
  assert.equal(result.victims[0].name, "Example Legacy");
  assert.equal(result.victims[0].group, "fixture-group");
  assert.equal(result.victims[0].url, "http://claim.onion/post");
});
test("Ransomware.live malformed records are not converted into zero victims or groups", async () => {
  for (const invalid of [{ error: "provider unavailable" }, [{}], [null], [{ description: "no victim identity" }]]) {
    mock.method(globalThis, "fetch", async () => Response.json(invalid));
    await assert.rejects(ransomwareRecent.execute({}, context), /invalid|without a name/);
    await assert.rejects(ransomwareGroups.execute({}, context), /invalid/);
  }
});
test("Ransomware.live respects current one request/minute per endpoint limiter", async () => {
  const configured: number[] = [];
  mock.method(RateLimiter.prototype, "acquire", async function(this: RateLimiter) { configured.push((this as unknown as { minDelayMs: number }).minDelayMs); });
  mock.method(globalThis, "fetch", async () => Response.json([]));
  await ransomwareSearch.execute({ keyword: "first.example.test" }, context);
  await ransomwareSearch.execute({ keyword: "second.example.test" }, context);
  assert.deepEqual(configured, [60_000, 60_000]);
});

const proContext: ToolContext = { config: { ...context.config, ransomwareLiveApiKey: "fixture-ransomware-pro-key" } };
// Verified primary PRO request specification: https://api-pro.ransomware.live/swagger.json.
test("Ransomware.live PRO uses documented search endpoint and never exposes account identity", async () => {
  mock.method(globalThis, "fetch", async (input: string | URL | Request, init?: RequestInit) => {
    assert.equal(String(input), "https://api-pro.ransomware.live/victims/search?q=example.test");
    assert.equal(new Headers(init?.headers).get("X-API-KEY"), "fixture-ransomware-pro-key");
    assert.equal(init?.redirect, "error");
    return Response.json({ client: "PRIVATE_ACCOUNT_IDENTITY", count: 1, victims: [{ victim: "Example PRO", group: "fixture-group", activity: "Technology", attackdate: "2026-01-01", discovered: "2026-01-02", website: "example.test", id: "RXhhbXBsZUBncm91cA==", permalink: "https://www.ransomware.live/id/RXhhbXBsZUBncm91cA==" }] });
  });
  const result = body(await ransomwareSearch.execute({ keyword: "example.test" }, proContext));
  assert.equal(result.backend, "pro");
  assert.equal(result.victims[0].name, "Example PRO");
  assert.equal(result.victims[0].url, result.victims[0].permalink);
  assert.equal(result.victims[0].id, "RXhhbXBsZUBncm91cA==");
  assert.doesNotMatch(JSON.stringify(result), /PRIVATE_ACCOUNT_IDENTITY/);
});
test("Ransomware.live PRO filtered tools use official query contracts", async () => {
  const requests: string[] = [];
  mock.method(globalThis, "fetch", async (input: string | URL | Request) => { requests.push(String(input)); return Response.json({ victims: [] }); });
  await ransomwareRecent.execute({}, proContext);
  await ransomwareGroupVictims.execute({ name: "fixture group" }, proContext);
  await ransomwareByCountry.execute({ countryCode: "us" }, proContext);
  await ransomwareBySector.execute({ sector: "Health Care" }, proContext);
  assert.deepEqual(requests, ["https://api-pro.ransomware.live/victims/recent", "https://api-pro.ransomware.live/victims/?group=fixture+group", "https://api-pro.ransomware.live/victims/?country=US", "https://api-pro.ransomware.live/victims/?sector=Health+Care"]);
});
test("Ransomware.live PRO group profiles preserve enrichment and strip identity", async () => {
  mock.method(globalThis, "fetch", async (input: string | URL | Request) => {
    if (String(input).endsWith("/groups")) return Response.json({ client: "PRIVATE_ACCOUNT_IDENTITY", groups: [{ group: "fixture-group", altname: "Example", victims: 2 }] });
    assert.equal(String(input), "https://api-pro.ransomware.live/groups/fixture-group");
    return Response.json({ client: "PRIVATE_ACCOUNT_IDENTITY", group: "fixture-group", description: "Fixture description", ttps: [{ id: "T1000" }], locations: [{ url: "http://fixture.onion" }], tools: ["fixture-tool"] });
  });
  const groups = body(await ransomwareGroups.execute({}, proContext));
  const profile = body(await ransomwareGroup.execute({ name: "fixture-group" }, proContext));
  assert.equal(groups.groups[0].name, "fixture-group");
  assert.equal(groups.groups[0].victims, 2);
  assert.deepEqual(profile.ttps, [{ id: "T1000" }]);
  assert.deepEqual(profile.tools, ["fixture-tool"]);
  assert.doesNotMatch(JSON.stringify({ groups, profile }), /PRIVATE_ACCOUNT_IDENTITY/);
});
test("Ransomware.live PRO caches isolate keys and cannot bypass failures by falling back", async () => {
  let requests = 0;
  mock.method(globalThis, "fetch", async () => { requests++; return Response.json({ victims: [] }); });
  await ransomwareSearch.execute({ keyword: "cache.example.test" }, proContext);
  await ransomwareSearch.execute({ keyword: "cache.example.test" }, proContext);
  await ransomwareSearch.execute({ keyword: "cache.example.test" }, { config: { ...context.config, ransomwareLiveApiKey: "other-pro-key" } });
  await ransomwareSearch.execute({ keyword: "cache.example.test" }, context);
  assert.equal(requests, 3);
  let errors = 0;
  mock.method(globalThis, "fetch", async (input: string | URL | Request) => { errors++; assert.equal(new URL(String(input)).hostname, "api-pro.ransomware.live"); return new Response("SECRET_ERROR_BODY", { status: 403 }); });
  await assert.rejects(ransomwareSearch.execute({ keyword: "uncached.example.test" }, proContext), (error: Error) => { assert.match(error.message, /HTTP 403/); assert.doesNotMatch(error.message, /SECRET/); return true; });
  assert.equal(errors, 1);
});
test("Ransomware.live bounded pagination preserves count and reports incomplete coverage", async () => {
  mock.method(globalThis, "fetch", async () => Response.json({ victims: [{ victim: "First" }, { victim: "Second" }, { victim: "Third" }] }));
  const first = body(await ransomwareSearch.execute({ keyword: "page.example.test", limit: 2 }, proContext));
  const last = body(await ransomwareSearch.execute({ keyword: "page.example.test", limit: 2, offset: first.next_offset }, proContext));
  assert.equal(first.total, 3);
  assert.equal(first.result_count, 2);
  assert.equal(first.next_offset, 2);
  assert.equal(first.complete, false);
  assert.equal(last.victims[0].name, "Third");
  assert.equal(last.next_offset, null);
  assert.equal(last.truncated, true);
  const recent = body(await ransomwareRecent.execute({}, proContext));
  assert.equal(recent.complete, false);
  assert.equal(recent.coverage, "latest_victims");
});

test("Ransomware.live reported counts above returned rows remain partial with no invented upstream cursor", async () => {
  mock.method(globalThis, "fetch", async () => Response.json({ count: 50, victims: [{ victim: "Returned record" }] }));
  const result = body(await ransomwareSearch.execute({ keyword: "partial.example.test" }, proContext));
  assert.equal(result.total, 50);
  assert.equal(result.available_count, 1);
  assert.equal(result.result_count, 1);
  assert.equal(result.provider_truncated, true);
  assert.equal(result.truncated, true);
  assert.equal(result.complete, false);
  assert.equal(result.next_offset, null);
  assert.equal(result.count_basis, "provider_count");
});
test("Ransomware.live malformed collection counts are errors", async () => {
  for (const count of [-1, "50", 0.5, 0]) {
    mock.method(globalThis, "fetch", async () => Response.json({ count, victims: [{ victim: "Returned record" }] }));
    await assert.rejects(ransomwareSearch.execute({ keyword: "badcount.example.test" }, proContext), /invalid collection count/);
  }
});
