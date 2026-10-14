import { createHash } from "node:crypto";
import { z } from "zod";
import { apiFetch } from "../utils/http.js";
import { RateLimiter } from "../utils/rate-limiter.js";
import { TTLCache } from "../utils/cache.js";
import { requireApiKey } from "../utils/require-key.js";

export interface VulnersDocument { id?: string; title?: string; type?: string; bulletinFamily?: string; cvelist?: string[]; [key: string]: unknown; }
export interface VulnersSearchResponse { result: "OK"; data: { search: VulnersDocument[]; total: number | null; references: Record<string, unknown> }; complete: boolean; }
export interface VulnersIdResponse { result: "OK"; data: { documents: Record<string, VulnersDocument>; references: Record<string, unknown> }; }
const BASE_URL = "https://vulners.com/api/v3";
const limiter = new RateLimiter(1000);
const cache = new TTLCache<unknown>(10 * 60 * 1000);
const fields = ["id", "title", "type", "bulletinFamily", "published", "modified", "cvss", "cvelist", "href", "sourceHref"];
const object = z.record(z.string(), z.unknown());

/** Current official SDK contract: POST, X-Api-Key, id arrays and _source search hits. */
async function request(path: string, body: Record<string, unknown>, apiKey?: string): Promise<Record<string, unknown>> {
  const key = requireApiKey(apiKey, "Vulners", "VULNERS_API_KEY");
  const cacheKey = createHash("sha256").update(key).digest("hex") + ":" + path + ":" + JSON.stringify(body);
  const cached = cache.get(cacheKey);
  if (cached !== undefined) return cached as Record<string, unknown>;
  await limiter.acquire();
  const response = await apiFetch(BASE_URL + path, {
    method: "POST", headers: { "X-Api-Key": key, "Content-Type": "application/json", Accept: "application/json" }, body: JSON.stringify(body),
  }, { beforeRetry: signal => limiter.acquire(signal) });
  if (!response.ok) throw new Error("Vulners API error: HTTP " + response.status);
  const envelope = z.object({ result: z.literal("OK"), data: object }).safeParse(await response.json());
  if (!envelope.success || "error" in envelope.data.data) throw new Error("Vulners returned an unsuccessful or invalid response");
  cache.set(cacheKey, envelope.data.data);
  return envelope.data.data;
}

export async function vulnersSearch(query: string, limit = 20, apiKey?: string): Promise<VulnersSearchResponse> {
  const input = z.string().trim().min(1).max(2048).parse(query);
  const size = z.number().int().min(1).max(1000).parse(limit);
  const data = await request("/search/lucene/", { query: input, size, skip: 0, fields }, apiKey);
  const hits = z.array(object).max(1000).safeParse(data.search);
  if (!hits.success) throw new Error("Vulners returned an invalid search result");
  const search = hits.data.map(hit => object.parse(hit._source ?? hit));
  const total = typeof data.total === "number" && Number.isSafeInteger(data.total) && data.total >= search.length ? data.total : null;
  return { result: "OK", data: { search, total, references: {} }, complete: total !== null && total <= search.length };
}

export async function vulnersId(id: string, apiKey?: string): Promise<VulnersIdResponse> {
  const value = z.string().trim().min(1).max(256).parse(id);
  const data = await request("/search/id/", { id: [value], references: false, fields }, apiKey);
  const documents = z.record(z.string(), object).safeParse(data.documents);
  if (!documents.success) throw new Error("Vulners returned an invalid document result");
  return { result: "OK", data: { documents: documents.data, references: {} } };
}

export async function vulnersExploit(query: string, limit = 20, apiKey?: string): Promise<VulnersSearchResponse> {
  const value = z.string().trim().min(1).max(1800).parse(query);
  // Match the entire exploit family, not only ExploitDB. Parentheses preserve the family filter.
  const term = /^CVE-\d{4}-\d{4,}$/i.test(value) ? JSON.stringify(value.toUpperCase()) : "(" + value + ")";
  return vulnersSearch("bulletinFamily:exploit AND " + term, limit, apiKey);
}
