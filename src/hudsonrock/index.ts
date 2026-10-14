import { createHash } from "node:crypto";
import { isIP } from "node:net";
import { z } from "zod";
import { apiFetch } from "../utils/http.js";
import { RateLimiter } from "../utils/rate-limiter.js";
import { TTLCache } from "../utils/cache.js";
import { requireApiKey } from "../utils/require-key.js";

/** Cavalier v3: https://docs.hudsonrock.com/docs/domain-search */
export interface StealerEntry {
  stealer?: string;
  date_compromised?: string;
  date_uploaded?: string;
  stealer_family?: string;
  ip?: string;
  computer_name?: string;
  operating_system?: string;
  credentials?: { url?: string; domain?: string; username?: string; password?: string; type?: string; [key: string]: unknown }[];
  [key: string]: unknown;
}

export interface StealerDomainResponse {
  stealers: StealerEntry[];
  /** The search API provides a page, not a corpus-wide total. */
  total: null;
  result_count: number;
  nextCursor: string | null;
  complete: boolean;
}
export type StealerEmailResponse = StealerDomainResponse;
export type StealerIpResponse = StealerDomainResponse;

const BASE_URL = "https://api.hudsonrock.com/json/v3";
const limiter = new RateLimiter(2000);
const cache = new TTLCache<StealerDomainResponse>(10 * 60 * 1000);
const domainSchema = z.string().trim().toLowerCase().max(253).regex(/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/);
const cursorSchema = z.string().min(1).max(4096).regex(/^[A-Za-z0-9+/=_-]+$/).optional();
const pageSchema = z.object({
  data: z.array(z.record(z.string(), z.unknown()).refine((item) => Object.keys(item).length > 0, "Empty stealer record")).max(20),
  nextCursor: z.string().max(4096).nullable().optional(),
}).passthrough();

async function hudsonrockFetch(path: string, payload: Record<string, unknown>, apiKey: string): Promise<StealerDomainResponse> {
  requireApiKey(apiKey, "Hudson Rock", "HUDSONROCK_API_KEY");
  const cacheKey = `${createHash("sha256").update(apiKey).digest("hex")}:${path}:${JSON.stringify(payload)}`;
  const cached = cache.get(cacheKey);
  if (cached !== undefined) return cached;
  await limiter.acquire();
  const response = await apiFetch(`${BASE_URL}${path}`, {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/json", "api-key": apiKey },
    body: JSON.stringify(payload),
  }, { timeoutMs: 95_000, beforeRetry: (signal) => limiter.acquire(signal) });
  // Never include provider bodies: they may echo credentials or the caller's API key.
  if (!response.ok) throw new Error(`Hudson Rock API error: HTTP ${response.status} ${response.statusText}`);
  const parsed = pageSchema.safeParse(await response.json());
  if (!parsed.success || "error" in parsed.data || "errors" in parsed.data || parsed.data.status === "error") throw new Error("Hudson Rock returned an invalid search response");
  const nextCursor = parsed.data.nextCursor || null;
  const result: StealerDomainResponse = {
    stealers: parsed.data.data as StealerEntry[], total: null, result_count: parsed.data.data.length,
    nextCursor, complete: nextCursor === null,
  };
  cache.set(cacheKey, result);
  return result;
}

/** https://docs.hudsonrock.com/reference/search-by-domains */
export async function stealerDomain(domain: string, apiKey: string, cursor?: string): Promise<StealerDomainResponse> {
  const normalized = domainSchema.parse(domain);
  return hudsonrockFetch("/search-by-domain", { domains: [normalized], filter_credentials: true, ...(cursorSchema.parse(cursor) ? { cursor } : {}) }, apiKey);
}

/** https://docs.hudsonrock.com/docs/email-search */
export async function stealerEmail(email: string, apiKey: string, cursor?: string): Promise<StealerEmailResponse> {
  const normalized = z.string().email().max(254).parse(email.trim().toLowerCase());
  return hudsonrockFetch("/search-by-login/emails", { logins: [normalized], filter_credentials: true, ...(cursorSchema.parse(cursor) ? { cursor } : {}) }, apiKey);
}

/** https://docs.hudsonrock.com/docs/ipcidr-search */
export async function stealerIp(ip: string, apiKey: string, cursor?: string): Promise<StealerIpResponse> {
  if (!isIP(ip)) throw new Error("Hudson Rock requires a valid IPv4 or IPv6 address");
  return hudsonrockFetch("/search-by-ip", { ips: [ip], filter_credentials: true, ...(cursorSchema.parse(cursor) ? { cursor } : {}) }, apiKey);
}
