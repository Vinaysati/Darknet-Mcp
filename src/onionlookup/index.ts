import { apiFetch } from "../utils/http.js";
import { RateLimiter } from "../utils/rate-limiter.js";
import { TTLCache } from "../utils/cache.js";

export interface OnionLookupResponse {
  address: string;
  lookup_status: "known" | "unknown";
  metadata: Record<string, unknown>;
  [key: string]: unknown;
}

const BASE_URL = "https://onion.ail-project.org";
const limiter = new RateLimiter(1000);
const cache = new TTLCache<OnionLookupResponse>(30 * 60 * 1000);

/** Validate before querying CIRCL. Bare v3 hostnames and HTTP(S) URLs are accepted. */
export function normalizeOnionAddress(address: string): string {
  let hostname = address.trim().toLowerCase();
  if (/^https?:\/\//.test(hostname)) {
    const url = new URL(hostname);
    if (url.username || url.password) throw new Error("Onion URLs must not contain credentials");
    hostname = url.hostname;
  } else {
    hostname = hostname.replace(/\/+$/, "");
  }
  if (!/^[a-z2-7]{56}\.onion$/.test(hostname)) throw new Error("CIRCL Onion Lookup requires a v3 onion hostname (56 base32 characters followed by .onion)");
  return hostname;
}

/** Official public route: https://github.com/ail-project/onion-lookup/blob/main/app.py */
export async function onionLookup(address: string): Promise<OnionLookupResponse> {
  const cleanAddress = normalizeOnionAddress(address);
  const cached = cache.get(cleanAddress);
  if (cached !== undefined) return cached;
  await limiter.acquire();
  const response = await apiFetch(`${BASE_URL}/api/lookup/${encodeURIComponent(cleanAddress)}`, {
    headers: { Accept: "application/json" },
  }, { beforeRetry: (signal) => limiter.acquire(signal) });
  if (!response.ok) throw new Error(`CIRCL Onion Lookup error: HTTP ${response.status} ${response.statusText}`);
  const data: unknown = await response.json();
  if (data === null || typeof data !== "object" || Array.isArray(data)) throw new Error("CIRCL Onion Lookup returned an invalid metadata response");
  const metadata = data as Record<string, unknown>;
  if ("error" in metadata || "errors" in metadata) throw new Error("CIRCL Onion Lookup returned a provider error");
  // CIRCL returns {} for an unavailable/unknown lookup; it is not a clean reputation result.
  const result: OnionLookupResponse = { ...metadata, address: cleanAddress, lookup_status: Object.keys(metadata).length ? "known" : "unknown", metadata };
  cache.set(cleanAddress, result);
  return result;
}
