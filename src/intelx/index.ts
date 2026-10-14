import { apiFetch } from "../utils/http.js";
// IntelligenceX — Dark web data search and phonebook provider
// Tools: intelxSearch, intelxSearchResults, intelxPhonebook, intelxPhonebookResults

import { RateLimiter } from "../utils/rate-limiter.js";
import { requireApiKey } from "../utils/require-key.js";

// ─── Types ───

export interface IntelxSearchInitResponse {
  id: string;
  status: number;
}

export interface IntelxSearchResultRecord {
  systemid: string;
  owner: string;
  storageid: string;
  intelxid: string;
  bucket: string;
  keyid: string;
  added: string;
  date: string;
  name: string;
  description: string;
  media: number;
  type: number;
  typeh: string;
  simhash: string;
  accesslevel: number;
  accesslevelh: string;
  [key: string]: unknown;
}

export interface IntelxSearchResultsResponse {
  id: string;
  status: number;
  selectors: unknown[];
  records: IntelxSearchResultRecord[];
  statistics: Record<string, unknown>;
  [key: string]: unknown;
}

export interface IntelxPhonebookInitResponse {
  id: string;
  status: number;
}

export interface IntelxPhonebookResultRecord {
  value: string;
  type: number;
  typeh: string;
  media: number;
  mediah: string;
  [key: string]: unknown;
}

export interface IntelxPhonebookResultsResponse {
  id: string;
  selectors: IntelxPhonebookResultRecord[];
  status: number;
  [key: string]: unknown;
}

// ─── Constants ───

const BASE_URL = "https://2.intelx.io";

// ─── Rate Limiter ───

const limiter = new RateLimiter(2000);
// Search IDs are short-lived and polling results change while a search runs.
// Always initiate a fresh search and fetch a fresh polling response. Never cache
// these authenticated, stateful endpoints or reuse search IDs across API keys.

// ─── Helpers ───

function intelxHeaders(apiKey: string): Record<string, string> {
  return {
    "x-key": apiKey,
    "Content-Type": "application/json",
    Accept: "application/json",
  };
}

// ─── 1. intelxSearch — Initiate an IntelligenceX search ───

export async function intelxSearch(
  term: string,
  maxResults: number = 100,
  apiKey: string,
): Promise<IntelxSearchInitResponse> {
  requireApiKey(apiKey, "IntelligenceX", "INTELX_API_KEY");

  await limiter.acquire();

  const response = await apiFetch(`${BASE_URL}/intelligent/search`, {
    method: "POST",
    headers: intelxHeaders(apiKey),
    body: JSON.stringify({
      term,
      maxresults: maxResults,
      media: 0,
      timeout: 10,
    }),
  }, { beforeRetry: (signal) => limiter.acquire(signal) });

  if (!response.ok) {
    throw new Error(`IntelligenceX search error: HTTP ${response.status}`);
  }

  const data = (await response.json()) as IntelxSearchInitResponse;
  return data;
}

// ─── 2. intelxSearchResults — Retrieve results for a search ID ───

export async function intelxSearchResults(
  id: string,
  offset: number = 0,
  limit: number = 100,
  apiKey: string,
): Promise<IntelxSearchResultsResponse> {
  requireApiKey(apiKey, "IntelligenceX", "INTELX_API_KEY");

  await limiter.acquire();

  const params = new URLSearchParams({
    id,
    offset: String(offset),
    limit: String(limit),
  });

  const response = await apiFetch(`${BASE_URL}/intelligent/search/result?${params.toString()}`, {
    headers: intelxHeaders(apiKey),
  }, { beforeRetry: (signal) => limiter.acquire(signal) });

  if (!response.ok) {
    throw new Error(`IntelligenceX results error: HTTP ${response.status}`);
  }

  const data = (await response.json()) as IntelxSearchResultsResponse;
  return data;
}

// ─── 3. intelxPhonebook — Initiate a phonebook search (emails, domains, URLs) ───

export async function intelxPhonebook(
  term: string,
  target: number = 0,
  maxResults: number = 100,
  apiKey: string,
): Promise<IntelxPhonebookInitResponse> {
  requireApiKey(apiKey, "IntelligenceX", "INTELX_API_KEY");

  await limiter.acquire();

  const response = await apiFetch(`${BASE_URL}/phonebook/search`, {
    method: "POST",
    headers: intelxHeaders(apiKey),
    body: JSON.stringify({
      term,
      target,
      maxresults: maxResults,
    }),
  }, { beforeRetry: (signal) => limiter.acquire(signal) });

  if (!response.ok) {
    throw new Error(`IntelligenceX phonebook error: HTTP ${response.status}`);
  }

  const data = (await response.json()) as IntelxPhonebookInitResponse;
  return data;
}

// ─── 4. intelxPhonebookResults — Retrieve phonebook search results ───

export async function intelxPhonebookResults(
  id: string,
  offset: number = 0,
  limit: number = 100,
  apiKey: string,
): Promise<IntelxPhonebookResultsResponse> {
  requireApiKey(apiKey, "IntelligenceX", "INTELX_API_KEY");

  await limiter.acquire();

  const params = new URLSearchParams({
    id,
    offset: String(offset),
    limit: String(limit),
  });

  const response = await apiFetch(`${BASE_URL}/phonebook/search/result?${params.toString()}`, {
    headers: intelxHeaders(apiKey),
  }, { beforeRetry: (signal) => limiter.acquire(signal) });

  if (!response.ok) {
    throw new Error(`IntelligenceX phonebook results error: HTTP ${response.status}`);
  }

  const data = (await response.json()) as IntelxPhonebookResultsResponse;
  return data;
}
