import { keyScope } from "../utils/key-scope.js";
import { apiFetch } from "../utils/http.js";
import { z } from "zod";
import { RateLimiter } from "../utils/rate-limiter.js";
import { TTLCache } from "../utils/cache.js";
import { requireApiKey } from "../utils/require-key.js";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json } from "../types/index.js";

// ─── Shared Infrastructure ───

const limiter = new RateLimiter(500);
const cache = new TTLCache<ToolResult>(5 * 60 * 1000); // 5 min

// ─── API Base URLs ───

const THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/";
const URLHAUS_API = "https://urlhaus-api.abuse.ch/v1";
const BAZAAR_API = "https://mb-api.abuse.ch/api/v1/";

// ─── Helpers ───

function authHeaders(ctx: ToolContext): Record<string, string> {
  return {
    "Auth-Key": requireApiKey(ctx.config.abusechAuthKey, "abuse.ch", "ABUSECH_AUTH_KEY"),
  };
}

async function threatfoxPost(
  body: Record<string, unknown>,
  ctx: ToolContext,
): Promise<unknown> {
  const headers = authHeaders(ctx);
  await limiter.acquire();
  const res = await apiFetch(THREATFOX_API, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...headers,
    },
    body: JSON.stringify(body),
  }, { beforeRetry: (signal) => limiter.acquire(signal) });
  if (!res.ok) {
    throw new Error(`ThreatFox API error: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

async function urlhausPost(
  path: string,
  params: Record<string, string>,
  ctx: ToolContext,
): Promise<unknown> {
  const headers = authHeaders(ctx);
  await limiter.acquire();
  const body = new URLSearchParams(params);
  const res = await apiFetch(`${URLHAUS_API}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      ...headers,
    },
    body: body.toString(),
  }, { beforeRetry: (signal) => limiter.acquire(signal) });
  if (!res.ok) {
    throw new Error(`URLhaus API error: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

async function bazaarPost(
  params: Record<string, string>,
  ctx: ToolContext,
): Promise<unknown> {
  const headers = authHeaders(ctx);
  await limiter.acquire();
  const body = new URLSearchParams(params);
  const res = await apiFetch(BAZAAR_API, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      ...headers,
    },
    body: body.toString(),
  }, { beforeRetry: (signal) => limiter.acquire(signal) });
  if (!res.ok) {
    throw new Error(`MalwareBazaar API error: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

// ─── ThreatFox Tools ───

const threatfoxGetIocs: ToolDef = {
  name: "threatfoxGetIocs",
  description:
    "Get recent IOCs from ThreatFox (abuse.ch). Returns indicators of compromise reported in the last N days.",
  schema: {
    days: z.number().int().min(1).max(7).default(3).describe("Number of days to look back (1-7, default 3)"),
  },
  async execute(args, ctx): Promise<ToolResult> {
    const days = (args.days as number) ?? 3;
    if (!Number.isInteger(days) || days < 1 || days > 7) {
      throw new Error("ThreatFox days must be an integer between 1 and 7.");
    }
    const cacheKey = `${keyScope(ctx.config.abusechAuthKey)}:threatfox:iocs:${days}`;
    const cached = cache.get(cacheKey);
    if (cached) return cached;

    const data = await threatfoxPost({ query: "get_iocs", days }, ctx);
    const result = json(data);
    cache.set(cacheKey, result);
    return result;
  },
};

const threatfoxSearch: ToolDef = {
  name: "threatfoxSearch",
  description:
    "Search ThreatFox IOCs by term. Accepts IP addresses, domain names, hashes (MD5/SHA256), or URLs.",
  schema: {
    searchTerm: z.string().describe("Search term: IP, domain, hash (MD5/SHA256), or URL"),
  },
  async execute(args, ctx): Promise<ToolResult> {
    const searchTerm = args.searchTerm as string;
    const cacheKey = `${keyScope(ctx.config.abusechAuthKey)}:threatfox:search:${searchTerm}`;
    const cached = cache.get(cacheKey);
    if (cached) return cached;

    // File hashes have a dedicated endpoint; IOC search targets domains/IPs/URLs.
    const isFileHash = /^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{64})$/.test(searchTerm);
    const data = await threatfoxPost(
      isFileHash
        ? { query: "search_hash", hash: searchTerm }
        : { query: "search_ioc", search_term: searchTerm },
      ctx,
    );
    const result = json(data);
    cache.set(cacheKey, result);
    return result;
  },
};

const threatfoxTag: ToolDef = {
  name: "threatfoxTag",
  description:
    'Search ThreatFox IOCs by tag (e.g., "Cobalt Strike", "Emotet", "AgentTesla").',
  schema: {
    tag: z.string().describe("Tag to search for (e.g., Cobalt Strike, Emotet)"),
    limit: z.number().min(1).max(1000).default(100).describe("Max results to return (1-1000, default 100)"),
  },
  async execute(args, ctx): Promise<ToolResult> {
    const tag = args.tag as string;
    const limit = (args.limit as number) ?? 100;
    const cacheKey = `${keyScope(ctx.config.abusechAuthKey)}:threatfox:tag:${tag}:${limit}`;
    const cached = cache.get(cacheKey);
    if (cached) return cached;

    const data = await threatfoxPost(
      { query: "taginfo", tag, limit },
      ctx,
    );
    const result = json(data);
    cache.set(cacheKey, result);
    return result;
  },
};

const threatfoxMalware: ToolDef = {
  name: "threatfoxMalware",
  description:
    "Search ThreatFox IOCs by malware family using Malpedia naming convention (e.g., \"win.cobalt_strike\", \"win.emotet\").",
  schema: {
    malware: z.string().describe("Malware family name in Malpedia format (e.g., win.cobalt_strike)"),
    limit: z.number().min(1).max(1000).default(100).describe("Max results to return (1-1000, default 100)"),
  },
  async execute(args, ctx): Promise<ToolResult> {
    const malware = args.malware as string;
    const limit = (args.limit as number) ?? 100;
    const cacheKey = `${keyScope(ctx.config.abusechAuthKey)}:threatfox:malware:${malware}:${limit}`;
    const cached = cache.get(cacheKey);
    if (cached) return cached;

    const data = await threatfoxPost(
      { query: "malwareinfo", malware, limit },
      ctx,
    );
    const result = json(data);
    cache.set(cacheKey, result);
    return result;
  },
};

// ─── URLhaus Tools ───

const urlhausLookup: ToolDef = {
  name: "urlhausLookup",
  description:
    "Look up a URL or host in URLhaus (abuse.ch). Provide either a full URL for URL lookup or a hostname/IP for host lookup.",
  schema: {
    url: z.string().trim().min(1).optional().describe("Full URL to look up (e.g., http://evil.com/malware.exe); provide exactly one of url or host"),
    host: z.string().trim().min(1).optional().describe("Hostname or IP to look up (e.g., evil.com or 1.2.3.4); provide exactly one of url or host"),
  },
  async execute(args, ctx): Promise<ToolResult> {
    const url = (args.url as string | undefined)?.trim();
    const host = (args.host as string | undefined)?.trim();

    if (Boolean(url) === Boolean(host)) {
      throw new Error("Provide exactly one non-empty 'url' or 'host' parameter.");
    }

    if (url) {
      const cacheKey = `${keyScope(ctx.config.abusechAuthKey)}:urlhaus:url:${url}`;
      const cached = cache.get(cacheKey);
      if (cached) return cached;

      const data = await urlhausPost("/url/", { url }, ctx);
      const result = json(data);
      cache.set(cacheKey, result);
      return result;
    }

    const cacheKey = `${keyScope(ctx.config.abusechAuthKey)}:urlhaus:host:${host}`;
    const cached = cache.get(cacheKey);
    if (cached) return cached;

    const data = await urlhausPost("/host/", { host: host! }, ctx);
    const result = json(data);
    cache.set(cacheKey, result);
    return result;
  },
};

const urlhausTag: ToolDef = {
  name: "urlhausTag",
  description:
    "Search URLhaus (abuse.ch) entries by tag (e.g., \"Emotet\", \"Dridex\", \"elf\").",
  schema: {
    tag: z.string().describe("Tag to search for in URLhaus"),
  },
  async execute(args, ctx): Promise<ToolResult> {
    const tag = args.tag as string;
    const cacheKey = `${keyScope(ctx.config.abusechAuthKey)}:urlhaus:tag:${tag}`;
    const cached = cache.get(cacheKey);
    if (cached) return cached;

    const data = await urlhausPost("/tag/", { tag }, ctx);
    const result = json(data);
    cache.set(cacheKey, result);
    return result;
  },
};

// ─── MalwareBazaar Tools ───

const bazaarHash: ToolDef = {
  name: "bazaarHash",
  description:
    "Look up a malware sample in MalwareBazaar (abuse.ch) by hash. Accepts MD5, SHA1, or SHA256.",
  schema: {
    hash: z.string().describe("MD5, SHA1, or SHA256 hash of the malware sample"),
  },
  async execute(args, ctx): Promise<ToolResult> {
    const hash = args.hash as string;
    const cacheKey = `${keyScope(ctx.config.abusechAuthKey)}:bazaar:hash:${hash}`;
    const cached = cache.get(cacheKey);
    if (cached) return cached;

    const data = await bazaarPost(
      { query: "get_info", hash },
      ctx,
    );
    const result = json(data);
    cache.set(cacheKey, result);
    return result;
  },
};

const bazaarRecent: ToolDef = {
  name: "bazaarRecent",
  description:
    "Get recent malware samples from MalwareBazaar (abuse.ch). Returns the most recently submitted samples.",
  schema: {
    selector: z.string().default("time").describe("Selector for recent samples (default: time)"),
  },
  async execute(args, ctx): Promise<ToolResult> {
    const selector = (args.selector as string) ?? "time";
    const cacheKey = `${keyScope(ctx.config.abusechAuthKey)}:bazaar:recent:${selector}`;
    const cached = cache.get(cacheKey);
    if (cached) return cached;

    const data = await bazaarPost(
      { query: "get_recent", selector },
      ctx,
    );
    const result = json(data);
    cache.set(cacheKey, result);
    return result;
  },
};

const bazaarTag: ToolDef = {
  name: "bazaarTag",
  description:
    "Search MalwareBazaar (abuse.ch) by tag or malware family signature name. Provide exactly one of 'tag' or 'signature'.",
  schema: {
    tag: z.string().trim().min(1).optional().describe("Tag to search for (e.g., Emotet, AgentTesla); provide exactly one of tag or signature"),
    signature: z.string().trim().min(1).optional().describe("Malware family signature name to search for; provide exactly one of tag or signature"),
  },
  async execute(args, ctx): Promise<ToolResult> {
    const tag = (args.tag as string | undefined)?.trim();
    const signature = (args.signature as string | undefined)?.trim();

    if (Boolean(tag) === Boolean(signature)) {
      throw new Error("Provide exactly one non-empty 'tag' or 'signature' parameter.");
    }

    if (tag) {
      const cacheKey = `${keyScope(ctx.config.abusechAuthKey)}:bazaar:tag:${tag}`;
      const cached = cache.get(cacheKey);
      if (cached) return cached;

      const data = await bazaarPost(
        { query: "get_taginfo", tag },
        ctx,
      );
      const result = json(data);
      cache.set(cacheKey, result);
      return result;
    }

    const cacheKey = `${keyScope(ctx.config.abusechAuthKey)}:bazaar:sig:${signature}`;
    const cached = cache.get(cacheKey);
    if (cached) return cached;

    const data = await bazaarPost(
      { query: "get_siginfo", signature: signature! },
      ctx,
    );
    const result = json(data);
    cache.set(cacheKey, result);
    return result;
  },
};

// ─── Export ───

export const abusechTools: ToolDef[] = [
  // ThreatFox
  threatfoxGetIocs,
  threatfoxSearch,
  threatfoxTag,
  threatfoxMalware,
  // URLhaus
  urlhausLookup,
  urlhausTag,
  // MalwareBazaar
  bazaarHash,
  bazaarRecent,
  bazaarTag,
].map((tool): ToolDef => ({
  ...tool,
  description: `${tool.description} Requires ABUSECH_AUTH_KEY.`,
  async execute(args, ctx): Promise<ToolResult> {
    // Validate credentials before cache access as well as before network access.
    authHeaders(ctx);
    return tool.execute(args, ctx);
  },
}));
