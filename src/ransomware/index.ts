import { createHash } from "node:crypto";
import { apiFetch } from "../utils/http.js";
import { z } from "zod";
import { RateLimiter } from "../utils/rate-limiter.js";
import { TTLCache } from "../utils/cache.js";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json } from "../types/index.js";

// ─── Constants ───

const RANSOMWARE_LIVE_BASE = "https://api.ransomware.live/v2";
const RANSOMLOOK_BASE = "https://www.ransomlook.io/api";

const FIFTEEN_MIN = 15 * 60 * 1000;

// ─── Rate Limiters ───

// Official /api page: API v2 allows one request/minute per endpoint.
const ransomwareLiveLimiters = new Map<string, RateLimiter>();
function liveLimiter(path: string): RateLimiter {
  const endpoint = path.split("/")[1]!;
  let limiter = ransomwareLiveLimiters.get(endpoint);
  if (!limiter) { limiter = new RateLimiter(60_000); ransomwareLiveLimiters.set(endpoint, limiter); }
  return limiter;
}
const ransomwareProRL = new RateLimiter(500);
const ransomlookRL = new RateLimiter(500);

// ─── Cache ───

const cache = new TTLCache<unknown>(FIFTEEN_MIN);
const collectionMetadata = new WeakMap<unknown[], { providerCount: number | null; providerTruncated: boolean }>();

// ─── Types ───

interface RansomwareVictim {
  name: string;
  group: string;
  url: string;
  country: string;
  sector: string;
  published: string;
  discovered: string;
  description: string;
  website: string;
  [key: string]: unknown;
}

interface RansomwareGroupProfile {
  name: string;
  url: string;
  description: string;
  locations: unknown[];
  profile: unknown[];
  [key: string]: unknown;
}

// /api/groups returns names, not group profiles (official genericapi.py).
const ransomlookGroupSchema = z.array(z.string().min(1));
const ransomlookPostSchema = z.array(z.object({
  group_name: z.string().min(1), post_title: z.string(), discovered: z.string(),
  link: z.string().optional(), post_url: z.string().optional(),
}).passthrough()).max(100);


// ─── HTTP Helpers ───

async function fetchRansomwareLive<T>(path: string, ctx: ToolContext, proPath: string): Promise<T> {
  const apiKey = ctx.config.ransomwareLiveApiKey;
  const sourcePath = apiKey ? proPath : path;
  const backend = apiKey ? "pro" : "v2";
  const scope = apiKey ? createHash("sha256").update(apiKey).digest("hex") : "public";
  const cacheKey = `rwlive:${backend}:${scope}:${sourcePath}`;
  const cached = cache.get(cacheKey);
  if (cached !== undefined) return cached as T;

  const limiter = apiKey ? ransomwareProRL : liveLimiter(path);
  await limiter.acquire();

  const url = apiKey ? `https://api-pro.ransomware.live${proPath}` : `${RANSOMWARE_LIVE_BASE}${path}`;
  const res = await apiFetch(url, {
    headers: { Accept: "application/json", "User-Agent": "darknet-mcp/0.1.0", ...(apiKey ? { "X-API-KEY": apiKey } : {}) },
    redirect: "error",
  }, { beforeRetry: (signal) => limiter.acquire(signal) });

  if (!res.ok) {
    throw new Error(`ransomware.live API error: HTTP ${res.status} ${res.statusText}`);
  }

  const raw: unknown = await res.json();
  const isGroup = path.startsWith("/group/");
  const data = isGroup ? normalizeGroup(raw) : path === "/groups" ? normalizeGroups(unwrapList(raw, "groups")) : normalizeVictims(unwrapList(raw, "victims"));
  if (Array.isArray(data)) {
    const envelope = Array.isArray(raw) ? undefined : record(raw);
    const count = envelope?.count;
    if (count !== undefined && (!Number.isSafeInteger(count) || (count as number) < data.length)) throw new Error("ransomware.live returned an invalid collection count");
    const providerCount = typeof count === "number" ? count : null;
    collectionMetadata.set(data, { providerCount, providerTruncated: providerCount !== null && providerCount > data.length });
  }
  cache.set(cacheKey, data);
  return data as T;
}

function unwrapList(raw: unknown, field: "victims" | "groups"): unknown[] {
  if (Array.isArray(raw)) return raw;
  const envelope = record(raw);
  if (!Array.isArray(envelope[field])) throw new Error(`ransomware.live returned an invalid ${field} envelope`);
  return envelope[field] as unknown[];
}
function record(raw: unknown): Record<string, unknown> {
  if (!raw || typeof raw !== "object" || Array.isArray(raw) || "error" in raw || "errors" in raw) throw new Error("ransomware.live returned an invalid provider response");
  return raw as Record<string, unknown>;
}
function firstText(raw: Record<string, unknown>, ...keys: string[]): string {
  for (const key of keys) if (typeof raw[key] === "string" && raw[key]) return raw[key] as string;
  return "";
}
function normalizeGroup(raw: unknown): RansomwareGroupProfile {
  const envelope = record(raw);
  const value = envelope.group && typeof envelope.group === "object" ? record(envelope.group) : envelope;
  const { client: _client, ...metadata } = value;
  const name = firstText(value, "name", "group", "group_name");
  if (!name) throw new Error("ransomware.live returned an invalid group profile");
  return { ...metadata, name, url: firstText(value, "url"), description: firstText(value, "description", "meta"), locations: value.locations ?? [], profile: value.profile ?? [] } as RansomwareGroupProfile;
}
function normalizeGroups(raw: unknown): RansomwareGroupProfile[] {
  if (!Array.isArray(raw)) throw new Error("ransomware.live returned an invalid groups response");
  return raw.map(normalizeGroup);
}
function normalizeVictims(raw: unknown): RansomwareVictim[] {
  if (!Array.isArray(raw)) throw new Error("ransomware.live returned an invalid victims response");
  return raw.map((entry) => {
    const value = record(entry);
    const name = firstText(value, "victim", "post_title", "name");
    if (!name) throw new Error("ransomware.live returned a victim without a name");
    return {
      ...value, name, group: firstText(value, "group", "group_name"),
      sector: firstText(value, "activity", "sector"), country: firstText(value, "country"),
      published: firstText(value, "published", "attackdate"), discovered: firstText(value, "discovered"),
      description: firstText(value, "description"), website: firstText(value, "website"),
      url: firstText(value, "claim_url", "post_url", "url", "link", "permalink"),
    };
  });
}

async function fetchRansomlook<T>(path: string): Promise<T> {
  const cacheKey = `ransomlook:${path}`;
  const cached = cache.get(cacheKey);
  if (cached !== undefined) return cached as T;

  await ransomlookRL.acquire();

  const url = `${RANSOMLOOK_BASE}${path}`;
  const res = await apiFetch(url, {
    headers: { Accept: "application/json", "User-Agent": "darknet-mcp/0.1.0" },
  }, { beforeRetry: (signal) => ransomlookRL.acquire(signal) });

  if (!res.ok) {
    throw new Error(`RansomLook API error: HTTP ${res.status} ${res.statusText}`);
  }

  const raw: unknown = await res.json();
  const parsed = (path === "/groups" ? ransomlookGroupSchema : ransomlookPostSchema).safeParse(raw);
  if (!parsed.success) throw new Error(`RansomLook returned an invalid ${path === "/groups" ? "groups" : "recent-posts"} response`);
  cache.set(cacheKey, parsed.data);
  return parsed.data as T;
}

const paginationSchema = {
  limit: z.number().int().min(1).max(200).default(100).describe("Maximum returned records per page (1-200; default 100)"),
  offset: z.number().int().min(0).max(1_000_000).default(0).describe("Local result offset for the provider's cached response (default 0)"),
};
function paginate<T>(rows: T[], args: Record<string, unknown>, recent = false) {
  const limit = paginationSchema.limit.parse(args.limit);
  const offset = paginationSchema.offset.parse(args.offset);
  const items = rows.slice(offset, offset + limit);
  const provider = collectionMetadata.get(rows);
  const truncated = offset > 0 || items.length < rows.length || provider?.providerTruncated === true;
  return { items, metadata: {
    total: provider?.providerCount ?? rows.length,
    available_count: rows.length, provider_count: provider?.providerCount ?? null,
    count_basis: provider?.providerCount !== null && provider?.providerCount !== undefined ? "provider_count" : "returned_records",
    provider_truncated: provider?.providerTruncated ?? false,
    result_count: items.length, limit, offset,
    next_offset: offset + items.length < rows.length ? offset + items.length : null,
    complete: !recent && !truncated, truncated,
    coverage: recent ? "latest_victims" : "provider_results",
  } };
}

// ─── Tool Implementations ───

/**
 * 1. ransomwareRecent - Recent ransomware victims
 */
export const ransomwareRecent: ToolDef = {
  name: "ransomwareRecent",
  description:
    "Fetch the most recent ransomware victims from ransomware.live. Returns victim name, group, country, sector, publication date, and associated URLs.",
  schema: { ...paginationSchema },
  async execute(args: Record<string, unknown>, ctx: ToolContext): Promise<ToolResult> {
    const victims = await fetchRansomwareLive<RansomwareVictim[]>("/recentvictims", ctx, "/victims/recent");
    const page = paginate(victims, args, true);
    return json({
      backend: ctx.config.ransomwareLiveApiKey ? "pro" : "v2",
      ...page.metadata,
      victims: page.items.map((v) => ({
        name: v.name,
        group: v.group,
        country: v.country,
        sector: v.sector,
        published: v.published,
        discovered: v.discovered,
        description: v.description,
        website: v.website,
        url: v.url,
        permalink: v.permalink,
        id: v.id,
      })),
    });
  },
};

/**
 * 2. ransomwareGroups - List all ransomware groups
 */
export const ransomwareGroups: ToolDef = {
  name: "ransomwareGroups",
  description:
    "List all known ransomware groups tracked by ransomware.live. Returns group names, descriptions, onion URLs, and profile information.",
  schema: { ...paginationSchema },
  async execute(args: Record<string, unknown>, ctx: ToolContext): Promise<ToolResult> {
    const groups = await fetchRansomwareLive<RansomwareGroupProfile[]>("/groups", ctx, "/groups");
    const page = paginate(groups, args);
    return json({
      backend: ctx.config.ransomwareLiveApiKey ? "pro" : "v2",
      ...page.metadata,
      groups: page.items.map((g) => ({
        ...g,
        name: g.name,
        url: g.url,
        description: g.description,
        locations: g.locations,
        profile: g.profile,
      })),
    });
  },
};

/**
 * 3. ransomwareGroup - Get specific group profile
 */
export const ransomwareGroup: ToolDef = {
  name: "ransomwareGroup",
  description:
    "Get a detailed profile for a specific ransomware group by name. Includes description, known URLs, locations, and profile metadata.",
  schema: {
    name: z.string().trim().min(1).max(100).describe("Ransomware group name (e.g. 'lockbit3', 'clop', 'blackcat')"),
  },
  async execute(args: Record<string, unknown>, ctx: ToolContext): Promise<ToolResult> {
    const name = args.name as string;
    const group = await fetchRansomwareLive<RansomwareGroupProfile>(`/group/${encodeURIComponent(name)}`, ctx, `/groups/${encodeURIComponent(name)}`);
    return json({
      ...group,
      backend: ctx.config.ransomwareLiveApiKey ? "pro" : "v2",
      name: group.name,
      url: group.url,
      description: group.description,
      locations: group.locations,
      profile: group.profile,
    });
  },
};

/**
 * 4. ransomwareGroupVictims - Victims of a specific group
 */
export const ransomwareGroupVictims: ToolDef = {
  name: "ransomwareGroupVictims",
  description:
    "Get all victims claimed by a specific ransomware group. Returns victim names, countries, sectors, and publication dates.",
  schema: {
    ...paginationSchema,
    name: z.string().trim().min(1).max(100).describe("Ransomware group name (e.g. 'lockbit3', 'clop', 'blackcat')"),
  },
  async execute(args: Record<string, unknown>, ctx: ToolContext): Promise<ToolResult> {
    const name = args.name as string;
    const victims = await fetchRansomwareLive<RansomwareVictim[]>(`/groupvictims/${encodeURIComponent(name)}`, ctx, `/victims/?${new URLSearchParams({ group: name })}`);
    const page = paginate(victims, args, false);
    return json({
      group: name,
      backend: ctx.config.ransomwareLiveApiKey ? "pro" : "v2",
      ...page.metadata,
      victims: page.items.map((v) => ({
        name: v.name,
        country: v.country,
        sector: v.sector,
        published: v.published,
        discovered: v.discovered,
        description: v.description,
        website: v.website,
        url: v.url,
        permalink: v.permalink,
        id: v.id,
      })),
    });
  },
};

/**
 * 5. ransomwareSearch - Search victims by keyword
 */
export const ransomwareSearch: ToolDef = {
  name: "ransomwareSearch",
  description:
    "Search ransomware victims by keyword. Matches against victim names, descriptions, and other fields. Useful for checking if a specific company has been listed as a victim.",
  schema: {
    ...paginationSchema,
    keyword: z.string().trim().min(1).max(200).describe("Search keyword (company name, domain, or other identifier)"),
  },
  async execute(args: Record<string, unknown>, ctx: ToolContext): Promise<ToolResult> {
    const keyword = args.keyword as string;
    const results = await fetchRansomwareLive<RansomwareVictim[]>(
      `/searchvictims/${encodeURIComponent(keyword)}`, ctx, `/victims/search?${new URLSearchParams({ q: keyword })}`,
    );
    const page = paginate(results, args, false);
    return json({
      keyword,
      backend: ctx.config.ransomwareLiveApiKey ? "pro" : "v2",
      ...page.metadata,
      victims: page.items.map((v) => ({
        name: v.name,
        group: v.group,
        country: v.country,
        sector: v.sector,
        published: v.published,
        discovered: v.discovered,
        description: v.description,
        website: v.website,
        url: v.url,
        permalink: v.permalink,
        id: v.id,
      })),
    });
  },
};

/**
 * 6. ransomwareByCountry - Victims by country ISO code
 */
export const ransomwareByCountry: ToolDef = {
  name: "ransomwareByCountry",
  description:
    "Get ransomware victims filtered by country using ISO 3166-1 alpha-2 country code. Example codes: US, GB, DE, TR, FR, JP.",
  schema: {
    ...paginationSchema,
    countryCode: z
      .string()
      .regex(/^[A-Za-z]{2}$/)
      .describe("ISO 3166-1 alpha-2 country code (e.g. 'US', 'GB', 'DE', 'TR')"),
  },
  async execute(args: Record<string, unknown>, ctx: ToolContext): Promise<ToolResult> {
    const code = (args.countryCode as string).toUpperCase();
    const victims = await fetchRansomwareLive<RansomwareVictim[]>(
      `/countryvictims/${encodeURIComponent(code)}`, ctx, `/victims/?${new URLSearchParams({ country: code })}`,
    );
    const page = paginate(victims, args, false);
    return json({
      country: code,
      backend: ctx.config.ransomwareLiveApiKey ? "pro" : "v2",
      ...page.metadata,
      victims: page.items.map((v) => ({
        name: v.name,
        group: v.group,
        sector: v.sector,
        published: v.published,
        discovered: v.discovered,
        description: v.description,
        website: v.website,
        url: v.url,
        permalink: v.permalink,
        id: v.id,
      })),
    });
  },
};

/**
 * 7. ransomwareBySector - Victims by sector/industry
 */
export const ransomwareBySector: ToolDef = {
  name: "ransomwareBySector",
  description:
    "Get ransomware victims filtered by sector or industry. Examples: 'healthcare', 'finance', 'education', 'government', 'technology'.",
  schema: {
    ...paginationSchema,
    sector: z.string().trim().min(1).max(100).describe("Sector or industry name (e.g. 'healthcare', 'finance', 'education')"),
  },
  async execute(args: Record<string, unknown>, ctx: ToolContext): Promise<ToolResult> {
    const sector = args.sector as string;
    const victims = await fetchRansomwareLive<RansomwareVictim[]>(
      `/sectorvictims/${encodeURIComponent(sector)}`, ctx, `/victims/?${new URLSearchParams({ sector })}`,
    );
    const page = paginate(victims, args, false);
    return json({
      sector,
      backend: ctx.config.ransomwareLiveApiKey ? "pro" : "v2",
      ...page.metadata,
      victims: page.items.map((v) => ({
        name: v.name,
        group: v.group,
        country: v.country,
        published: v.published,
        discovered: v.discovered,
        description: v.description,
        website: v.website,
        url: v.url,
        permalink: v.permalink,
        id: v.id,
      })),
    });
  },
};

/**
 * 8. ransomlookGroups - Groups from RansomLook API
 */
export const ransomlookGroups: ToolDef = {
  name: "ransomlookGroups",
  description:
    "List the ransomware group names tracked by RansomLook. The public groups endpoint returns names only; it does not supply group URLs or profiles.",
  schema: {},
  async execute(_args: Record<string, unknown>, ctx: ToolContext): Promise<ToolResult> {
    const parsed = ransomlookGroupSchema.safeParse(await fetchRansomlook<unknown>("/groups"));
    if (!parsed.success) throw new Error("RansomLook returned an invalid groups response");
    return json({ total: parsed.data.length, groups: parsed.data.map((name) => ({ name })) });
  },
};

/**
 * 9. ransomlookRecent - Recent posts from RansomLook
 */
export const ransomlookRecent: ToolDef = {
  name: "ransomlookRecent",
  description:
    "Fetch the most recent ransomware posts and victim claims from RansomLook. Returns group name, post title, URL, and discovery timestamp.",
  schema: {},
  async execute(_args: Record<string, unknown>, ctx: ToolContext): Promise<ToolResult> {
    const parsed = ransomlookPostSchema.safeParse(await fetchRansomlook<unknown>("/recent"));
    if (!parsed.success) throw new Error("RansomLook returned an invalid recent-posts response");
    return json({
      total: parsed.data.length,
      coverage: "latest_posts",
      complete: false,
      posts: parsed.data.map((p) => ({ ...p, post_url: p.link ?? p.post_url ?? null })),
    });
  },
};

// ─── Export All Tools ───

export const allTools: ToolDef[] = [
  ransomwareRecent,
  ransomwareGroups,
  ransomwareGroup,
  ransomwareGroupVictims,
  ransomwareSearch,
  ransomwareByCountry,
  ransomwareBySector,
  ransomlookGroups,
  ransomlookRecent,
];
