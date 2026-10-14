import { isIP } from "node:net";
import { domainToASCII } from "node:url";
import { normalizeBitcoin, normalizeOnion } from "./validation.js";
import type { Indicator, InvestigationSource, TargetType } from "./types.js";

const HASH = /^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i;
const CVE = /^CVE-\d{4}-\d{4,19}$/i;
const EMAIL = /[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9-]+(?:\.[A-Z0-9-]+)+/gi;
const SENSITIVE_KEY = /password|passwd|(?:^|_)pwd(?:$|_)|token|secret|api.?key|auth.?key|authorization|cookie|credential|top.?logins|^login$|username|^emails?$|^account$|computer.?name|author.?name|^owner$|full.?name|first.?name|last.?name|phone|street.?address|home.?address|malware.?path|submit.?name|^(?:raw|body|content|document|snippet|text)$/i;
const RECORD_FIELDS: Record<InvestigationSource, readonly string[]> = {
  ransomware: ["name", "group", "country", "sector", "published", "discovered", "website", "url"],
  ransomlook: ["group_name", "post_title", "post_url", "link", "discovered", "site", "published"],
  threatfox: ["id", "ioc", "ioc_type", "threat_type", "malware", "malware_printable", "confidence_level", "first_seen", "last_seen", "reference", "tags"],
  urlhaus: ["id", "url", "url_status", "host", "dateadded", "firstseen", "last_online", "threat", "tags", "urlhaus_reference", "url_count", "blacklists", "payloads"],
  otx: ["id", "name", "created", "modified", "tags", "malware_families", "attack_ids", "industries", "TLP", "adversary", "indicator_count", "indicators"],
  stealer: ["date_compromised", "url", "operating_system", "antiviruses", "ip", "computer_name", "top_logins", "top_passwords", "malware_path"],
  hibp: ["Name", "Title", "Domain", "BreachDate", "AddedDate", "ModifiedDate", "PwnCount", "DataClasses", "IsVerified", "IsFabricated", "IsSensitive", "IsRetired", "IsSpamList", "Source", "Id", "Date", "EmailCount"],
  intelx: ["systemid", "intelxid", "bucket", "added", "date", "media", "type", "typeh", "accesslevel", "accesslevelh"],
  abuseipdb: ["ipAddress", "isPublic", "ipVersion", "isWhitelisted", "abuseConfidenceScore", "countryCode", "countryName", "usageType", "isp", "domain", "hostnames", "isTor", "totalReports", "numDistinctUsers", "lastReportedAt"],
  greynoise: ["ip", "noise", "riot", "classification", "name", "link", "last_seen"],
  bazaar: ["sha256_hash", "sha1_hash", "md5_hash", "first_seen", "last_seen", "file_size", "file_type", "file_type_mime", "signature", "tags", "delivery_method", "intelligence", "yara_rules"],
  hybrid: ["sha256", "sha1", "md5", "verdict", "av_detect", "threat_score", "vx_family", "type", "type_short", "environment_description", "environment_id", "analysis_start_time", "size", "tags"],
  tor: ["socksAvailable", "socksHost", "socksPort", "url", "statusCode", "title", "fetchTimeMs"],
  onionlookup: ["address", "lookup_status", "first_seen", "last_seen", "last_check", "status", "tags", "pgp", "certificates", "ports", "base_url", "title", "bitcoin_addresses", "metadata"],
  blockchain: ["address", "hash160", "n_tx", "n_unredeemed", "total_received", "total_sent", "final_balance", "txs"],
  chainabuse: ["id", "address", "chain", "category", "createdAt", "scamType", "scamCategory", "reportedAddress", "reportedAddresses", "reportDate", "trusted", "checked"],
  vulners: ["id", "title", "type", "bulletinFamily", "cvss", "cvss3", "cvss4", "published", "modified", "href", "sourceHref", "cvelist"],
  phishing: ["url", "in_database", "phish_id", "phish_detail_page", "verified", "verified_at", "valid"],
  pulsedive: ["iid", "type", "indicator", "risk", "risk_recommended", "retired", "stamp_added", "stamp_updated", "stamp_seen", "summary", "threats", "feeds", "attributes", "properties"],
};

export function normalizeDomain(value: string): string | null {
  const normalized = domainToASCII(value.replace(/\.$/, "").toLowerCase());
  if (!normalized || normalized.length > 253 || normalized.endsWith(".onion") || isIP(normalized)) return null;
  const labels = normalized.split(".");
  if (labels.length < 2 || /^\d+$/.test(labels.at(-1)!)) return null;
  return labels.every((label) => label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)) ? normalized : null;
}

export function normalizeTarget(raw: string, requested: TargetType | "auto" = "auto"): { value: string; type: TargetType } {
  const value = raw.trim();
  if (!value || value.length > 2048 || /[\s\\\u0000-\u001f\u007f]/.test(value)) throw new Error("Provide one valid investigation target without whitespace or control characters.");
  if (/^https?:\/\//i.test(value)) {
    let url: URL;
    try { url = new URL(value); } catch { throw new Error("Target is not a valid HTTP/HTTPS URL."); }
    if (url.username || url.password || url.hash) throw new Error("URL credentials and fragments are not accepted.");
    const onion = normalizeOnion(url.hostname);
    const type = onion ? "onion" : "url";
    if (!onion && !normalizeDomain(url.hostname) && !isIP(url.hostname.replace(/^\[|\]$/g, ""))) throw new Error("URL must have a valid domain, IP address, or checksum-valid v3 onion hostname.");
    if (requested !== "auto" && requested !== type) throw new Error(`Target is not a valid ${requested}.`);
    return { type, value: url.href };
  }
  if (/[/%?#]/.test(value)) throw new Error("Malformed investigation target; URLs must include http:// or https://.");
  const ipVersion = isIP(value);
  const domain = normalizeDomain(value);
  const onion = normalizeOnion(value);
  const bitcoin = normalizeBitcoin(value);
  const at = value.lastIndexOf("@");
  const emailDomain = at > 0 ? normalizeDomain(value.slice(at + 1)) : null;
  const email = value.length <= 320 && emailDomain && /^[A-Za-z0-9.!$&'*+=^_`{|}~-]+$/.test(value.slice(0, at)) && value.slice(0, at).length <= 64 && !value.slice(0, at).startsWith(".") && !value.slice(0, at).endsWith(".") && !value.slice(0, at).includes("..") ? `${value.slice(0, at)}@${emailDomain}` : null;
  const inferred: TargetType | null = ipVersion ? "ip" : HASH.test(value) ? "hash" : CVE.test(value) ? "cve" : onion ? "onion" : bitcoin ? "bitcoin" : email ? "email" : domain ? "domain" : null;
  if (!inferred || (requested !== "auto" && inferred !== requested)) throw new Error(`Target is not a valid ${requested === "auto" ? "domain, email, IP, file hash, URL, v3 onion, mainnet Bitcoin address, or CVE" : requested}.`);
  return { type: inferred, value: inferred === "domain" ? domain! : inferred === "email" ? email! : inferred === "hash" ? value.toLowerCase() : inferred === "cve" ? value.toUpperCase() : inferred === "onion" ? onion! : inferred === "bitcoin" ? bitcoin! : ipVersion === 6 ? new URL(`http://[${value}]`).hostname.slice(1, -1) : value };
}

/** A global traversal budget prevents multiplicatively large provider metadata. */
export function redactMetadata(value: unknown, depth = 0): unknown {
  const budget = { nodes: 300, characters: 6000 };
  function clean(item: unknown, level: number): unknown {
    if (level > 6 || --budget.nodes < 0 || budget.characters <= 0) return "[TRUNCATED]";
    if (typeof item === "string") {
      const sanitized = item.replace(/(https?:\/\/)[^\s/@]+:[^\s/@]+@/gi, "$1[REDACTED]@")
        .replace(/(https?:\/\/[^\s?#]+)[?#][^\s]*/gi, "$1?[REDACTED QUERY]")
        .replace(EMAIL, "[REDACTED EMAIL]")
        .replace(/\b(?:password|passwd|token|secret|api[-_]?key|auth[-_]?key)\s*[:=]\s*[^\s,;]+/gi, "[REDACTED SECRET]")
        .replace(/\bBearer\s+[A-Za-z0-9._~+\/-]+/gi, "Bearer [REDACTED]");
      const limit = Math.min(1000, budget.characters);
      budget.characters -= Math.min(sanitized.length, limit);
      return sanitized.length > limit ? sanitized.slice(0, Math.max(0, limit - 11)) + "[TRUNCATED]" : sanitized;
    }
    if (typeof item === "number") return Number.isFinite(item) ? item : null;
    if (typeof item === "boolean" || item === null) return item;
    if (Array.isArray(item)) {
      const result: unknown[] = [];
      for (const child of item.slice(0, 25)) { if (budget.nodes <= 0 || budget.characters <= 0) break; result.push(clean(child, level + 1)); }
      return result;
    }
    if (typeof item === "object" && item !== null) {
      const result: Record<string, unknown> = {};
      for (const [key, child] of Object.entries(item).slice(0, 40)) {
        if (budget.nodes <= 0 || budget.characters <= 0) break;
        if (key.length > 80 || ["__proto__", "constructor", "prototype"].includes(key)) continue;
        result[key] = SENSITIVE_KEY.test(key) ? "[REDACTED]" : clean(child, level + 1);
      }
      return result;
    }
    return null;
  }
  return clean(value, depth);
}

/** Retain known metadata only, never raw documents, page bodies, scripts or arbitrary response bodies. */
export function projectEvidence(source: InvestigationSource, value: unknown): unknown {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return {};
  const record = value as Record<string, unknown>;
  const projected: Record<string, unknown> = {};
  for (const key of RECORD_FIELDS[source]) if (Object.prototype.hasOwnProperty.call(record, key)) projected[key] = record[key];
  const clean = redactMetadata(projected) as Record<string, unknown>;
  // UTF-8 strings and nested structures are additionally bounded in bytes.
  while (Buffer.byteLength(JSON.stringify(clean)) > 8192) { const key = Object.keys(clean).at(-1); if (!key) break; delete clean[key]; }
  return clean;
}

export function extractIndicators(value: unknown, source?: InvestigationSource): Indicator[] {
  const found = new Map<string, Indicator>();
  function add(candidate: string): void {
    if (candidate.includes("[REDACTED") || candidate.includes("[TRUNCATED")) return;
    try {
      const normalized = normalizeTarget(candidate);
      if (normalized.type === "email" || (source === "blockchain" && normalized.type === "hash")) return;
      if (normalized.type === "url" || /^https?:\/\//i.test(normalized.value)) { const url = new URL(normalized.value); if (url.search || url.hash || url.username || url.password) return; }
      if (found.size < 40) found.set(`${normalized.type}:${normalized.value}`, { type: normalized.type, value: normalized.value });
    } catch {
      if (/^\d+(?:\.\d+){3}:\d+$/.test(candidate)) add(candidate.split(":")[0]!);
    }
  }
  function walk(item: unknown, key = "", depth = 0): void {
    if (depth > 6) return;
    // Bibliography/provider URLs never become observed IOCs, even nested in metadata.
    if (/^(?:reference|references|link|href|sourceHref|source_url|urlhaus_reference|phish_detail_page)$/i.test(key)) return;
    if (typeof item === "string") {
      if (/^(?:sha256_hash|sha1_hash|md5_hash|sha256|sha1|md5|hash|ip|ipAddress|host|hosts|hostname|hostnames|domain|domains|ioc|indicator|url|website|address|bitcoin_addresses|cve|cvelist|addr)$/.test(key)) add(item);
    } else if (Array.isArray(item)) item.slice(0, 25).forEach((child) => walk(child, key, depth + 1));
    else if (typeof item === "object" && item !== null) Object.entries(item).slice(0, 40).forEach(([childKey, child]) => walk(child, childKey, depth + 1));
  }
  walk(value);
  return [...found.values()];
}

export function safeSourceUrl(value: unknown): string | undefined {
  if (typeof value !== "string" || value.length > 2048) return undefined;
  try { const url = new URL(value); if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) return undefined; url.search = ""; url.hash = ""; return url.href; } catch { return undefined; }
}

export function originalEventAt(value: unknown): string | undefined {
  if (!value || typeof value !== "object") return undefined;
  const info = value as Record<string, unknown>;
  for (const key of ["date_compromised", "BreachDate", "published", "discovered", "first_seen", "dateadded", "firstseen", "createdAt", "Date", "date", "created", "analysis_start_time", "stamp_seen"]) {
    const candidate = info[key];
    if (typeof candidate === "string" && candidate.length <= 64 && /^\d{4}-\d{2}-\d{2}(?:[ T].*)?$/.test(candidate) && Number.isFinite(Date.parse(candidate))) return candidate;
  }
  return undefined;
}
