import type { ToolContext, ToolDef } from "../types/index.js";
import { listSources } from "./sources.js";
import { checkTorStatus, type TorStatus } from "../utils/tor-fetch.js";

export interface ReadinessCheck {
  name: string;
  tools: string[];
  configuration_status: "configured" | "partial" | "missing_key" | "available_without_key";
  health_status: "not_checked" | "reachable" | "unavailable";
  detail: string;
  missing_env: string | null;
  requires_tor: boolean;
}
export interface ReadinessReport {
  schema_version: "1.0";
  checked_at: string;
  checks: ReadinessCheck[];
  tor: TorStatus;
  summary: {
    configured_sources: number; partial_sources: number; blocked_sources: number;
    tor_available: boolean; live_verified: false;
  };
}

/** Inspect configuration and the configured SOCKS endpoint. Never authenticate to a provider. */
export async function checkReadiness(ctx: ToolContext, registry: ToolDef[], probe = checkTorStatus): Promise<ReadinessReport> {
  const tor = await probe(ctx.config.torSocksHost, ctx.config.torSocksPort);
  const checks = listSources(ctx.config, registry).map((source): ReadinessCheck => {
    const configuration_status = source.blockedTools.length === source.tools.length && source.tools.length > 0
      ? "missing_key" : source.blockedTools.length > 0 ? "partial"
      : source.keyPresent ? "configured" : "available_without_key";
    return {
      name: source.name, tools: source.tools, configuration_status,
      health_status: source.requiresTor ? tor.socksAvailable ? "reachable" : "unavailable" : "not_checked",
      detail: source.requiresTor
        ? tor.socksAvailable ? "SOCKS5 handshake succeeded. Onion reachability is still unverified."
          : "SOCKS5 proxy is unavailable. Onion fetching is blocked; clearnet Tor search/exit tools are independent."
        : configuration_status === "missing_key" ? "Required key is missing; source checks will be skipped."
        : configuration_status === "partial" ? "Some source tools require a missing key. Upstream health is unverified."
        : "Tool registration and configuration are present. Key validity, permissions and upstream health are unverified.",
      missing_env: source.blockedTools.length > 0 ? source.envVar : null,
      requires_tor: Boolean(source.requiresTor),
    };
  });
  return {
    schema_version: "1.0", checked_at: new Date().toISOString(), checks, tor,
    summary: {
      configured_sources: checks.filter(check => ["configured", "available_without_key"].includes(check.configuration_status)).length,
      partial_sources: checks.filter(check => check.configuration_status === "partial").length,
      blocked_sources: checks.filter(check => check.configuration_status === "missing_key").length,
      tor_available: tor.socksAvailable, live_verified: false,
    },
  };
}
