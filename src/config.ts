import type { ToolContext } from "./types/index.js";
export function buildToolContext(env: NodeJS.ProcessEnv = process.env): ToolContext {
  const port = Number(env.TOR_SOCKS_PORT ?? "9050");
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("TOR_SOCKS_PORT must be an integer from 1 to 65535");
  const clean = (value: string | undefined): string | undefined => value?.trim() || undefined;
  return { config: {
    hibpApiKey: clean(env.HIBP_API_KEY), intelxApiKey: clean(env.INTELX_API_KEY),
    otxApiKey: clean(env.OTX_API_KEY), abuseipdbApiKey: clean(env.ABUSEIPDB_API_KEY),
    abusechAuthKey: clean(env.ABUSECH_AUTH_KEY), pulsediveApiKey: clean(env.PULSEDIVE_API_KEY),
    hudsonrockApiKey: clean(env.HUDSONROCK_API_KEY), vulnersApiKey: clean(env.VULNERS_API_KEY),
    hybridApiKey: clean(env.HYBRID_API_KEY), phishtankApiKey: clean(env.PHISHTANK_API_KEY),
    chainabuseApiKey: clean(env.CHAINABUSE_API_KEY),
    ransomwareLiveApiKey: clean(env.RANSOMWARELIVE_API_KEY),
    torSocksHost: env.TOR_SOCKS_HOST ?? "127.0.0.1", torSocksPort: port,
  } };
}
