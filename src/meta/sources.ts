import type { ToolContext, ToolDef } from "../types/index.js";

export interface DataSource {
  name: string; url: string; authRequired: boolean; envVar: string | null;
  tools: string[]; configured: boolean; keyPresent: boolean;
  availableTools: string[]; blockedTools: string[];
  health: "not_checked"; requiresTor?: boolean;
}
interface SourceDefinition {
  name: string; url: string; prefixes: string[];
  configKey?: keyof ToolContext["config"]; envVar?: string;
  authRequired?: boolean; gatedTools?: string[]; requiresTor?: boolean;
}
const definitions: SourceDefinition[] = [
  { name: "Have I Been Pwned", url: "https://haveibeenpwned.com", prefixes: ["breach"], configKey: "hibpApiKey", envVar: "HIBP_API_KEY", gatedTools: ["breachSearch", "breachPastes"] },
  { name: "IntelligenceX", url: "https://intelx.io", prefixes: ["intelx_"], configKey: "intelxApiKey", envVar: "INTELX_API_KEY", authRequired: true },
  { name: "AlienVault OTX", url: "https://otx.alienvault.com", prefixes: ["otx_"], configKey: "otxApiKey", envVar: "OTX_API_KEY" },
  { name: "AbuseIPDB", url: "https://www.abuseipdb.com", prefixes: ["abuseipdb_"], configKey: "abuseipdbApiKey", envVar: "ABUSEIPDB_API_KEY", authRequired: true },
  { name: "abuse.ch: ThreatFox, URLhaus, MalwareBazaar", url: "https://abuse.ch", prefixes: ["threatfox", "urlhaus", "bazaar"], configKey: "abusechAuthKey", envVar: "ABUSECH_AUTH_KEY", authRequired: true },
  { name: "GreyNoise Community", url: "https://www.greynoise.io", prefixes: ["greynoise_"] },
  { name: "Pulsedive", url: "https://pulsedive.com", prefixes: ["pulsedive_"], configKey: "pulsediveApiKey", envVar: "PULSEDIVE_API_KEY" },
  { name: "Hudson Rock Cavalier", url: "https://api.hudsonrock.com", prefixes: ["stealer_"], configKey: "hudsonrockApiKey", envVar: "HUDSONROCK_API_KEY", authRequired: true },
  { name: "Vulners", url: "https://vulners.com", prefixes: ["vulners_"], configKey: "vulnersApiKey", envVar: "VULNERS_API_KEY", authRequired: true },
  { name: "Blockchain.info", url: "https://blockchain.info", prefixes: ["btc_address", "btc_balance", "btc_tx"] },
  { name: "ChainAbuse", url: "https://www.chainabuse.com", prefixes: ["btc_abuse_check"], configKey: "chainabuseApiKey", envVar: "CHAINABUSE_API_KEY", authRequired: true },
  { name: "Hybrid Analysis", url: "https://hybrid-analysis.com", prefixes: ["malware_"], configKey: "hybridApiKey", envVar: "HYBRID_API_KEY", authRequired: true },
  { name: "CIRCL Onion Lookup", url: "https://onion.ail-project.org", prefixes: ["onion_"] },
  { name: "PhishTank", url: "https://phishtank.org", prefixes: ["phishing_"], configKey: "phishtankApiKey", envVar: "PHISHTANK_API_KEY" },
  { name: "Tor Network", url: "https://www.torproject.org", prefixes: ["tor_"], requiresTor: true },
  { name: "Ransomware.live", url: "https://www.ransomware.live", prefixes: ["ransomware"], configKey: "ransomwareLiveApiKey", envVar: "RANSOMWARELIVE_API_KEY" },
  { name: "RansomLook", url: "https://www.ransomlook.io", prefixes: ["ransomlook"] },
];

/** Registry-derived names; configuration is not a claim of upstream health. */
export function listSources(config: ToolContext["config"], registry: ToolDef[] = []): DataSource[] {
  return definitions.map(source => {
    const tools = registry.filter(tool => source.prefixes.some(prefix => tool.name.startsWith(prefix))).map(tool => tool.name);
    const key = source.configKey ? config[source.configKey] : undefined;
    const keyPresent = typeof key === "string" && key.trim().length > 0;
    const blockedTools = keyPresent ? [] : tools.filter(name => source.authRequired || source.gatedTools?.includes(name));
    const availableTools = tools.filter(name => !blockedTools.includes(name));
    return {
      name: source.name, url: source.url, authRequired: Boolean(source.authRequired), envVar: source.envVar ?? null,
      tools, keyPresent, configured: tools.length > 0 && availableTools.length > 0,
      availableTools, blockedTools, health: "not_checked" as const,
      ...(source.requiresTor ? { requiresTor: true } : {}),
    };
  });
}
