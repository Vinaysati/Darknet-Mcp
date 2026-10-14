#!/usr/bin/env node

import type { ToolContext } from "./types/index.js";
import { startMcpStdio } from "./protocol/mcp-server.js";
import { allTools } from "./protocol/tools.js";
import { checkTorStatus } from "./utils/tor-fetch.js";
import { buildToolContext } from "./config.js";
import { safeErrorMessage } from "./utils/errors.js";
import { executeCliTool } from "./cli.js";
import { checkReadiness } from "./meta/readiness.js";

// ─── Tool Categories for --list display ───

const TOOL_CATEGORIES: { category: string; prefix: string }[] = [
  { category: "Tor Network", prefix: "tor_" },
  // ransomware/index.ts uses camelCase names
  { category: "Ransomware Intelligence", prefix: "ransomware" },
  { category: "Ransomware Intelligence", prefix: "ransomlook" },
  // breach/index.ts uses camelCase names
  { category: "Breach Intelligence (HIBP)", prefix: "breach" },
  // abusech/index.ts uses camelCase names
  { category: "abuse.ch Suite", prefix: "threatfox" },
  { category: "abuse.ch Suite", prefix: "urlhaus" },
  { category: "abuse.ch Suite", prefix: "bazaar" },
  { category: "AlienVault OTX", prefix: "otx_" },
  { category: "AbuseIPDB", prefix: "abuseipdb_" },
  { category: "GreyNoise Community", prefix: "greynoise_" },
  { category: "Pulsedive", prefix: "pulsedive_" },
  { category: "Hudson Rock (Stealer Logs)", prefix: "stealer_" },
  { category: "Vulners (Exploits)", prefix: "vulners_" },
  { category: "Blockchain Intelligence", prefix: "btc_" },
  { category: "Hybrid Analysis (Malware)", prefix: "malware_" },
  { category: "CIRCL Onion Lookup", prefix: "onion_" },
  { category: "IntelligenceX", prefix: "intelx_" },
  { category: "PhishTank", prefix: "phishing_" },
  { category: "Meta", prefix: "darknet_" },
];

function categorize(toolName: string): string {
  for (const { category, prefix } of TOOL_CATEGORIES) {
    if (toolName.startsWith(prefix)) return category;
  }
  return "Other";
}

// ─── CLI: --help ───

function printHelp(): void {
  console.log(`darknet-mcp — Dark Web & Threat Intelligence MCP Server

USAGE:
  darknet-mcp                Start MCP server on stdio
  darknet-mcp --help         Show this help message
  darknet-mcp --list         List all ${allTools.length} tools grouped by category
  darknet-mcp --check-tor    Check Tor SOCKS5 proxy connectivity
  darknet-mcp --doctor       Report source configuration and local SOCKS readiness
  darknet-mcp --tool NAME JSON  Execute one tool with validated JSON arguments
  darknet-mcp --gui [--port 4318]  Open the local investigation dashboard

ENVIRONMENT VARIABLES:
  HIBP_API_KEY               Have I Been Pwned API key (breachSearch, breachPastes)
  INTELX_API_KEY             IntelligenceX API key (4 intelx tools)
  OTX_API_KEY                AlienVault OTX key (increases rate limit)
  ABUSEIPDB_API_KEY          AbuseIPDB key (4 abuseipdb tools)
  ABUSECH_AUTH_KEY           Required for ThreatFox, URLhaus and MalwareBazaar
  PULSEDIVE_API_KEY          Pulsedive key (higher rate)
  HUDSONROCK_API_KEY         Hudson Rock Cavalier key (3 stealer tools)
  VULNERS_API_KEY            Vulners key (search, document and exploit lookups)
  HYBRID_API_KEY             Hybrid Analysis key (3 malware tools)
  PHISHTANK_API_KEY          PhishTank key (higher rate)
  CHAINABUSE_API_KEY         ChainAbuse key (Bitcoin abuse lookup)
  RANSOMWARELIVE_API_KEY     Optional licensed Ransomware.live PRO API
  TOR_SOCKS_HOST             Tor SOCKS5 host (default: 127.0.0.1)
  TOR_SOCKS_PORT             Tor SOCKS5 port (default: 9050)

TOR SETUP:
  macOS:    brew install tor && brew services start tor
  Linux:    sudo apt install tor && sudo systemctl start tor
  Docker:   docker run -d -p 9050:9050 dperson/torproxy
`);
}

// ─── CLI: --list ───

function printToolList(): void {
  const grouped = new Map<string, typeof allTools>();

  for (const tool of allTools) {
    const cat = categorize(tool.name);
    if (!grouped.has(cat)) grouped.set(cat, []);
    grouped.get(cat)!.push(tool);
  }

  console.log(`\ndarknet-mcp — ${allTools.length} tools\n`);

  for (const [category, tools] of grouped) {
    console.log(`━━━ ${category} (${tools.length}) ━━━`);
    for (const tool of tools) {
      const schemaKeys = Object.keys(tool.schema);
      const params = schemaKeys.length > 0 ? `(${schemaKeys.join(", ")})` : "()";
      console.log(`  ${tool.name}${params}`);
      console.log(`    ${tool.description.split(".")[0]}.`);
    }
    console.log();
  }
}

// ─── CLI: --check-tor ───

async function checkTor(): Promise<void> {
  const host = process.env.TOR_SOCKS_HOST ?? "127.0.0.1";
  const port = parseInt(process.env.TOR_SOCKS_PORT ?? "9050", 10);

  console.log(`Checking Tor SOCKS5 proxy at ${host}:${port}...`);

  const status = await checkTorStatus(host, port);

  if (status.socksAvailable) {
    console.log(`[OK] Tor SOCKS5 proxy is running at ${host}:${port}`);
    console.log("     .onion fetching tools (tor_fetch_onion, tor_scrape_onion) are available.");
  } else {
    console.log(`[FAIL] Tor SOCKS5 proxy is NOT available at ${host}:${port}`);
    console.log("\nTo start Tor:");
    console.log("  macOS:    brew install tor && brew services start tor");
    console.log("  Linux:    sudo apt install tor && sudo systemctl start tor");
    console.log("  Docker:   docker run -d -p 9050:9050 dperson/torproxy");
    process.exit(1);
  }
}

// ─── Main ───

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.length === 1 && ["--help", "-h"].includes(args[0]!)) { printHelp(); return; }
  if (args.length === 1 && ["--list", "-l"].includes(args[0]!)) { printToolList(); return; }
  const ctx = buildToolContext();
  if (args.length === 1 && args[0] === "--check-tor") { await checkTor(); return; }
  if (args.length === 1 && args[0] === "--doctor") {
    process.stdout.write(JSON.stringify(await checkReadiness(ctx, allTools), null, 2) + "\n");
    return;
  }
  if (args[0] === "--tool") {
    if (args.length !== 3) throw new Error("Usage: --tool NAME '{\"argument\":\"value\"}'");
    const tool = allTools.find(candidate => candidate.name === args[1]);
    if (!tool) throw new Error("Unknown tool. Use --list to see available tool names.");
    let input: unknown;
    try { input = JSON.parse(args[2]!); } catch { throw new Error("Tool arguments must be valid JSON"); }
    const result = await executeCliTool(tool, input, ctx);
    if (result.isError) process.exitCode = 1;
    let output: unknown = result.structuredContent ?? result;
    if (!result.structuredContent && result.content.length === 1) {
      try { output = JSON.parse(result.content[0]!.text); } catch { /* Preserve non-JSON tool text. */ }
    }
    process.stdout.write(JSON.stringify(output, null, 2) + "\n");
    return;
  }
  if (args[0] === "--gui") {
    if (args.length !== 1 && !(args.length === 3 && args[1] === "--port")) throw new Error("Usage: --gui [--port 4318]");
    const port = args.length === 3 ? Number(args[2]) : 4318;
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("GUI port must be an integer from 1 to 65535");
    const { startGuiServer } = await import("./gui/server.js");
    const { server, url } = await startGuiServer(ctx, { port });
    console.log("Darknet investigation dashboard: " + url);
    console.log("API keys are loaded from server environment variables. Press Ctrl+C to stop.");
    const shutdown = () => { server.close(); server.closeAllConnections(); };
    process.once("SIGINT", shutdown); process.once("SIGTERM", shutdown);
    return;
  }
  if (args.length !== 0) throw new Error("Unknown options. Use --help for supported commands.");
  await startMcpStdio(ctx);
}

main().catch(error => {
  console.error("Error: " + safeErrorMessage(error));
  process.exitCode = 1;
});
