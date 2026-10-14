# Darknet Mcp

Dark-web and threat intelligence for AI agents, with a local investigation dashboard. Version **0.3.0** preserves the original 66 tool names and adds `darknet_investigate` and `darknet_readiness`: **68 MCP tools** in total.

This fork is based on [badchars/darknet-mcp-server](https://github.com/badchars/darknet-mcp-server) at commit `8a19a37a03b302452bfabb30599d64669c374bfd`. Upstream MIT attribution and `LICENSE` are preserved.

The combined tool selects relevant sources for one indicator, returns bounded evidence with provenance, and shows exactly which checks succeeded, were skipped, or could not reach a conclusion. The GUI uses that same tool.

## Quick start

Use Node.js **22.13 or newer** and the included dependency lockfile:

```sh
npx pnpm@11.25.0 install --frozen-lockfile --ignore-scripts
npm run build
npm test
npm run gui
```

Open **http://127.0.0.1:4318**. To use another port:

```sh
node dist/index.js --gui --port 4320
```

The dashboard binds to `127.0.0.1` and is intended for a trusted local workstation. It has no runtime CDN dependency. API keys stay on the server and are not returned to the browser. Remote hosting, user accounts and multi-user access are outside this release's deployment scope.

## Configure sources

Copy `.env.example` to `.env`, configure the sources you use, then load that file explicitly:

```sh
node --env-file=.env dist/index.js --gui
```

`npm run gui` does **not** automatically load `.env`. Exported environment variables are also supported. `.env` is ignored by Git.

| Variable | Purpose |
| --- | --- |
| `HIBP_API_KEY` | Account breach and paste lookups; public breach metadata/password APIs remain keyless |
| `ABUSECH_AUTH_KEY` | Required for ThreatFox, URLhaus and MalwareBazaar |
| `ABUSEIPDB_API_KEY` | AbuseIPDB lookups |
| `HUDSONROCK_API_KEY` | Hudson Rock Cavalier v3 exposure metadata |
| `INTELX_API_KEY` | IntelligenceX metadata searches; the adapter uses the paid `2.intelx.io` instance |
| `HYBRID_API_KEY` | Hybrid Analysis reports, hash searches and detonation feed |
| `VULNERS_API_KEY` | Required for vulnerability, bulletin and exploit searches |
| `CHAINABUSE_API_KEY` | ChainAbuse Bitcoin abuse reports |
| `OTX_API_KEY`, `PULSEDIVE_API_KEY`, `PHISHTANK_API_KEY` | Provider-specific access and rate permissions |
| `RANSOMWARELIVE_API_KEY` | Optional Ransomware.live PRO access; requires the provider's appropriate subscription/license |
| `TOR_SOCKS_HOST`, `TOR_SOCKS_PORT` | SOCKS5 endpoint for onion access; defaults to `127.0.0.1:9050` |

Without `RANSOMWARELIVE_API_KEY`, the Ransomware.live adapter uses its free v2 API, which the provider limits to **personal use** and one request per minute per endpoint. Its data can be delayed. Configuring a PRO key selects the PRO API for all seven Ransomware.live tools; authentication or permission failures do not silently fall back to the free API. RansomLook's two public tools are independent. Check the provider's [API terms and PRO access information](https://www.ransomware.live/api) for your use.

Missing required keys produce explicit skipped checks. A configured key is not proof of valid account permissions or upstream availability.

## Eight investigation target types

`darknet_investigate` accepts these types, plus `auto` detection:

| Target type | Default checks |
| --- | --- |
| `domain` | Ransomware.live, ThreatFox, URLhaus, OTX, Hudson Rock, IntelligenceX |
| `email` | HIBP account breaches and pastes, Hudson Rock, IntelligenceX |
| `ip` | AbuseIPDB, GreyNoise, OTX, Hudson Rock, ThreatFox, URLhaus, IntelligenceX |
| `hash` | MalwareBazaar, ThreatFox, OTX, Hybrid Analysis |
| `url` | URLhaus, PhishTank, OTX host context, Pulsedive |
| `onion` | CIRCL Onion Lookup metadata and local Tor proxy status |
| `bitcoin` | Bitcoin address context and ChainAbuse reports |
| `cve` | Vulners bulletin/exploit context and OTX pulses |

Hashes support MD5, SHA1 and SHA256; unsupported combinations are explicitly skipped. IP inputs support IPv4 and IPv6, while the OTX adapter supports IPv4 only. Onion inputs require a checksum-valid v3 address or its HTTP/HTTPS URL. Bitcoin inputs require a checksum-valid mainnet address. CVE inputs use `CVE-YYYY-NNNN...` format.

There are **19 selectable source categories**:

`ransomware`, `ransomlook`, `threatfox`, `urlhaus`, `otx`, `stealer`, `hibp`, `intelx`, `abuseipdb`, `greynoise`, `bazaar`, `hybrid`, `tor`, `onionlookup`, `blockchain`, `chainabuse`, `vulners`, `phishing`, `pulsedive`.

Omit `sources` for relevant default checks. An explicitly selected source that does not support the target type is reported as skipped. RansomLook is optional domain context from its latest feed, not an exhaustive historical victim search. Domain lookups do not enumerate all breached employees or establish domain ownership; use explicit email targets for HIBP account searches.

## Use from an AI agent

Use `mcp-config.example.json`, replacing the folder and environment-file paths with your own absolute paths. With no CLI flags, the server starts MCP over stdio:

```sh
node --env-file=.env dist/index.js
```

Example `darknet_investigate` input:

```json
{
  "target": "example.com",
  "target_type": "auto",
  "max_results": 10
}
```

`max_results` is 1–50 records retained per check, default 10. Provider totals may exceed the retained evidence. At most three checks run concurrently. Normal checks have a 20-second deadline; Hudson Rock checks allow 100 seconds and an explicitly requested onion page allows 65 seconds. Large or paginated results remain marked partial.

For an onion target, `fetch_onion` defaults to **false**. Setting it to `true` opts into fetching and parsing only the supplied page through the configured SOCKS proxy. Select the `tor` category if supplying `sources`. The combined workflow discards page body text and extracted links; it does not follow them, crawl, fetch raw documents, download malware or submit new scans. The original direct tools remain separately available.

Hudson Rock returns first-page metadata with `nextCursor` and `complete`; use the direct `stealer_domain`, `stealer_email` or `stealer_ip` tool with its optional `cursor` for subsequent pages. It does not invent a corpus-wide total from a single page.

Ransomware.live list tools expose `limit` and `offset` over the fetched, cached response, with `next_offset`, `complete` and explicit count basis. These offsets are local result pagination, not invented upstream cursors. Its recent-victim tool is a latest-feed lookup and remains partial even when the returned page is exhausted.

## Dashboard and readiness

The responsive dashboard supports all eight target types, optional source selection, an explicit onion-page checkbox, evidence/source links, shared indicators, coverage gaps and JSON downloads. **Stop** cancels the in-flight investigation. A previous completed report remains available in the page after a later run is stopped or fails.

The Sources screen shows configuration and a refreshable readiness report. `darknet_readiness` and the doctor command check registered tools, missing keys and a SOCKS5 handshake to the configured Tor endpoint:

```sh
node --env-file=.env dist/index.js --doctor
```

This check does not authenticate to external providers or test onion reachability. The report deliberately sets `live_verified: false`; `health_status: not_checked` for a clearnet source means it has not been tested. GUI readiness is cached for up to one minute, with a short refresh cooldown.

Reports remain in the current browser page unless downloaded. This release includes no persistent case database, scheduled monitoring, alert delivery or embedded AI chat. MCP clients provide the AI-agent interaction.

## Direct CLI

```sh
node dist/index.js --list
node dist/index.js --help
node dist/index.js --doctor
node dist/index.js --tool darknet_list_sources '{}'
node --env-file=.env dist/index.js --tool darknet_investigate '{"target":"CVE-2024-12345","target_type":"cve","max_results":10}'
```

Invalid arguments and unknown flags exit with status 1. The doctor command returns a configuration report even when some keys are missing; it is not a pass/fail certificate for production API access. PowerShell JSON quoting varies by version; using the GUI or an MCP client avoids shell quoting.

## Evidence and reliability

Combined reports distinguish `match`, `no_match`, `skipped`, `error`, `timeout` and `inconclusive`. Unknown or malformed response shapes are not treated as negative findings. Evidence includes observation time, source event time when available, safe source links and provenance; external records remain unverified source claims.

The combined workflow allowlists and bounds metadata, masks returned credential/account fields and URL query values, and caps the whole report at 256 KiB. The explicitly requested target remains identifiable. The original individual tools retain their more detailed provider output and are not covered by the combined report's redaction guarantee. JSON exports can still contain sensitive target and incident metadata.

Correlation requires an actual shared indicator in retained evidence from at least two source categories; source reference links are not counted as matching IOCs. No fabricated risk score, automatic attribution or verified-threat claim is added. A match can be benign, stale or disputed; no match is not proof of safety. Treat provider text as data, never as instructions to an AI agent.

This release also includes:

- Current contracts for RansomLook group lists, CIRCL onion lookup, Hudson Rock v3, Hybrid Analysis GET hash search/detonation feed, and Vulners authenticated POST searches.
- HIBP query defaults, IntelligenceX polling fixes, abuse.ch authentication and alternative-argument validation, and ChainAbuse authentication fixes.
- Credential-scoped caches, bounded TTL/LRU storage, cancellable rate limiting, validated tool inputs and secret-safe errors.
- HTTP/body deadlines, a 10 MB body cap, and GET/HEAD transient retries through the provider rate limiter. POST requests are not automatically replayed. Hudson Rock uses its longer documented request allowance.
- SOCKS5 remote DNS, correct HTTP/HTTPS onion transport, response limits and cancellation; onion redirects are not followed.
- Local GUI Host/Origin enforcement, a restrictive content policy, bounded request sizes and investigation concurrency, and escaped evidence rendering.
- Offline regression tests, a frozen lockfile and GitHub CI configured for Node 22/24 on Linux and Windows.

## Validation and deployment boundary

See `VERIFICATION.md` for the release's executed checks. Provider contracts are exercised with mocked network responses and the browser is checked against offline fixtures. No live authenticated provider, onion site, credential lookup, malware sample or scan submission is part of this release's validation. The [GitHub CI matrix](https://github.com/Vinaysati/Darknet-Mcp/actions/runs/38597988476) passed on Linux and Windows with Node 22 and 24 for the uploaded implementation.

The code and local workflows can be verified without keys. Live data coverage depends on provider permissions, current service contracts and availability, and a working Tor proxy where needed. This is not a guarantee of complete visibility into the dark web or of every future provider response.

## Import into your own repository

For a new repository, copy this folder's contents, including hidden files, and run the quick-start checks. For a checkout of the exact upstream commit, follow the patch instructions in `SETUP.md`.

The package remains `private: true`; the inherited npm publishing workflow is removed. This enhanced build is not the original upstream npm release. If you later publish a separate package, choose your own available name and update author/repository/homepage metadata while preserving upstream attribution and `LICENSE`.

The original README is retained as `UPSTREAM_README.md` for historical reference. Setup and behavior in this README take precedence over its old release instructions and API claims.
