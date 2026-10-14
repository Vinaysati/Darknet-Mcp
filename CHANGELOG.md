# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-10-14

Repository distribution: Vinaysati/Darknet-Mcp; contribution/security guidance and package metadata identify this project.

### Added

- `darknet_readiness` and the `--doctor` CLI report for tool/key configuration and a local SOCKS5 handshake. Provider authentication and live upstream health are explicitly unverified.
- URL, checksum-valid v3 onion, checksum-valid mainnet Bitcoin and CVE investigation targets, completing eight combined target types with `auto` detection and 19 selectable source categories.
- Explicit `fetch_onion` opt-in for one supplied page; no link following or crawling. Metadata remains the default onion workflow.
- Dashboard Stop control, readiness refresh, safe evidence links, provenance and coverage follow-up details.
- Optional `RANSOMWARELIVE_API_KEY` configuration for licensed PRO API access, with no silent fallback after authentication failures.
- Contract and workflow regression tests for the new adapters, target validation, report privacy bounds and local GUI routes.

### Fixed

- RansomLook string group lists and recent-post links; Ransomware.live victim fields, malformed responses and free v2 per-endpoint rate limits.
- CIRCL public `/api/lookup/{onion}` route and unknown-address handling; unknown metadata is no longer interpreted as a clean result.
- Hudson Rock Cavalier v3 POST contracts, `api-key` authentication, cursor pagination and explicit first-page result counts.
- Hybrid Analysis GET hash search and detonation feed, response validation and credential-scoped caching.
- Vulners authenticated POST contracts, document ID arrays, search hit normalization and provider error detection.
- Blank key normalization and source configuration metadata for authenticated tools.
- Combined report handling of paginated/unknown results, source event times and provider references; longer deadlines for Hudson Rock and explicit onion-page requests.
- Stop cancellation now settles even when a child ignores cancellation and never launches queued lookups. Provider totals greater than returned records remain partial; RansomLook domain mentions include valid subdomains.
- Cache isolation across API keys for AbuseIPDB, OTX, PhishTank and abuse.ch; provider exceptions no longer reflect upstream error bodies. Clearnet redirects are refused to prevent API-key forwarding.
- Fragmented SOCKS5 greeting handling and cancelled rate-limiter timer cleanup without bypassing provider spacing.

### Changed

- 68 MCP tools including combined investigation and readiness. Provider contract fixes may change normalized result shapes; callers should use the documented metadata and pagination fields.
- Release documentation now distinguishes offline verification, local-workstation deployment and live account-dependent coverage. Free Ransomware.live v2 access is documented as personal-use only.

## [0.2.0] - 2026-10-14

### Added

- `darknet_investigate` for domain, email, IP and file-hash targets with explicit coverage, bounded redacted metadata and shared indicators.
- A local responsive dashboard, JSON report downloads, source configuration, Node build scripts, offline tests, a frozen pnpm lockfile and Linux/Windows Node 22/24 CI.
- Validation, bounded caches, HTTP/body deadlines, cancellation and read-only MCP annotations.

### Fixed

- Direct `--tool` execution, registry-derived source/tool discovery and package-derived MCP version.
- HIBP query defaults, IntelligenceX polling, abuse.ch authentication/argument constraints and ChainAbuse authentication/cache isolation.
- HTTP retries through provider rate limits and Tor HTTP/HTTPS transport with SOCKS5 remote DNS.

### Changed

- Disabled npm publishing using the package private setting.
