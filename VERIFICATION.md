# Verification record

Version: **0.3.0**. Upstream base: `8a19a37a03b302452bfabb30599d64669c374bfd`.

Validation is limited to code and offline fixtures, as requested. No API keys were supplied or required for the regression suite.

## Executed release checks

Checked on macOS with Node.js 24.19.0 and pnpm 11.25.0 on 14 October 2026.

- Production TypeScript build, including local GUI assets: **PASS**.
- Offline regression suite: **125 tests**, **125 passed; zero failures/skips**. Includes core/CLI/MCP/HTTP/cache checks, provider contracts, all eight investigation target types, target checksums, report privacy/correlation, readiness and GUI route checks.
- Actual MCP client handshake, **68-tool** discovery and local metadata/readiness calls: **PASS — real client handshake, metadata/readiness and missing-key investigation**.
- Frozen-lockfile installation and build/tests from the extracted source ZIP: **PASS — all 124 dependencies installed offline from the frozen lockfile; clean extracted package built and passed all 125 tests**.
- Patch applicability against the exact upstream base above: **PASS — apply check and actual application; resulting source matched all 66 release files byte for byte**.

## Browser and route coverage

Chrome checks use offline fixtures served through the actual local GUI endpoint. They exercise desktop and mobile layouts, all eight target types, 19 source selections, onion opt-in/reset, running/report/error states, Stop cancellation, readiness refresh/cooldown and JSON downloads.

Browser QA passed in Chrome at desktop and 700/390/320-pixel widths. The final independent review also reproduced and verified ten fixes for cancellation, partial results, domain matching, credential isolation/error handling, SOCKS greeting fragmentation and request spacing.

Evidence rendering uses text nodes and validated source links. Hostile fixture content and unsafe URL schemes are checked without executing it. The browser checks also cover absence of runtime external page requests and console/content-policy errors.

GUI route tests cover local Host/Origin enforcement, input/body/concurrency bounds, readiness caching, disconnect cancellation and secret-safe errors. Provider fixtures check current request methods, paths, headers, payload normalization, pagination and malformed/error responses. A mocked success does not verify a provider account or service.

## GitHub upload validation

Public repository: [Vinaysati/Darknet-Mcp](https://github.com/Vinaysati/Darknet-Mcp). Implementation commit: `14cdbdb7a8ad8290f581a1f26a34b55c43642f7f`. The [CI run](https://github.com/Vinaysati/Darknet-Mcp/actions/runs/38597988476) passed all four jobs: Linux/Windows with Node 22/24. Each job installed the frozen lockfile, built, ran the offline regression suite and checked the CLI. The subsequent documentation-only commit records this result without changing tested code.

## Live checks not performed

- No authenticated provider access, key validity or subscription permissions were tested.
- No onion page, real credential lookup, malware sample, scan submission or raw IntelligenceX document was retrieved.
- Readiness probes only the configured local SOCKS5 endpoint. A successful handshake does not verify an onion site's availability or confirm that the SOCKS endpoint is the Tor network.


The GUI and readiness report keep these distinctions visible: configured keys are not confirmed permissions; unrecognized responses are inconclusive; partial pages are not exhaustive; provider matches remain source claims. Live coverage requires the appropriate keys/licenses, current provider availability and Tor access where applicable.

This record supports the stated local-workstation release scope. It does not certify complete dark-web visibility, remote multi-user deployment or future compatibility with every upstream API change.
