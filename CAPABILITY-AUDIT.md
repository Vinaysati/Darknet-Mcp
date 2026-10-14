# Release capability audit — 0.3.0

Reviewed 14 October 2026. Base: upstream `8a19a37a03b302452bfabb30599d64669c374bfd`.

The eight advertised capability families are implemented through the retained provider tools and the combined investigator/GUI. The original 66 tool names remain intact; combined investigation and readiness bring the registry to 68 unique tools. The code and offline verification are complete for the documented local-workstation release. Authenticated production operation is unverified because no API keys were supplied.

| Family | Implemented combined workflow | Offline verification / live requirement |
| --- | --- | --- |
| HIBP | Explicit email breach/paste context | Query flags and authenticated-cache isolation tested; account keys/permissions needed |
| ThreatFox / abuse.ch | IOC, URL and file-hash context | Authentication, alternate parameters and malformed/empty responses tested; abuse.ch key needed |
| Ransomware | Domain victim search plus optional RansomLook latest feed | Group/link mapping, fields, PRO routing and partial pagination tested; free v2 is delayed personal use only, licensed PRO is optional |
| Tor / onion | v3 metadata plus local SOCKS context; supplied-page fetch only with explicit opt-in | Checksums, transport, bounded cancellation and fragmented greetings tested; real Tor/onion reachability untested |
| Blockchain | Bitcoin mainnet address and abuse context | Checksums, Basic authentication, cache isolation and incomplete coverage tested; abuse key needed, no ownership/crime inference |
| Exploit search | CVE bulletin and exploit metadata | Authenticated Vulners POST methods, ID arrays, hit normalization and partial results tested; Vulners key needed |
| Stealer exposure | Domain/email/IP metadata | Hudson v3 methods/auth/cursors tested; combined report removes credential fields, direct tools retain detailed provider output; account access untested |
| Malware analysis | Existing file-hash reports and malware metadata | Hybrid GET and supported feed envelopes tested; account access/feed runtime shape unverified; no samples downloaded or new analyses submitted |

The investigator accepts domain, email, IP, hash, URL, v3 onion, Bitcoin and CVE targets with automatic detection. The GUI exposes 19 source categories, explicit onion opt-in, Stop, readiness, source links and JSON downloads. Unknown/pending/error responses and missing permissions do not become clean findings. Partial provider pages remain visibly partial.

## Resolved audit findings

The previous 0.2.0 adapter and GUI gaps were corrected. Additional independent review found and verified fixes for queued work continuing after cancellation, inaccurate partial coverage, subdomain matching, cross-key cache reuse, provider error-body exposure, fragmented SOCKS greetings and cancellation bypassing provider spacing.

## Executed release evidence

Production build passed. All 125 offline regression tests passed, including a real MCP client handshake and 68-tool discovery. Desktop/mobile Chrome checks passed with offline fixtures. A fresh extracted ZIP installed from the frozen lockfile, built and passed all 125 tests. The patch applied to the exact upstream source and produced byte-identical release files. Details: `VERIFICATION.md`.

## Remaining operational checks

No authenticated provider request, real leaked-account lookup, onion page, malware sample or scan submission was performed. PRO Swagger confirms routes/authentication but supplies no response schemas; realistic response variants are fixture-tested and must be checked against an authorized account. The Hybrid feed also requires authenticated runtime confirmation. [GitHub CI](https://github.com/Vinaysati/Darknet-Mcp/actions/runs/38597988476) passed all four Linux/Windows and Node 22/24 jobs for the uploaded implementation.

Complete code does not establish exhaustive dark-web visibility or 100% detection. Scheduled monitoring, persistent cases, remote multi-user hosting and embedded AI chat are outside this local MCP/GUI release. AI interaction is supplied by an MCP client.

## Primary contract references

- [RansomLook published API implementation](https://github.com/RansomLook/RansomLook/blob/main/website/web/api/genericapi.py)
- [CIRCL/AIL onion lookup application](https://github.com/ail-project/onion-lookup/blob/main/app.py)
- [Hudson Rock authentication](https://docs.hudsonrock.com/reference/authentication) and [domain search](https://docs.hudsonrock.com/reference/search-by-domains)
- [Hybrid Analysis API changelog](https://www.hybrid-analysis.com/docs/api/v2-changelog)
- [Vulners official SDK search implementation](https://github.com/vulnersCom/api/blob/master/src/vulners/_resources/_sync/search.py)
- [Ransomware.live API terms](https://www.ransomware.live/api) and [PRO Swagger](https://api-pro.ransomware.live/docs)
