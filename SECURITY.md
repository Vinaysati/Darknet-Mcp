# Security policy

## Maintainer and supported versions

This policy covers the Darknet MCP server and local investigation GUI maintained in [Vinaysati/Darknet-Mcp](https://github.com/Vinaysati/Darknet-Mcp).

| Release | Security maintenance |
| --- | --- |
| Latest 0.3.x release | Current maintained release line |
| Earlier releases | Upgrade before reporting |

The maintainer is [Vinaysati](https://github.com/Vinaysati). Maintenance is provided on a best-effort basis, without a promised response deadline or security certification.

## Report a vulnerability privately

Private reporting requires the repository owner to enable GitHub's private vulnerability-reporting setting. Once enabled, use [the private report form](https://github.com/Vinaysati/Darknet-Mcp/security/advisories/new), or open this repository's **Security** tab and choose **Report a vulnerability**. A report starts privately; do not open a public issue containing an exploit, exposed keys or sensitive investigation data.

Include:

- Affected release or commit and your OS/Node.js version.
- The affected component and potential impact.
- Minimal steps to reproduce using synthetic targets and test accounts.
- Sanitized logs or screenshots, with all keys, credentials and personal data removed.

Ordinary bugs and feature requests belong in [GitHub Issues](https://github.com/Vinaysati/Darknet-Mcp/issues). If you cannot access private reporting, wait for that route to be available rather than posting sensitive details publicly.

## Scope

Report issues in this repository's input validation, local GUI request controls, MCP tool execution, metadata handling, credential isolation, cancellation and provider adapters. The maintainer can assess these and coordinate a fix and disclosure where appropriate.

Third-party API services, their subscriptions/permissions, the Tor network and provider-held data are operated separately. Report vulnerabilities in those services to their operators. Reports about a dependency are welcome when they explain the impact on this application.

Only investigate systems and accounts you are authorized to assess. Use synthetic fixtures for public reproductions and never attach real stolen credentials or malware samples to a report.

## Safe deployment and data handling

The GUI binds to local loopback and has no remote multi-user authentication. Public hosting requires a separately reviewed deployment design.

Keep API keys in the server environment or an ignored `.env` file. Never commit them. Combined reports mask and bound metadata, but the explicit target and incident details can remain sensitive. Individual provider tools return more detailed records; restrict access to their output and downloaded reports.

Treat provider text as untrusted evidence rather than instructions to an AI agent. A source match is a claim; no match is not proof of safety. Offline tests and CI do not validate provider accounts, subscriptions or real onion reachability.

## License

MIT license terms and copyright notices are in [LICENSE](LICENSE).
