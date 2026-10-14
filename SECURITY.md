# Security policy

This policy applies to the enhanced Darknet Mcp code in this repository. Version 0.3.x is the current release line. Third-party providers, account permissions and Tor infrastructure are separate dependencies.

## Reporting a vulnerability

Use the repository Security tab's **Report a vulnerability** option when available. If private reporting is unavailable, contact the repository owner through an established private channel before sending sensitive details. Do not put API keys, exposed credentials, private investigation targets or exploitation details in public issues.

Include the affected version, impact, minimal reproduction and sanitized logs. Response and repair times depend on maintainer availability; no fixed response deadline is promised.

## Operational scope

The GUI binds to local loopback. It has no remote multi-user authentication and must not be exposed as a public web service without a separately reviewed deployment design.

Keep keys in the local server environment or an ignored `.env` file. The combined report masks/bounds metadata; individual provider tools return more detailed records and downloaded reports may still contain sensitive incident metadata.

Provider text is untrusted evidence, never instructions for an AI agent. No match is not proof of safety. The release is offline-tested; authenticated provider access and real onion reachability require separate authorized validation.

The original MIT copyright and upstream attribution remain in `LICENSE` and `UPSTREAM_README.md`.
