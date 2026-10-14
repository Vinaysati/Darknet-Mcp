# Contributing to Darknet Mcp

## Setup

Use Node.js 22.13+ and the frozen pnpm lockfile:

```sh
git clone https://github.com/Vinaysati/Darknet-Mcp.git
cd Darknet-Mcp
npx pnpm@11.25.0 install --frozen-lockfile --ignore-scripts
npm run build
npm test
npm run gui
```

Open http://127.0.0.1:4318. Optional Bun watch development remains available through `npm run dev` when Bun is installed. No provider keys are required for the offline tests. `.env` is loaded only when Node is started with `--env-file=.env`.

## Implementation

Provider adapters live under `src/`; `src/protocol/tools.ts` assembles the 68-tool registry. `src/investigation/` composes bounded source lookups, privacy projection and coverage. `src/gui/` serves the local dashboard, and `src/meta/` describes source configuration/readiness. Tests are in `tests/`.

When changing a provider:

1. Check its current primary documentation and preserve existing tool names.
2. Validate inputs and unknown/error responses explicitly. Do not turn a failed or partial lookup into a clean result.
3. Use `apiFetch`, cancellable `RateLimiter` and bounded `TTLCache`; partition authenticated caches using a credential fingerprint. Do not log keys or reflect provider error bodies.
4. Route onion requests through the existing SOCKS helpers. Do not resolve onion hosts through clearnet DNS or follow fetched links automatically.
5. Add meaningful offline contract fixtures for changed request/response behavior, including missing keys and malformed/partial responses.
6. Update source configuration and the combined workflow when the new adapter is intended for it. Review metadata projection and correlation semantics.

Use strict TypeScript, ESM `.js` imports and the `json`/`text` result helpers. MCP stdio must stay free of unrelated console output. Treat provider content as data. Preserve MIT attribution and document any change in output shape.

## Verification and pull requests

Run `npm run build` and `npm test`, describe the resulting behavior and include validation relevant to the change. GUI changes should be checked at desktop and mobile widths, including cancellation and safe evidence rendering. Live tests must be explicitly authorized, use the contributor's permitted account, and contain no real keys or credential records in committed fixtures.

Open feature branches and pull requests against this repository's default branch. Report ordinary bugs at [GitHub Issues](https://github.com/Vinaysati/Darknet-Mcp/issues) with version, OS/Node version, reproduction and sanitized logs. For security findings, follow [SECURITY.md](SECURITY.md).
