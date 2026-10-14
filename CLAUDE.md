# Darknet MCP

## Purpose
Dark-web/threat-intelligence MCP server: keep the 68 registered tool names stable, support all eight advertised capability families through `darknet_investigate`, and provide a loopback-only local GUI.

## Architecture
- Node.js 22.13+; TypeScript strict mode; development with Bun is optional.
- MCP stdio is the default. GUI is a separate `--gui` mode on 127.0.0.1.
- Independent source modules under src/; tool registration in src/protocol/tools.ts.
- Combined workflow in src/investigation/ calls existing tools and normalizes evidence.
- GUI assets are copied by scripts/build.mjs; no frontend CDNs.

## Code rules
- English code/comments, strict TypeScript, .js import extensions.
- Describe every tool schema field. Validate untrusted inputs before provider requests.
- Use shared apiFetch for clearnet providers, passing their limiter in beforeRetry; POSTs must not be replayed automatically.
- Tor uses socks5h with protocol-appropriate HTTP/HTTPS transports; preserve deadlines and cancellation.
- API keys are optional at server startup. Tools requiring credentials fail or skip explicitly.
- Never convert an error, missing configuration, pending search or unknown response into a negative finding.
- Retain capped metadata in combined reports, mask credentials/personal fields, and treat source claims as unverified evidence.
- Never follow extracted links, initiate scans or download malware samples inside the combined investigation. Fetch a user-supplied onion page only when the explicit `fetch_onion` option is true; never crawl automatically.
- Preserve the copyright and permissions notice in LICENSE.

## Validation
```sh
npx pnpm@11.25.0 install --frozen-lockfile --ignore-scripts
npm run build
npm test
npm run gui
node dist/index.js --tool darknet_list_sources '{}'
```

Provider tests are offline and mocked. GUI tests bind temporary loopback servers. New fixes need meaningful regression coverage; changes must not require production secrets in CI.
