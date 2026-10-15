# Apne repo mein enhanced tool kaise daalein

Ye version **0.3.0** hai: **68 MCP tools**, including `darknet_investigate` aur `darknet_readiness`. GUI mein domain, email, IP, file hash, URL, v3 onion, Bitcoin address aur CVE investigate kar sakte ho.

## Naya repo

1. Release ZIP extract karo. Extracted project folder ke files apne repo mein copy karo, including `.github`, `.gitignore` aur `.env.example`.
2. Node.js **22.13+** install hona chahiye. Project folder mein ye chalao:

```sh
npx pnpm@11.25.0 install --frozen-lockfile --ignore-scripts
npm run build
npm test
npm run gui
```

3. Browser mein **http://127.0.0.1:4318** kholo. `Auto` target type aur automatic sources se shuru kar sakte ho. Required key missing ho to related check `Skipped` dikhega; usse target safe prove nahi hota.

Port occupied ho to:

```sh
node dist/index.js --gui --port 4320
```

GUI local machine ke liye hai aur `127.0.0.1` par bind hoti hai. Remote team access, login system aur public hosting is release mein included nahi hain.

## Abhi keys nahi hain

Build aur offline tests ke liye API keys nahi chahiye. Sources screen par key/configuration status aur local Tor readiness dekh sakte ho. Ye command bhi wahi readiness report deta hai:

```sh
npm run doctor
```

Doctor external providers ko authenticate nahi karta. Tor check sirf configured SOCKS5 proxy ka handshake karta hai; onion site ka live access verify nahi karta. Missing keys report mein dikhti hain, command ko production access certificate mat samajhna.

## Baad mein API keys configure karo

`.env.example` ki copy `.env` naam se banao. Sirf required sources ke keys fill karo, phir:

```sh
node --env-file=.env dist/index.js --gui
node --env-file=.env dist/index.js --doctor
```

`npm run gui` aur `npm run doctor` `.env` apne aap load nahi karte. Keys chat ya GitHub par paste mat karo; `.env` already Git ignore mein hai. GUI browser ko keys nahi bhejti.

HIBP, abuse.ch, AbuseIPDB, Hudson Rock, IntelligenceX, Hybrid Analysis, Vulners aur ChainAbuse ke related checks ko provider keys/access chahiye. Optional OTX, Pulsedive aur PhishTank keys provider permissions/rate limits mein help karti hain. IntelligenceX adapter paid `2.intelx.io` instance use karta hai.

`RANSOMWARELIVE_API_KEY` blank ho to Ransomware.live ka free v2 API use hota hai: provider ke hisaab se personal use, har endpoint par ek request per minute, aur delayed data ho sakta hai. PRO key configure karne par saare seven Ransomware.live tools PRO API use karte hain; uske liye suitable subscription/license chahiye. PRO auth fail ho to tool free API par silently switch nahi karta. RansomLook ke two public tools separate hain. Business use se pehle provider ke [API terms](https://www.ransomware.live/api) check karo.

## Onion access

Tor SOCKS5 proxy alag se running hona chahiye. Defaults `TOR_SOCKS_HOST=127.0.0.1` aur `TOR_SOCKS_PORT=9050` hain. Sources screen ka readiness status proxy availability dikhata hai.

Combined investigation mein onion page fetch **default off** hai. Valid v3 onion address/URL daal kar explicit checkbox enable karoge tab sirf diya hua page fetch hoga. Tool links follow ya crawl nahi karta; page body text aur extracted links combined evidence mein retain nahi hote. Sirf metadata chahiye to checkbox off rakho.

## AI agent ke saath

`mcp-config.example.json` mein apne project folder aur `.env` ke absolute paths set karo. Default stdio server:

```sh
node --env-file=.env dist/index.js
```

Agent ko `darknet_investigate` call karna hai, for example:

```json
{
  "target": "example.com",
  "target_type": "auto",
  "max_results": 10
}
```

`sources` optional hai; omit karne par relevant sources select hote hain. 19 categories selectable hain. Har source har target support nahi karta; unsupported selection skipped dikhegi. `darknet_readiness` configuration aur local proxy check deta hai. GUI mein **Stop** current investigation cancel karta hai aur JSON download completed report export karta hai.

## Report samajhna

Report `match`, `no_match`, `skipped`, `error`, `timeout` aur `inconclusive` alag dikhati hai. Source links, observation time, provenance, incomplete coverage aur capped results visible hain. Source ka claim analyst review maangta hai; combined tool khud verified attack ya risk score invent nahi karta.

Combined evidence credentials/account fields mask karti hai aur size bounded rakhti hai. Tumhara explicitly entered target identifiable rahega. Individual tools ke detailed provider outputs par combined report wali redaction guarantee apply nahi hoti. Downloaded report mein target aur incident metadata ho sakta hai.

Reports browser page mein rehti hain; download karne par file banti hai. Persistent case database, scheduled alerts aur built-in AI chat included nahi hain; AI interaction MCP client se hoti hai.

## Release verification aur license

`VERIFICATION.md` mein actual executed offline checks hain. Live authenticated API access abhi verify nahi hua kyunki keys available nahi hain. GitHub par Linux/Windows aur Node 22/24 ke chaaron CI checks pass hue hain.

Package `@vinaysati/darknet-mcp` GitHub Packages ke liye configured hai. `Publish npm package` workflow build/tests aur extracted package verify karne ke baad publish karti hai. GitHub npm registry se install karne ke liye `read:packages` wala classic token aur npm login chahiye; token repo/chat mein mat rakho. Install instructions README mein hain. MIT terms `LICENSE` mein hain.
