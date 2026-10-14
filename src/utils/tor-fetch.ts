import net from "node:net";
import http from "node:http";
import https from "node:https";
import { SocksProxyAgent } from "socks-proxy-agent";
import * as cheerio from "cheerio";
import { RateLimiter } from "./rate-limiter.js";
import { getRequestSignal } from "./http.js";

// ─── Tor SOCKS5 Proxy Client ───

const MAX_BODY_SIZE = 10 * 1024 * 1024; // 10 MB
const TOR_TIMEOUT_MS = 60_000; // 60 seconds
const TOR_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0";

// Rate limiter: 3s between Tor requests (circuits are slow + shared)
const torLimiter = new RateLimiter(3000);

export interface TorStatus {
  socksAvailable: boolean;
  socksHost: string;
  socksPort: number;
}

export interface ScrapedPage {
  url: string;
  statusCode: number;
  title: string;
  links: { href: string; text: string }[];
  bodyText: string;
  fetchTimeMs: number;
}

// ─── Check Tor Status ───

export async function checkTorStatus(
  host = "127.0.0.1",
  port = 9050,
): Promise<TorStatus> {
  const signal = getRequestSignal();
  const available = await new Promise<boolean>((resolve) => {
    const socket = new net.Socket();
    let settled = false;
    let greeting = Buffer.alloc(0);
    const finish = (available: boolean): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener("abort", cancelled);
      socket.destroy();
      resolve(available);
    };
    const cancelled = () => finish(false);
    const timer = setTimeout(cancelled, 5_000);

    socket.on("connect", () => {
      // SOCKS5 handshake: version 5, 1 auth method (no auth)
      socket.write(Buffer.from([0x05, 0x01, 0x00]));
    });

    socket.on("data", (data: Buffer) => {
      greeting = Buffer.concat([greeting, data.subarray(0, 2 - greeting.length)]);
      if (greeting.length < 2) return;
      // Valid SOCKS5 response: 0x05 0x00 (no auth required)
      finish(greeting[0] === 0x05 && greeting[1] === 0x00);
    });

    socket.on("error", cancelled);
    socket.on("close", cancelled);
    signal?.addEventListener("abort", cancelled, { once: true });
    if (signal?.aborted) { cancelled(); return; }

    socket.connect(port, host);
  });

  return { socksAvailable: available, socksHost: host, socksPort: port };
}

// ─── Create SOCKS5h Agent ───

function createAgent(host: string, port: number): SocksProxyAgent {
  // socks5h:// = DNS resolution on Tor side (prevents DNS leaks)
  return new SocksProxyAgent(`socks5h://${host}:${port}`, {
    timeout: TOR_TIMEOUT_MS,
  });
}

// ─── Validate .onion URL ───

function validateOnionUrl(url: string): URL {
  const parsed = new URL(url);
  if (!parsed.hostname.endsWith(".onion")) {
    throw new Error("Only .onion URLs are allowed for Tor fetch. Use regular fetch for clearnet.");
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("Only http:// and https:// protocols are supported.");
  }
  return parsed;
}

// ─── Fetch Raw HTML from .onion ───

export async function fetchOnion(
  url: string,
  host = "127.0.0.1",
  port = 9050,
): Promise<{ html: string; statusCode: number }> {
  const parsed = validateOnionUrl(url);
  const signal = getRequestSignal();
  const cancellationError = (): Error => signal?.reason instanceof Error
    ? signal.reason : new Error("Tor request cancelled");
  if (signal?.aborted) throw cancellationError();
  await torLimiter.acquire();
  if (signal?.aborted) throw cancellationError();

  const agent = createAgent(host, port);
  const client = parsed.protocol === "https:" ? https : http;

  return new Promise<{ html: string; statusCode: number }>((resolve, reject) => {
    let deadline: ReturnType<typeof setTimeout> | undefined;
    let onAbort: (() => void) | undefined;
    let settled = false;
    const finish = (error?: Error, value?: { html: string; statusCode: number }): void => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      if (onAbort) signal?.removeEventListener("abort", onAbort);
      if (error) reject(error);
      else if (value) resolve(value);
    };
    // node:http and node:https do not follow redirects. A Location header can
    // never move this request to clearnet or bypass the onion URL validation.
    const req = client.get(
      parsed,
      {
        agent,
        timeout: TOR_TIMEOUT_MS,
        headers: {
          "User-Agent": TOR_USER_AGENT,
          Accept: "text/html,application/xhtml+xml,*/*",
          "Accept-Language": "en-US,en;q=0.5",
          Referer: "",
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        let totalSize = 0;

        res.on("data", (chunk: Buffer) => {
          if (settled) return;
          totalSize += chunk.length;
          if (totalSize > MAX_BODY_SIZE) {
            const error = new Error(`Response exceeded ${MAX_BODY_SIZE} bytes limit`);
            finish(error);
            req.destroy(error);
            return;
          }
          chunks.push(chunk);
        });

        res.on("end", () => {
          if (settled) return;
          const html = Buffer.concat(chunks).toString("utf-8");
          finish(undefined, { html, statusCode: res.statusCode ?? 0 });
        });

        res.on("error", (error: Error) => finish(error));
        res.on("aborted", () => finish(new Error("Tor response ended before the full body was received.")));
      },
    );

    req.on("error", (err) => {
      if (err.message.includes("ECONNREFUSED")) {
        finish(new Error(
          `Tor SOCKS5 proxy not available at ${host}:${port}. ` +
          "Start Tor daemon first: brew services start tor (macOS) or sudo systemctl start tor (Linux)",
        ));
      } else {
        finish(err);
      }
    });

    const timeout = (): void => {
      const error = new Error(`Tor request timed out after ${TOR_TIMEOUT_MS}ms`);
      finish(error);
      req.destroy(error);
    };
    req.on("timeout", timeout);
    // The socket timeout alone does not bound a response that trickles forever.
    if (!settled) {
      deadline = setTimeout(timeout, TOR_TIMEOUT_MS);
      if (signal) {
        onAbort = (): void => {
          const error = cancellationError();
          finish(error);
          req.destroy(error);
        };
        signal.addEventListener("abort", onAbort, { once: true });
        // Cancellation can happen between the initial check and subscription.
        if (signal.aborted) onAbort();
      }
    }
  }).finally(() => agent.destroy());
}

// ─── Scrape .onion Page (parsed) ───

export async function scrapeOnion(
  url: string,
  host = "127.0.0.1",
  port = 9050,
): Promise<ScrapedPage> {
  const start = Date.now();
  const { html, statusCode } = await fetchOnion(url, host, port);
  const $ = cheerio.load(html);

  const title = $("title").first().text().trim();

  const links: { href: string; text: string }[] = [];
  $("a[href]").each((_, el) => {
    const href = $(el).attr("href") ?? "";
    const linkText = $(el).text().trim();
    if (href && linkText) {
      links.push({ href, text: linkText });
    }
  });

  // Extract visible body text
  $("script, style, noscript, iframe").remove();
  const bodyText = $("body").text().replace(/\s+/g, " ").trim();

  return {
    url,
    statusCode,
    title,
    links,
    bodyText: bodyText.substring(0, 50_000),
    fetchTimeMs: Date.now() - start,
  };
}
