import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { readFile } from "node:fs/promises";
import { z } from "zod";
import { allTools } from "../protocol/tools.js";
import { listSources } from "../meta/sources.js";
import { checkReadiness, type ReadinessReport } from "../meta/readiness.js";
import type { ToolContext, ToolDef } from "../types/index.js";
import { withRequestSignal } from "../utils/http.js";

const MAX_BODY_BYTES = 16 * 1024;
const MAX_INVESTIGATIONS = 2;
const READINESS_CACHE_MS = 60_000;
const READINESS_REFRESH_INTERVAL_MS = 5_000;
const CONTENT_SECURITY_POLICY = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "connect-src 'self'",
  "img-src 'self' data:",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join("; ");

export interface GuiOptions {
  port?: number;
  /** Allows an isolated tool implementation in offline route tests. */
  investigationTool?: ToolDef;
  /** Injectable local diagnostics for offline tests; credentials never enter the response. */
  readinessResolver?: (context: ToolContext, registry: ToolDef[]) => Promise<ReadinessReport>;
}

class BodyError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

function sendJson(response: ServerResponse, status: number, data: unknown): void {
  if (response.destroyed || response.writableEnded) return;
  response.writeHead(status, { "Content-Type": "application/json; charset=utf-8" });
  response.end(JSON.stringify(data));
}

function readJson(request: IncomingMessage): Promise<unknown> {
  const length = request.headers["content-length"];
  if (length && (!/^\d+$/.test(length) || Number(length) > MAX_BODY_BYTES)) {
    request.resume();
    return Promise.reject(new BodyError(413, "Request is too large."));
  }
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    const fail = (error: BodyError): void => {
      request.removeListener("data", onData);
      request.removeListener("end", onEnd);
      request.removeListener("error", onError);
      request.removeListener("aborted", onAborted);
      request.resume();
      reject(error);
    };
    const onData = (chunk: Buffer): void => {
      size += chunk.byteLength;
      if (size > MAX_BODY_BYTES) {
        fail(new BodyError(413, "Request is too large."));
        return;
      }
      chunks.push(chunk);
    };
    const onEnd = (): void => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
      } catch {
        reject(new BodyError(400, "Request must contain valid JSON."));
      }
    };
    const onError = (): void => fail(new BodyError(400, "Could not read the request."));
    const onAborted = (): void => fail(new BodyError(400, "Request was interrupted."));
    request.on("data", onData);
    request.once("end", onEnd);
    request.once("error", onError);
    request.once("aborted", onAborted);
  });
}

/** Serve the investigation console only on the local IPv4 loopback interface. */
export async function startGuiServer(
  context: ToolContext,
  options: GuiOptions = {},
): Promise<{ server: Server; url: string }> {
  const port = options.port ?? 4318;
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new Error("GUI port must be an integer between 0 and 65535.");
  }
  const tool = options.investigationTool ?? allTools.find((item) => item.name === "darknet_investigate");
  if (!tool) throw new Error("The investigation tool is not registered.");
  const inputSchema = z.object(tool.schema).strict();
  const [html, javascript, css] = await Promise.all([
    readFile(new URL("./assets/index.html", import.meta.url)),
    readFile(new URL("./assets/app.js", import.meta.url)),
    readFile(new URL("./assets/app.css", import.meta.url)),
  ]);
  const assets = new Map([
    ["/", { body: html, type: "text/html; charset=utf-8" }],
    ["/app.js", { body: javascript, type: "text/javascript; charset=utf-8" }],
    ["/app.css", { body: css, type: "text/css; charset=utf-8" }],
  ]);
  let listeningPort = port;
  let inFlight = 0;
  const readinessResolver = options.readinessResolver ?? checkReadiness;
  let readinessCache: ReadinessReport | undefined;
  let readinessUpdatedAt = 0;
  let readinessInFlight: Promise<ReadinessReport> | undefined;
  let readinessAttemptAt = 0;

  async function readiness(): Promise<ReadinessReport> {
    if (readinessInFlight) return readinessInFlight;
    readinessAttemptAt = Date.now();
    readinessInFlight = readinessResolver(context, allTools).then((report) => {
      readinessCache = report;
      readinessUpdatedAt = Date.now();
      return report;
    }).finally(() => { readinessInFlight = undefined; });
    return readinessInFlight;
  }

  const server = createServer(async (request, response) => {
    response.setHeader("Content-Security-Policy", CONTENT_SECURITY_POLICY);
    response.setHeader("X-Content-Type-Options", "nosniff");
    response.setHeader("X-Frame-Options", "DENY");
    response.setHeader("Referrer-Policy", "no-referrer");
    response.setHeader("Cache-Control", "no-store");
    response.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");

    const host = request.headers.host?.toLowerCase();
    if (host !== `127.0.0.1:${listeningPort}` && host !== `localhost:${listeningPort}`) {
      sendJson(response, 403, { error: "Only local requests are accepted." });
      return;
    }
    let pathname: string;
    try {
      // Reject absolute-form and protocol-relative request targets.
      if (!request.url?.startsWith("/") || request.url.startsWith("//")) throw new Error();
      pathname = new URL(request.url, `http://${host}`).pathname;
    } catch {
      sendJson(response, 400, { error: "Invalid request URL." });
      return;
    }
    if (request.method === "GET") {
      const asset = assets.get(pathname);
      if (asset) {
        response.writeHead(200, { "Content-Type": asset.type });
        response.end(asset.body);
        return;
      }
      if (pathname === "/api/sources") {
        sendJson(response, 200, { sources: listSources(context.config, allTools) });
        return;
      }
      if (pathname === "/api/readiness") {
        if ((request.headers.origin && request.headers.origin !== `http://${host}`) || request.headers["sec-fetch-site"] === "cross-site") {
          sendJson(response, 403, { error: "Readiness is available only from this local console." });
          return;
        }
        if (!readinessInFlight && (!readinessCache || Date.now() - readinessUpdatedAt >= READINESS_CACHE_MS) && Date.now() - readinessAttemptAt < READINESS_REFRESH_INTERVAL_MS) {
          response.setHeader("Retry-After", "5");
          sendJson(response, 429, { error: "Readiness was checked recently. Wait a few seconds before retrying." });
          return;
        }
        try {
          const report = readinessCache && Date.now() - readinessUpdatedAt < READINESS_CACHE_MS
            ? readinessCache : await readiness();
          sendJson(response, 200, { readiness: report });
        } catch {
          sendJson(response, 503, { error: "Local readiness checks could not complete. Try refreshing shortly." });
        }
        return;
      }
      sendJson(response, 404, { error: "Page not found." });
      return;
    }
    if (request.method !== "POST" || (pathname !== "/api/investigate" && pathname !== "/api/readiness")) {
      sendJson(response, 405, { error: "This action is not available." });
      return;
    }

    // A browser on another website cannot call this local tool, including through DNS rebinding.
    const origin = request.headers.origin;
    if (origin !== `http://${host}` || request.headers["sec-fetch-site"] === "cross-site") {
      sendJson(response, 403, { error: "Requests must start from this local console." });
      return;
    }
    if (request.headers["content-type"]?.split(";", 1)[0]?.trim().toLowerCase() !== "application/json") {
      sendJson(response, 415, { error: "Use an application/json request." });
      return;
    }
    if (pathname === "/api/readiness") {
      try {
        const parsed = z.object({}).strict().safeParse(await readJson(request));
        if (!parsed.success) {
          sendJson(response, 400, { error: "Readiness refresh expects an empty JSON object." });
          return;
        }
      } catch (error) {
        sendJson(response, error instanceof BodyError ? error.status : 400, { error: error instanceof BodyError ? error.message : "Invalid request." });
        return;
      }
      if (readinessInFlight || Date.now() - readinessAttemptAt < READINESS_REFRESH_INTERVAL_MS) {
        response.setHeader("Retry-After", "5");
        sendJson(response, 429, { error: "Readiness was checked recently. Wait a few seconds before refreshing." });
        return;
      }
      try {
        sendJson(response, 200, { readiness: await readiness() });
      } catch {
        sendJson(response, 503, { error: "Local readiness checks could not complete. Try refreshing shortly." });
      }
      return;
    }
    if (inFlight >= MAX_INVESTIGATIONS) {
      response.setHeader("Retry-After", "5");
      sendJson(response, 429, { error: "Two investigations are already running. Try again when one finishes." });
      return;
    }
    let args: Record<string, unknown>;
    try {
      const parsed = inputSchema.safeParse(await readJson(request));
      if (!parsed.success) {
        sendJson(response, 400, {
          error: "Check the target, target type, selected sources, and result limit.",
          fields: [...new Set(parsed.error.issues.map((issue) => String(issue.path[0] ?? "request")))],
        });
        return;
      }
      args = parsed.data;
    } catch (error) {
      const status = error instanceof BodyError ? error.status : 400;
      sendJson(response, status, { error: error instanceof BodyError ? error.message : "Invalid request." });
      return;
    }
    // Recheck after reading the body because other requests may have acquired a slot.
    if (inFlight >= MAX_INVESTIGATIONS) {
      response.setHeader("Retry-After", "5");
      sendJson(response, 429, { error: "Two investigations are already running. Try again when one finishes." });
      return;
    }
    inFlight++;
    const controller = new AbortController();
    const cancel = (): void => {
      if (!response.writableEnded) controller.abort(new Error("Local console request disconnected."));
    };
    response.once("close", cancel);
    try {
      const result = await withRequestSignal(controller.signal, () => tool.execute(args, context));
      if (result.isError) {
        sendJson(response, 400, { error: "The investigation could not start. Check the target and selected sources." });
        return;
      }
      const report = result.structuredContent ?? JSON.parse(result.content.map((item) => item.text).join("\n"));
      sendJson(response, 200, { report });
    } catch {
      // Provider exception messages can contain keys or raw personal data; never reflect them.
      sendJson(response, 502, { error: "The investigation could not complete. Check server configuration and try again." });
    } finally {
      inFlight--;
      response.removeListener("close", cancel);
    }
  });
  server.requestTimeout = 30_000;
  server.headersTimeout = 15_000;
  server.keepAliveTimeout = 5_000;
  server.maxRequestsPerSocket = 100;
  await new Promise<void>((resolve, reject) => {
    const onError = (error: Error): void => reject(error);
    server.once("error", onError);
    server.listen(port, "127.0.0.1", () => {
      server.removeListener("error", onError);
      const address = server.address();
      if (!address || typeof address === "string") {
        reject(new Error("Could not determine the local GUI address."));
        return;
      }
      listeningPort = address.port;
      resolve();
    });
  });
  return { server, url: `http://127.0.0.1:${listeningPort}` };
}
