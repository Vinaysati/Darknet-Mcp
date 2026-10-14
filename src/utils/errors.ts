import type { ToolContext } from "../types/index.js";
export function safeErrorMessage(error: unknown, ctx?: ToolContext): string {
  let message = error instanceof Error ? error.message : "Unexpected tool failure";
  for (const [name, value] of Object.entries(ctx?.config ?? {})) {
    if (/key/i.test(name) && typeof value === "string" && value.length > 0) message = message.split(value).join("[REDACTED]");
  }
  return message.replace(/((?:api[_-]?key|password|token|authorization)\s*[=:]\s*)[^\s&,;]+/gi, "$1[REDACTED]").slice(0, 800);
}
