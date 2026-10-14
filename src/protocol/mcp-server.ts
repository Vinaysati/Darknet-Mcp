import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { allTools } from "./tools.js";
import type { ToolContext } from "../types/index.js";
import { VERSION } from "../version.js";
import { safeErrorMessage } from "../utils/errors.js";
import { withRequestSignal } from "../utils/http.js";

export function createMcpServer(ctx: ToolContext): McpServer {
  const server = new McpServer({ name: "darknet-mcp", version: VERSION });
  for (const tool of allTools) {
    server.registerTool(tool.name, {
      description: tool.description, inputSchema: tool.schema,
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: tool.name !== "darknet_list_sources" },
    }, async (args, extra) => {
      try { return await withRequestSignal(extra.signal, () => tool.execute(args, ctx)); }
      catch (error) { return { content: [{ type: "text" as const, text: "Error: " + safeErrorMessage(error, ctx) }], isError: true }; }
    });
  }
  return server;
}

export async function startMcpStdio(ctx: ToolContext): Promise<McpServer> {
  const server = createMcpServer(ctx);
  await server.connect(new StdioServerTransport());
  console.error("[darknet-mcp] MCP server started on stdio");
  return server;
}
