import { z } from "zod";
import type { ToolContext, ToolDef, ToolResult } from "./types/index.js";
import { safeErrorMessage } from "./utils/errors.js";

export async function executeCliTool(tool: ToolDef, input: unknown, ctx: ToolContext): Promise<ToolResult> {
  const parsed = z.object(tool.schema).strict().safeParse(input);
  if (!parsed.success) throw new Error("Invalid tool arguments: " + parsed.error.issues.map(issue => issue.path.join(".") + ": " + issue.message).join("; "));
  try { return await tool.execute(parsed.data, ctx); }
  catch (error) { throw new Error(safeErrorMessage(error, ctx)); }
}
