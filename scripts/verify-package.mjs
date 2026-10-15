import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const source = fileURLToPath(new URL("../", import.meta.url));
const directory = resolve(process.argv[2] ?? "package-out");
const archives = readdirSync(directory).filter(name => name.endsWith(".tgz"));
assert.equal(archives.length, 1, "Expected exactly one packed archive");
const archive = join(directory, archives[0]);
const listing = spawnSync("tar", ["-tzf", archive], { encoding: "utf8" });
assert.equal(listing.status, 0, listing.stderr);
const files = listing.stdout.trim().split(/\r?\n/);
for (const name of files) {
  assert.ok(name.startsWith("package/") && !name.split("/").includes(".."), "Unsafe archive path");
  assert.ok(!/(?:^|\/)(?:node_modules|src|tests|\.git|\.github|\.test-dist)(?:\/|$)/.test(name), "Development files in package: " + name);
  assert.ok(name === "package/.env.example" || !/(?:^|\/)\.env(?:[./]|$)/.test(name), "Environment secrets in package");
  assert.ok(!name.endsWith("/.npmrc"), "Registry credentials/config must not be packed");
}
for (const name of ["dist/index.js", "dist/gui/assets/index.html", "dist/gui/assets/app.js", "dist/gui/assets/app.css", "LICENSE", "README.md", ".env.example"]) {
  assert.ok(files.includes("package/" + name), "Missing runtime asset: " + name);
}

const temporary = mkdtempSync(join(tmpdir(), "darknet-packed-runtime-"));
let client;
let gui;
try {
  const extracted = spawnSync("tar", ["-xzf", archive, "-C", temporary], { encoding: "utf8" });
  assert.equal(extracted.status, 0, extracted.stderr);
  const root = join(temporary, "package");
  const metadata = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  assert.equal(metadata.name, "@vinaysati/darknet-mcp");
  assert.notEqual(metadata.private, true);
  assert.equal(metadata.publishConfig.registry, "https://npm.pkg.github.com");
  assert.equal(metadata.repository.url, "https://github.com/Vinaysati/Darknet-Mcp.git");
  const template = readFileSync(join(root, ".env.example"), "utf8");
  for (const line of template.split(/\r?\n/)) if (/^[A-Z_]*(?:KEY|TOKEN)=/.test(line)) assert.ok(line.endsWith("="), "A nonempty key in the example environment");
  assert.equal(readFileSync(join(root, "LICENSE"), "utf8"), readFileSync(join(source, "LICENSE"), "utf8"));
  // Use the frozen-lockfile runtime dependencies, rather than fetching any provider data.
  symlinkSync(join(source, "node_modules"), join(root, "node_modules"), "junction");
  const entry = join(root, "dist/index.js");
  assert.ok(readFileSync(entry, "utf8").startsWith("#!/usr/bin/env node"));
  for (const args of [["--help"], ["--list"], ["--tool", "darknet_list_sources", "{}"]]) {
    const result = spawnSync(process.execPath, [entry, ...args], { encoding: "utf8", timeout: 8000 });
    assert.equal(result.status, 0, result.stderr);
    if (args[0] === "--tool") assert.equal(JSON.parse(result.stdout).tool_count, 68);
  }
  client = new Client({ name: "packed-runtime-check", version: "1.0.0" });
  await client.connect(new StdioClientTransport({ command: process.execPath, args: [entry], env: { PATH: process.env.PATH ?? "" }, stderr: "pipe" }));
  const tools = await client.listTools();
  assert.equal(tools.tools.length, 68);
  assert.equal(new Set(tools.tools.map(tool => tool.name)).size, 68);
  await client.close(); client = undefined;
  const { startGuiServer } = await import(pathToFileURL(join(root, "dist/gui/server.js")).href);
  const { buildToolContext } = await import(pathToFileURL(join(root, "dist/config.js")).href);
  gui = await startGuiServer(buildToolContext({}), { port: 0 });
  for (const path of ["/", "/app.js", "/app.css", "/api/sources"]) {
    const response = await fetch(gui.url + path, { signal: AbortSignal.timeout(5000) });
    assert.equal(response.status, 200, path);
    if (path === "/api/sources") assert.equal((await response.json()).sources.length, 17);
    else assert.ok((await response.text()).length > 0);
  }
  console.log(JSON.stringify({ archive: archives[0], package: metadata.name, version: metadata.version, entries: files.length, cli: "PASS", mcp_tools: 68, gui_assets: "PASS", secret_files: "absent" }));
} finally {
  if (client) await client.close();
  if (gui) { gui.server.closeAllConnections(); await new Promise(resolve => gui.server.close(resolve)); }
  rmSync(temporary, { recursive: true, force: true });
}
