import { spawnSync } from "node:child_process";
import { cpSync, readdirSync, rmSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
rmSync(new URL("../.test-dist/", import.meta.url), { recursive: true, force: true });
const result = spawnSync(process.execPath, [fileURLToPath(new URL("../node_modules/typescript/bin/tsc", import.meta.url)), "-p", "tsconfig.tests.json"], { cwd: root, stdio: "inherit" });
if (result.status !== 0) process.exit(result.status ?? 1);
if (existsSync(new URL("../src/gui/assets/", import.meta.url))) cpSync(new URL("../src/gui/assets/", import.meta.url), new URL("../.test-dist/src/gui/assets/", import.meta.url), { recursive: true });
const tests = readdirSync(new URL("../.test-dist/tests/", import.meta.url)).filter(name => name.endsWith(".test.js")).map(name => fileURLToPath(new URL("../.test-dist/tests/" + name, import.meta.url)));
const run = spawnSync(process.execPath, ["--test", "--test-concurrency=1", ...tests], { cwd: root, stdio: "inherit" });
process.exit(run.status ?? 1);
