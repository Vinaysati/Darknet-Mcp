import { spawnSync } from "node:child_process";
import { cpSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const version = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).version;
writeFileSync(new URL("../src/version.ts", import.meta.url), "export const VERSION = " + JSON.stringify(version) + ";\n");
const result = spawnSync(process.execPath, [fileURLToPath(new URL("../node_modules/typescript/bin/tsc", import.meta.url)), "-p", "tsconfig.build.json"], { cwd: root, stdio: "inherit" });
if (result.status !== 0) process.exit(result.status ?? 1);
mkdirSync(new URL("../dist/gui/", import.meta.url), { recursive: true });
cpSync(new URL("../src/gui/assets/", import.meta.url), new URL("../dist/gui/assets/", import.meta.url), { recursive: true });
