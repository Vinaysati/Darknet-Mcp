import { createHash } from "node:crypto";
/** Partition authenticated caches without keeping raw credentials in cache keys. */
export function keyScope(key?: string): string {
  return key ? createHash("sha256").update(key).digest("hex") : "public";
}
