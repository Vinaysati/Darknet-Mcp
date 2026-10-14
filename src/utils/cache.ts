/** Bounded TTL/LRU cache. Expired entries are pruned on reads and writes. */
export class TTLCache<T> {
  private store = new Map<string, { value: T; expires: number; bytes: number }>();
  private bytes = 0;
  constructor(private ttlMs: number, private maxEntries = 128, private maxBytes = 32 * 1024 * 1024) {}
  private remove(key: string): void {
    const entry = this.store.get(key);
    if (entry) { this.bytes -= entry.bytes; this.store.delete(key); }
  }
  private prune(): void {
    const now = Date.now();
    for (const [key, entry] of this.store) if (now >= entry.expires) this.remove(key);
  }
  get(key: string): T | undefined {
    const entry = this.store.get(key);
    if (!entry) return undefined;
    if (Date.now() >= entry.expires) { this.remove(key); return undefined; }
    this.store.delete(key); this.store.set(key, entry);
    return entry.value;
  }
  set(key: string, value: T): void {
    this.prune(); this.remove(key);
    let bytes: number;
    try { bytes = Buffer.byteLength(JSON.stringify(value) ?? "", "utf8"); } catch { return; }
    if (bytes > this.maxBytes || this.maxEntries < 1) return;
    this.store.set(key, { value, expires: Date.now() + this.ttlMs, bytes }); this.bytes += bytes;
    while (this.store.size > this.maxEntries || this.bytes > this.maxBytes) this.remove(this.store.keys().next().value!);
  }
  has(key: string): boolean { return this.get(key) !== undefined; }
  clear(): void { this.store.clear(); this.bytes = 0; }
  get size(): number { this.prune(); return this.store.size; }
}
