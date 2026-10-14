import { getRequestSignal } from "./http.js";
interface Waiter { resolve: () => void; reject: (reason: unknown) => void; signal?: AbortSignal; cancel: () => void; }
/** Space provider requests while allowing cancelled investigations to leave the queue. */
export class RateLimiter {
  private lastRequest = 0;
  private queue: Waiter[] = [];
  private processing = false;
  private wake?: () => void;
  constructor(private minDelayMs: number) {}
  acquire(signal = getRequestSignal()): Promise<void> {
    if (signal?.aborted) return Promise.reject(signal.reason ?? new Error("Request cancelled"));
    return new Promise((resolve, reject) => {
      const waiter: Waiter = { resolve, reject, signal, cancel: () => {
        const index = this.queue.indexOf(waiter);
        if (index >= 0) this.queue.splice(index, 1);
        if (this.queue.length === 0) this.wake?.();
        signal?.removeEventListener("abort", waiter.cancel);
        reject(signal?.reason ?? new Error("Request cancelled"));
      } };
      this.queue.push(waiter);
      signal?.addEventListener("abort", waiter.cancel, { once: true });
      if (!this.processing) void this.processQueue();
    });
  }
  private async processQueue(): Promise<void> {
    this.processing = true;
    try {
      while (this.queue.length > 0) {
        const wait = this.minDelayMs - (Date.now() - this.lastRequest);
        if (wait > 0) {
          await new Promise<void>(resolve => {
            const finish = () => { clearTimeout(timer); this.wake = undefined; resolve(); };
            const timer = setTimeout(finish, wait);
            this.wake = finish;
          });
          // An emptied queue can wake early; recheck spacing before admitting new work.
          continue;
        }
        const waiter = this.queue.shift();
        if (!waiter) continue;
        waiter.signal?.removeEventListener("abort", waiter.cancel);
        if (waiter.signal?.aborted) { waiter.reject(waiter.signal.reason); continue; }
        this.lastRequest = Date.now(); waiter.resolve();
      }
    } finally { this.processing = false; }
  }
}
