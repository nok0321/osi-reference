/**
 * Reusable Map-based TTL store with periodic cleanup.
 * Prevents unbounded memory growth in long-running servers.
 */

export interface TtlStoreOptions {
  /** Time-to-live in milliseconds */
  ttlMs: number;
  /** Periodic cleanup interval in milliseconds (default: 60_000) */
  cleanupIntervalMs?: number;
}

export interface TtlStore<T> {
  get(key: string): T | undefined;
  set(key: string, value: T): void;
  delete(key: string): void;
  has(key: string): boolean;
  size(): number;
  /** Stop the periodic cleanup timer (for tests / shutdown) */
  destroy(): void;
}

export function createTtlStore<T>(opts: TtlStoreOptions): TtlStore<T> {
  const { ttlMs, cleanupIntervalMs = 60_000 } = opts;
  const store = new Map<string, { value: T; createdAt: number }>();

  function isExpired(createdAt: number): boolean {
    return Date.now() - createdAt > ttlMs;
  }

  function cleanup() {
    for (const [key, entry] of store) {
      if (isExpired(entry.createdAt)) store.delete(key);
    }
  }

  // Periodic cleanup to reclaim memory during idle periods
  const timer = setInterval(cleanup, cleanupIntervalMs);
  // Allow Node.js to exit even if the timer is still active
  if (timer.unref) timer.unref();

  return {
    get(key: string): T | undefined {
      const entry = store.get(key);
      if (!entry) return undefined;
      if (isExpired(entry.createdAt)) {
        store.delete(key);
        return undefined;
      }
      return entry.value;
    },
    set(key: string, value: T) {
      cleanup();
      store.set(key, { value, createdAt: Date.now() });
    },
    delete(key: string) {
      store.delete(key);
    },
    has(key: string): boolean {
      const entry = store.get(key);
      if (!entry) return false;
      if (isExpired(entry.createdAt)) {
        store.delete(key);
        return false;
      }
      return true;
    },
    size(): number {
      return store.size;
    },
    destroy() {
      clearInterval(timer);
      store.clear();
    },
  };
}
