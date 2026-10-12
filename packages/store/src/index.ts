/**
 * A durable-enough JSON document store for service metadata.
 *
 * PRD section 25/26: accounts, credentials, template metadata, sessions and
 * proof records are small, structured and never contain plaintext biometrics.
 * A single-file store keeps the MVP runnable without a database; the interface
 * is deliberately narrow so swapping in Postgres means reimplementing this file
 * and nothing else.
 *
 * The collection is keyed by `id` at runtime but the static type parameter is
 * only constrained to `object`, so one store can back several record shapes
 * (`StoredPasskeyCredential`, `SubmissionRecord`, ...) without the caller
 * casting at every boundary.
 *
 * Writes are atomic (temp file + rename) and serialised through a promise chain
 * so concurrent requests cannot interleave and corrupt the snapshot.
 */

import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import path from "node:path";

export interface StoreOptions {
  /** Directory for the snapshot file. */
  directory: string;
  /** File name; defaults to `store.json`. */
  fileName?: string;
  /** Flush to disk after every write. Disable in tests. */
  persist?: boolean;
}

export interface Record_ {
  id: string;
  createdAt: number;
  updatedAt: number;
  [key: string]: unknown;
}

export type WithTimestamps<T> = T & { createdAt: number; updatedAt: number };

export class JsonStore<T extends object> {
  private readonly collections = new Map<string, Map<string, T>>();
  private writeChain: Promise<void> = Promise.resolve();
  private dirty = false;

  constructor(private readonly options: StoreOptions) {
    if (options.persist !== false) mkdirSync(options.directory, { recursive: true });
    this.load();
  }

  private get file(): string {
    return path.join(this.options.directory, this.options.fileName ?? "store.json");
  }

  private load(): void {
    if (this.options.persist === false) return;
    if (!existsSync(this.file)) return;
    try {
      const parsed = JSON.parse(readFileSync(this.file, "utf-8")) as Record<string, Record<string, T>>;
      for (const [name, records] of Object.entries(parsed)) {
        this.collections.set(name, new Map(Object.entries(records)));
      }
    } catch {
      // A corrupt snapshot must not take the service down; start empty and let
      // the caller re-enroll rather than silently serving stale metadata.
      this.collections.clear();
    }
  }

  private collection(name: string): Map<string, T> {
    let existing = this.collections.get(name);
    if (!existing) {
      existing = new Map();
      this.collections.set(name, existing);
    }
    return existing;
  }

  put(name: string, record: T & { id: string }): T {
    const now = Math.floor(Date.now() / 1000);
    const stored = { ...record, updatedAt: now, createdAt: (record as { createdAt?: number }).createdAt ?? now } as T;
    this.collection(name).set(record.id, stored);
    this.schedulePersist();
    return stored;
  }

  get(name: string, id: string): T | undefined {
    return this.collection(name).get(id);
  }

  has(name: string, id: string): boolean {
    return this.collection(name).has(id);
  }

  delete(name: string, id: string): boolean {
    const removed = this.collection(name).delete(id);
    if (removed) this.schedulePersist();
    return removed;
  }

  list(name: string, predicate?: (record: T) => boolean): T[] {
    const all = [...this.collection(name).values()];
    return predicate ? all.filter(predicate) : all;
  }

  find(name: string, predicate: (record: T) => boolean): T | undefined {
    for (const record of this.collection(name).values()) {
      if (predicate(record)) return record;
    }
    return undefined;
  }

  update(name: string, id: string, patch: Partial<T>): T | undefined {
    const existing = this.collection(name).get(id);
    if (!existing) return undefined;
    const next = { ...existing, ...patch, id, updatedAt: Math.floor(Date.now() / 1000) } as T;
    this.collection(name).set(id, next);
    this.schedulePersist();
    return next;
  }

  count(name: string, predicate?: (record: T) => boolean): number {
    return this.list(name, predicate).length;
  }

  clear(name: string): void {
    this.collections.delete(name);
    this.schedulePersist();
  }

  /** Snapshot everything and write atomically. */
  flush(): void {
    if (this.options.persist === false) return;
    const snapshot: Record<string, Record<string, T>> = {};
    for (const [name, records] of this.collections) snapshot[name] = Object.fromEntries(records);
    const target = this.file;
    const temporary = `${target}.${process.pid}.tmp`;
    writeFileSync(temporary, JSON.stringify(snapshot, null, 2), "utf-8");
    renameSync(temporary, target);
    this.dirty = false;
  }

  private schedulePersist(): void {
    this.dirty = true;
    if (this.options.persist === false) return;
    this.writeChain = this.writeChain.then(() => {
      if (this.dirty) this.flush();
    });
  }

  async settled(): Promise<void> {
    await this.writeChain;
  }
}

export interface StoredRecord extends Record_ {
  id: string;
}

/** In-memory store for tests. */
export function memoryStore<T extends object>(): JsonStore<T> {
  return new JsonStore<T>({ directory: "", persist: false });
}
