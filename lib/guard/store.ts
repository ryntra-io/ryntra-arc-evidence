import { existsSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { compareCanonicalStrings } from "./canonical.ts";

/**
 * Guard prototype persistence port.
 *
 * The kernel does not care where its objects live, but it must never be able to
 * pretend they survive when they do not. Every adapter therefore declares its
 * own durability, and the runtime refuses state-changing calls when the declared
 * durability is weaker than the deployment requires. That refusal is the point
 * of this file: an ephemeral store is legitimate for a local demo and is a
 * correctness bug in a multi-instance deployment, and only the adapter itself
 * can honestly say which one it is.
 *
 * The port is asynchronous because a store that is safe for concurrent writers
 * lives across a network, and a synchronous `Map`-shaped surface can never
 * reach one. That was not a style choice — the previous surface made a
 * multi-writer adapter unrepresentable, which is why a multi-instance
 * deployment had to refuse every state change outright.
 */
export type GuardStoreDurability =
  /** Per-process memory. Lost on cold start; never shared between instances. */
  | "EPHEMERAL_SINGLE_INSTANCE"
  /** Survives cold start on one writer. Not safe for concurrent instances. */
  | "DURABLE_SINGLE_WRITER"
  /** Survives cold start and concurrent writers. */
  | "DURABLE_MULTI_WRITER";

export const GUARD_COLLECTIONS = [
  "intents",
  "evaluations",
  "authorizations",
  "executions",
  "receipts",
  "idempotency",
  "transactionIndex",
  /* Treasury payout collections. Appended rather than folded into the existing
     names: a payout is a business facade over one `SEND` intent, and mixing the
     two in one collection would make a tenant scan over intents return records
     that are not intents. */
  "payouts",
  "payoutBeneficiaries",
  "payoutPolicies",
  "payoutApprovals",
  "payoutReservations",
  "payoutReceipts",
  /* Payout markers must never share the legacy Guard idempotency namespace:
     legacy keys are delimiter-concatenated and cannot be made collision-free by
     changing only the payout key encoding. */
  "payoutIdempotency",
  /* Agent Control lifecycle collections. Appended for the same reason the
     payout ones were: an agent intent is not a Guard SEND intent, and folding
     them together would make a scan over one return records of the other. The
     audit collection is written only through insertIfAbsent, which is what
     makes append-only a property of the store rather than of the caller. */
  "agentIntents",
  "agentArtifacts",
  "agentAuthorizations",
  "agentObservations",
  "agentReconciliations",
  "agentPolicies",
  "agentIdempotency",
  "agentAudit",
  /* Release D external-adoption collections. Appended for the third time on
     the same reasoning: an API key is not an agent intent, and a quota window
     is not either. They add no DDL — the Postgres adapter is one table keyed
     by (collection, key), so a new collection name is a new value in a column
     that already exists rather than a migration. */
  "agentTenants",
  "agentApiKeys",
  "agentQuotas",
  "agentOauthClients",
  "agentOauthGrants",
  "agentOauthTokens",
  "agentMcpReceipts",
] as const;

export type GuardCollectionName = (typeof GUARD_COLLECTIONS)[number];

/**
 * Deliberately the smallest surface the kernel actually uses.
 *
 * `insertIfAbsent` is the one operation that cannot be composed from the
 * others. Read-then-write is a race: two instances both see a free idempotency
 * key, a free intent id or an unrecorded transaction hash, and both write. On a
 * single writer that window does not exist, which is exactly why the shape has
 * to carry the guarantee rather than the caller — the caller cannot tell which
 * adapter it is talking to.
 */
export type GuardCollection<T> = {
  get(key: string): Promise<T | undefined>;
  set(key: string, value: T): Promise<void>;
  /**
   * Atomically claim a key. Resolves `true` when this caller stored the value
   * and `false` when the key already existed — never overwriting the winner.
   */
  insertIfAbsent(key: string, value: T): Promise<boolean>;
  /**
   * Atomically claim every key in one collection. Either all entries are
   * inserted or none are. Sorting is handled by the adapter so concurrent
   * writers acquire overlapping keys in one deterministic order.
   */
  insertAllIfAbsent(entries: readonly { key: string; value: T }[]): Promise<boolean>;
  /**
   * Remove a key. Used to release a claim whose operation failed — a burnt
   * idempotency key would make a corrected retry impossible forever.
   */
  delete(key: string): Promise<void>;
  has(key: string): Promise<boolean>;
  /**
   * Every stored value whose key starts with `keyPrefix`.
   *
   * Keys are `${tenantId}:${objectId}`, so the prefix is what keeps a tenant
   * scan from reading another tenant's rows — on a shared table that is a
   * tenancy boundary, not an optimization.
   */
  valuesWithPrefix(keyPrefix: string): Promise<readonly T[]>;
};

/**
 * A record whose updates are serialized by an explicit version counter.
 *
 * `insertIfAbsent` decides who *creates* a key. It cannot decide who *updates*
 * one, and a daily-outflow reservation is updated several times across its
 * life — reserved, then committed or released. Read-modify-write on that record
 * is the same race the insert helper exists to close, one step later: two
 * writers read version 3, both write version 4, and one transition disappears.
 */
export type GuardVersionedRecord = { readonly version: number };

export type GuardAtomicVersionedWrite = {
  readonly collection: GuardCollectionName;
  readonly key: string;
  readonly expectedVersion: number | null;
  readonly next: GuardVersionedRecord;
};

export type GuardVersionedCollection<T extends GuardVersionedRecord> = GuardCollection<T> & {
  /**
   * Atomically write `next` only if the stored record is still at
   * `expectedVersion`.
   *
   * - `expectedVersion === null` means "create": the write succeeds only if the
   *   key is absent, so a create cannot silently clobber a concurrent one.
   * - Otherwise the write succeeds only if the stored `version` matches exactly.
   *
   * Resolves `true` when this caller wrote and `false` when it lost the race.
   * A loser is expected to re-read and decide again — see
   * {@link withBoundedCasRetry} — never to retry blindly forever.
   */
  compareAndSet(key: string, expectedVersion: number | null, next: T): Promise<boolean>;
};

export type GuardStore = {
  readonly durability: GuardStoreDurability;
  /** Human-readable adapter identity for `/health`, status limitations and docs. */
  readonly description: string;
  collection<T>(name: GuardCollectionName): GuardCollection<T>;
  /**
   * The same collection, with compare-and-set.
   *
   * Every adapter implements the identical semantic contract; only the
   * mechanism differs — a synchronous check in one process, a whole-file
   * replace on one writer, a conditional `UPDATE` in the database. An adapter
   * that could not offer it would be an adapter on which a daily limit is not
   * a limit.
   */
  versioned<T extends GuardVersionedRecord>(name: GuardCollectionName): GuardVersionedCollection<T>;
  /**
   * Atomically apply version-checked writes across Guard collections.
   *
   * This is intentionally a store-level primitive rather than a service-level
   * compensation loop. A payout authorization and its outflow reservation, or
   * a transaction-hash claim and the payout record that consumes it, are one
   * correctness boundary: a process interruption may expose both or neither,
   * never only one side.
   */
  compareAndSetMany(writes: readonly GuardAtomicVersionedWrite[]): Promise<boolean>;
  /** Release adapter resources. Adapters that hold none resolve immediately. */
  close?(): Promise<void>;
};

/** How many times a lost compare-and-set is re-attempted before giving up. */
export const GUARD_CAS_MAX_ATTEMPTS = 5;

export class GuardCasExhaustedError extends Error {
  constructor(attempts: number) {
    super(`Contended record did not settle within ${attempts} attempts.`);
    this.name = "GuardCasExhaustedError";
  }
}

/**
 * Run a read-decide-write cycle until it wins or the attempt budget runs out.
 *
 * The budget is the point. An unbounded retry under sustained contention is a
 * request that never returns and a connection that is never released; failing
 * after a stated number of attempts turns that into an honest, retryable error
 * the caller can surface.
 *
 * `attempt` returns `false` to mean "I lost the race, re-read and try again"
 * and any value to mean "done". It must re-read state itself: a closure that
 * captures the version it read the first time will lose every subsequent round.
 */
export async function withBoundedCasRetry<T>(
  attempt: () => Promise<T | false>,
  attempts: number = GUARD_CAS_MAX_ATTEMPTS,
): Promise<T> {
  if (!Number.isInteger(attempts) || attempts < 1) {
    throw new TypeError("A compare-and-set budget must be at least one attempt.");
  }
  for (let round = 0; round < attempts; round += 1) {
    const result = await attempt();
    if (result !== false) return result;
  }
  throw new GuardCasExhaustedError(attempts);
}

export function storeSurvivesColdStart(store: GuardStore): boolean {
  return store.durability !== "EPHEMERAL_SINGLE_INSTANCE";
}

export function storeSupportsConcurrentInstances(store: GuardStore): boolean {
  return store.durability === "DURABLE_MULTI_WRITER";
}

/** The exact limitation strings the API reports for a given adapter. */
export function guardStoreLimitations(store: GuardStore): readonly string[] {
  if (!storeSurvivesColdStart(store)) return ["EPHEMERAL_SINGLE_INSTANCE_STORE"];
  if (!storeSupportsConcurrentInstances(store)) return ["DURABLE_SINGLE_WRITER_STORE"];
  return ["DURABLE_MULTI_WRITER_STORE"];
}

export function createMemoryGuardStore(): GuardStore {
  const maps = new Map<GuardCollectionName, Map<string, unknown>>();

  function mapFor(name: GuardCollectionName): Map<string, unknown> {
    let map = maps.get(name);
    if (!map) {
      map = new Map<string, unknown>();
      maps.set(name, map);
    }
    return map;
  }

  function collection<T>(name: GuardCollectionName): GuardCollection<T> {
    return {
        async get(key) {
          return mapFor(name).get(key) as T | undefined;
        },
        async set(key, value) {
          mapFor(name).set(key, value);
        },
        async insertIfAbsent(key, value) {
          /* A single JavaScript process runs this to completion with no await
             in between, so the check and the write cannot interleave. */
          const map = mapFor(name);
          if (map.has(key)) return false;
          map.set(key, value);
          return true;
        },
        async insertAllIfAbsent(entries) {
          const ordered = [...entries].sort((left, right) =>
            compareCanonicalStrings(left.key, right.key),
          );
          const keys = new Set(ordered.map((entry) => entry.key));
          if (keys.size !== ordered.length) {
            throw new TypeError("Guard batch claims require unique keys.");
          }
          const map = mapFor(name);
          if (ordered.some((entry) => map.has(entry.key))) return false;
          for (const entry of ordered) map.set(entry.key, entry.value);
          return true;
        },
        async delete(key) {
          mapFor(name).delete(key);
        },
        async has(key) {
          return mapFor(name).has(key);
        },
        async valuesWithPrefix(keyPrefix) {
          const out: T[] = [];
          for (const [key, value] of mapFor(name)) {
            if (key.startsWith(keyPrefix)) out.push(value as T);
          }
          return out;
        },
    };
  }

  return {
    durability: "EPHEMERAL_SINGLE_INSTANCE",
    description: "in-process memory (demo only; lost on cold start)",
    collection,
    versioned<T extends GuardVersionedRecord>(name: GuardCollectionName): GuardVersionedCollection<T> {
      return {
        ...collection<T>(name),
        async compareAndSet(key, expectedVersion, next) {
          /* Same guarantee as `insertIfAbsent` and for the same reason: this
             body runs to completion with no await inside it, so no other task
             can observe or write between the check and the write. */
          const map = mapFor(name);
          const current = map.get(key) as T | undefined;
          if (expectedVersion === null) {
            if (current !== undefined) return false;
          } else if (current === undefined || current.version !== expectedVersion) {
            return false;
          }
          map.set(key, next);
          return true;
        },
      };
    },
    async compareAndSetMany(writes) {
      const ordered = normalizeAtomicWrites(writes);
      for (const write of ordered) {
        const current = mapFor(write.collection).get(write.key) as GuardVersionedRecord | undefined;
        if (!atomicExpectationMatches(current, write.expectedVersion)) return false;
      }
      /* No await occurs between validation and mutation, so another task in
         this process cannot observe a partial batch. */
      for (const write of ordered) mapFor(write.collection).set(write.key, write.next);
      return true;
    },
  };
}

function normalizeAtomicWrites(
  writes: readonly GuardAtomicVersionedWrite[],
): readonly GuardAtomicVersionedWrite[] {
  if (writes.length === 0) throw new TypeError("An atomic Guard write batch cannot be empty.");
  const ordered = [...writes].sort((left, right) =>
    compareCanonicalStrings(`${left.collection}:${left.key}`, `${right.collection}:${right.key}`),
  );
  const identities = new Set(ordered.map((write) => `${write.collection}\u0000${write.key}`));
  if (identities.size !== ordered.length) {
    throw new TypeError("An atomic Guard write batch cannot target the same record twice.");
  }
  return ordered;
}

function atomicExpectationMatches(
  current: GuardVersionedRecord | undefined,
  expectedVersion: number | null,
): boolean {
  return expectedVersion === null
    ? current === undefined
    : current !== undefined && current.version === expectedVersion;
}

function readCollectionFile(file: string): Map<string, unknown> {
  try {
    const parsed: unknown = JSON.parse(readFileSync(file, "utf8"));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new TypeError(`Invalid Guard collection state in ${file}.`);
    }
    return new Map(Object.entries(parsed as Record<string, unknown>));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return new Map();
    throw new Error(`Guard collection is corrupt or unreadable: ${file}.`, { cause: error });
  }
}

function writeCollectionFile(directory: string, file: string, map: Map<string, unknown>): void {
  /* The directory is created at construction, but a long-lived process can
     outlive it: a cleanup, a container restart with an unmounted volume, or an
     operator clearing state by hand. Without this, every later write throws
     ENOENT and the lifecycle fails permanently behind a generic 503 with no
     hint of the cause. Re-asserting the directory is cheap and idempotent. */
  mkdirSync(directory, { recursive: true });
  const temporary = `${file}.tmp`;
  writeFileSync(temporary, JSON.stringify(Object.fromEntries(map), null, 0), "utf8");
  renameSync(temporary, file);
}

/**
 * JSON-file adapter for a local or single-writer deployment.
 *
 * Every write is a whole-collection atomic replace (temp file + rename), which
 * is correct at prototype volume and keeps a torn file from ever being read.
 * It is explicitly NOT multi-writer safe: two instances writing the same
 * directory would clobber each other, which is why it declares
 * `DURABLE_SINGLE_WRITER` and the runtime blocks it on multi-instance targets.
 */
export function createFileGuardStore(options: { directory: string }): GuardStore {
  mkdirSync(options.directory, { recursive: true });
  const loaded = new Map<GuardCollectionName, Map<string, unknown>>();
  const transactionFile = join(options.directory, ".guard-atomic-transaction.json");

  function recoverAtomicTransaction(): void {
    if (!existsSync(transactionFile)) return;
    const parsed: unknown = JSON.parse(readFileSync(transactionFile, "utf8"));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new TypeError(`Invalid Guard atomic transaction state in ${transactionFile}.`);
    }
    for (const [name, value] of Object.entries(parsed as Record<string, unknown>)) {
      if (!GUARD_COLLECTIONS.includes(name as GuardCollectionName)) {
        throw new TypeError(`Unknown Guard collection in ${transactionFile}.`);
      }
      if (!value || typeof value !== "object" || Array.isArray(value)) {
        throw new TypeError(`Invalid Guard collection snapshot in ${transactionFile}.`);
      }
      const collectionName = name as GuardCollectionName;
      const next = new Map(Object.entries(value as Record<string, unknown>));
      writeCollectionFile(options.directory, join(options.directory, `${collectionName}.json`), next);
      loaded.set(collectionName, next);
    }
    unlinkSync(transactionFile);
  }

  recoverAtomicTransaction();

  function snapshot(name: GuardCollectionName): Map<string, unknown> {
    recoverAtomicTransaction();
    let map = loaded.get(name);
    if (!map) {
      map = readCollectionFile(join(options.directory, `${name}.json`));
      loaded.set(name, map);
    }
    return map;
  }

  function collection<T>(name: GuardCollectionName): GuardCollection<T> {
    const file = join(options.directory, `${name}.json`);
    return {
        async get(key) {
          return snapshot(name).get(key) as T | undefined;
        },
        async set(key, value) {
          const next = new Map(snapshot(name));
          next.set(key, value);
          writeCollectionFile(options.directory, file, next);
          loaded.set(name, next);
        },
        async insertIfAbsent(key, value) {
          /* Atomic against this process only, which is precisely what
             DURABLE_SINGLE_WRITER promises and no more. */
          const current = snapshot(name);
          if (current.has(key)) return false;
          const next = new Map(current);
          next.set(key, value);
          writeCollectionFile(options.directory, file, next);
          loaded.set(name, next);
          return true;
        },
        async insertAllIfAbsent(entries) {
          const ordered = [...entries].sort((left, right) =>
            compareCanonicalStrings(left.key, right.key),
          );
          const keys = new Set(ordered.map((entry) => entry.key));
          if (keys.size !== ordered.length) {
            throw new TypeError("Guard batch claims require unique keys.");
          }
          const current = snapshot(name);
          if (ordered.some((entry) => current.has(entry.key))) return false;
          const next = new Map(current);
          for (const entry of ordered) next.set(entry.key, entry.value);
          /* One collection map becomes one temp-file rename, so no caller or
             cold-start reader can observe only half of this batch. */
          writeCollectionFile(options.directory, file, next);
          loaded.set(name, next);
          return true;
        },
        async delete(key) {
          const current = snapshot(name);
          if (!current.has(key)) return;
          const next = new Map(current);
          next.delete(key);
          writeCollectionFile(options.directory, file, next);
          loaded.set(name, next);
        },
        async has(key) {
          return snapshot(name).has(key);
        },
        async valuesWithPrefix(keyPrefix) {
          const out: T[] = [];
          for (const [entryKey, value] of snapshot(name)) {
            if (entryKey.startsWith(keyPrefix)) out.push(value as T);
          }
          return out;
        },
    };
  }

  return {
    durability: "DURABLE_SINGLE_WRITER",
    description: `JSON files under ${options.directory} (single writer)`,
    collection,
    versioned<T extends GuardVersionedRecord>(name: GuardCollectionName): GuardVersionedCollection<T> {
      const file = join(options.directory, `${name}.json`);
      return {
        ...collection<T>(name),
        async compareAndSet(key, expectedVersion, next) {
          const current = snapshot(name);
          const stored = current.get(key) as T | undefined;
          if (expectedVersion === null) {
            if (stored !== undefined) return false;
          } else if (stored === undefined || stored.version !== expectedVersion) {
            return false;
          }
          const updated = new Map(current);
          updated.set(key, next);
          /* One temp-file rename, so a cold-start reader never sees a
             half-applied transition — the same guarantee the other writes make,
             and the reason a reservation's history survives a restart. */
          writeCollectionFile(options.directory, file, updated);
          loaded.set(name, updated);
          return true;
        },
      };
    },
    async compareAndSetMany(writes) {
      const ordered = normalizeAtomicWrites(writes);
      for (const write of ordered) {
        const current = snapshot(write.collection).get(write.key) as GuardVersionedRecord | undefined;
        if (!atomicExpectationMatches(current, write.expectedVersion)) return false;
      }

      const nextByCollection = new Map<GuardCollectionName, Map<string, unknown>>();
      for (const write of ordered) {
        let next = nextByCollection.get(write.collection);
        if (!next) {
          next = new Map(snapshot(write.collection));
          nextByCollection.set(write.collection, next);
        }
        next.set(write.key, write.next);
      }

      /* The journal is the crash-recovery commit record. A cold start that
         encounters it deterministically replays every collection snapshot
         before serving a read, so a process exit between file renames cannot
         expose half of an authorization boundary. */
      writeFileSync(
        `${transactionFile}.tmp`,
        JSON.stringify(Object.fromEntries(
          [...nextByCollection].map(([name, map]) => [name, Object.fromEntries(map)]),
        )),
        "utf8",
      );
      renameSync(`${transactionFile}.tmp`, transactionFile);
      recoverAtomicTransaction();
      return true;
    },
  };
}
