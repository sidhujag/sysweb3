import * as syscoinjs from 'syscoinjs-lib';

/**
 * In-flight deduplication for Blockbook xpub account fetches used internally
 * by the keyring (address-index discovery and PSBT path enrichment, both
 * `tokens=used&details=tokens`).
 *
 * During a send flow several callers (fee estimation, PSBT creation, signing)
 * can request the same account data concurrently; collapsing them into a
 * single request removes redundant Blockbook round trips.
 *
 * Deliberately NOT a TTL cache: address/pubkey/path derivation must always
 * see fresh indexes, so once a request settles the next caller refetches.
 */

interface ICacheEntry {
  promise: Promise<any>;
}

const inflightFetches = new Map<string, ICacheEntry>();

const buildKey = (backendUrl: string, xpub: string, options: string) =>
  `${backendUrl}::${xpub}::${options}`;

export const fetchBackendAccountCached = (
  backendUrl: string,
  xpub: string,
  options: string
): Promise<any> => {
  const key = buildKey(backendUrl, xpub, options);

  const inflight = inflightFetches.get(key);
  if (inflight) {
    return inflight.promise;
  }

  const promise = Promise.resolve(
    (syscoinjs.utils as any).fetchBackendAccount(
      backendUrl,
      xpub,
      options,
      true
    )
  );

  inflightFetches.set(key, { promise });

  // Drop the entry as soon as the request settles so subsequent
  // callers always fetch fresh data
  const dropEntry = () => {
    const entry = inflightFetches.get(key);
    if (entry && entry.promise === promise) {
      inflightFetches.delete(key);
    }
  };
  promise.then(dropEntry, dropEntry);

  return promise;
};

/**
 * Drop in-flight account fetches. Without arguments clears everything;
 * with an xpub only that account's entries are dropped (any backend).
 */
export const invalidateBlockbookAccountCache = (xpub?: string) => {
  if (!xpub) {
    inflightFetches.clear();
    return;
  }
  for (const key of Array.from(inflightFetches.keys())) {
    if (key.includes(`::${xpub}::`)) {
      inflightFetches.delete(key);
    }
  }
};
