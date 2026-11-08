import { captureHardwareTransactionAuthority } from '../hardware-transaction-authority';
import { TREZOR_METHODS } from './host-types';

import type { HardwareTransactionAuthority } from '../hardware-transaction-authority';
import type { TrezorCalls, TrezorHost, TrezorMethod } from './host-types';

type Client = TrezorCalls;
type TransactionMethod = 'ethereumSignTransaction' | 'signTransaction';
type ForwardedMethod = Exclude<TrezorMethod, TransactionMethod>;
const methods = TREZOR_METHODS.filter(
  (method): method is ForwardedMethod =>
    method !== 'ethereumSignTransaction' && method !== 'signTransaction'
);
type Method = ForwardedMethod | TransactionMethod;
type Compatible<T> = T extends { success: false }
  ? T & { payload: { error: string; code?: string } }
  : T;
type CompatibleCall<FunctionType> = FunctionType extends {
  (...args: infer A): infer R;
  (...args: infer B): infer S;
  (...args: infer C): infer T;
}
  ? {
      (...args: A): Promise<Compatible<Awaited<R>>>;
      (...args: B): Promise<Compatible<Awaited<S>>>;
      (...args: C): Promise<Compatible<Awaited<T>>>;
    }
  : never;
type Calls = { [Name in ForwardedMethod]: CompatibleCall<Client[Name]> };
export type ConnectionEvent =
  | { type: 'disconnected' }
  | { type: 'model'; model: string };
export type TrezorConnection = Calls & {
  ethereumSignTransactionOwned: (
    request: Parameters<Client['ethereumSignTransaction']>[0],
    authority: HardwareTransactionAuthority
  ) => ReturnType<CompatibleCall<Client['ethereumSignTransaction']>>;
  signTransactionOwned: (
    request: Parameters<Client['signTransaction']>[0],
    authority: HardwareTransactionAuthority
  ) => ReturnType<CompatibleCall<Client['signTransaction']>>;
  init: () => Promise<void>;
  dispose: () => Promise<void>;
  retire: () => Promise<() => void>;
  subscribe(listener: (event: ConnectionEvent) => void): () => void;
};
const hostOwners = new WeakMap<TrezorHost, object>();

export function createTrezorConnection(host: TrezorHost): TrezorConnection {
  if (
    !host ||
    typeof host.init !== 'function' ||
    typeof host.dispose !== 'function' ||
    TREZOR_METHODS.some((method) => typeof host[method] !== 'function')
  )
    throw new TypeError('Trezor requires explicit host capabilities');
  const owner = {};
  const releaseHost = () => {
    if (hostOwners.get(host) === owner) hostOwners.delete(host);
  };
  const listeners = new Set<(event: ConnectionEvent) => void>();
  let clientPromise: Promise<TrezorHost> | undefined;
  let generation = 0;
  let initialized = false;
  let initializing = false;
  let cleanupPromise = Promise.resolve();
  let cleanupPending = false;
  const inFlight = new Set<Promise<unknown>>();
  const pending = new Set<(error: Error) => void>();
  const interrupted = () =>
    Object.assign(new Error('Trezor operation cancelled'), {
      code: 'Method_Interrupted',
    });
  const invalidate = () => {
    const invalidated = ++generation;
    initialized = false;
    const error = interrupted();
    for (const reject of pending) reject(error);
    pending.clear();
    emit({ type: 'disconnected' });
    return invalidated;
  };

  const subscribeTrezorEvents = (
    listener: (event: ConnectionEvent) => void
  ): (() => void) => {
    listeners.add(listener);
    return () => listeners.delete(listener);
  };
  const emit = (event: ConnectionEvent) => {
    for (const listener of listeners) {
      try {
        listener(event);
      } catch {
        // Status observers must not turn a completed device call into a retry.
      }
    }
  };

  const getClient = (): Promise<TrezorHost> => {
    clientPromise ??= Promise.resolve(host);
    return clientPromise;
  };

  /** Keep the SDK's established failure payload while preserving Connect 10 codes. */
  const normalize = (response: any, method: Method): any => {
    if (response?.success === false) {
      const error = response.error;
      const code = typeof error?.code === 'string' ? error.code : undefined;
      if (
        code === 'Device_Disconnected' ||
        code === 'Device_NotFound' ||
        code === 'Desktop_ConnectionMissing' ||
        code === 'Transport_Missing'
      ) {
        invalidate();
      }
      return {
        ...response,
        payload: {
          error:
            typeof error?.message === 'string'
              ? error.message
              : 'Trezor request failed',
          code,
        },
      };
    }
    const model =
      response?.device?.features?.model ??
      (method === 'getFeatures' ? response?.payload?.model : undefined);
    if (response?.success === true && typeof model === 'string') {
      emit({ type: 'model', model });
    }
    return response;
  };
  const withClient = async <Result>(
    operation: (
      client: TrezorHost,
      assertCurrent: () => void
    ) => Promise<Result>,
    requireInitialized = true
  ): Promise<Result> => {
    const captured = generation;
    const assertCurrent = () => {
      if (captured !== generation) throw interrupted();
      if (requireInitialized && !initialized) {
        throw Object.assign(new Error('TrezorConnect not initialized'), {
          code: 'Init_NotInitialized',
        });
      }
      if (hostOwners.get(host) !== owner) throw interrupted();
    };
    assertCurrent();
    let rejectPending!: (error: Error) => void;
    const cancelled = new Promise<never>((_resolve, reject) => {
      rejectPending = reject;
    });
    pending.add(rejectPending);
    try {
      const result = await Promise.race([
        (async () => {
          await cleanupPromise;
          assertCurrent();
          const client = await getClient();
          assertCurrent();
          const request = Promise.resolve(operation(client, assertCurrent));
          inFlight.add(request);
          try {
            return await request;
          } finally {
            inFlight.delete(request);
          }
        })(),
        cancelled,
      ]);
      // A late response must not restore a model/status or return a signature.
      assertCurrent();
      return result;
    } finally {
      pending.delete(rejectPending);
    }
  };
  const calls = Object.fromEntries(
    methods.map((method) => [
      method,
      async (...args: any[]) => {
        const captured = generation;
        const response = await withClient((client, assertCurrent) =>
          (client[method] as any)(assertCurrent, ...args)
        );
        if (captured !== generation) throw interrupted();
        const normalized = normalize(response, method);
        if (normalized?.success === true && captured !== generation)
          throw interrupted();
        return normalized;
      },
    ])
  ) as Calls;

  async function signOwned<Result>(
    method: TransactionMethod,
    authority: HardwareTransactionAuthority,
    call: (client: TrezorHost, assertCurrent: () => void) => Promise<Result>
  ) {
    const { assertCurrent } = captureHardwareTransactionAuthority(authority);
    const captured = generation;
    const response = await withClient((client, assertConnectionCurrent) => {
      assertCurrent();
      return call(client, () => {
        assertConnectionCurrent();
        assertCurrent();
        assertConnectionCurrent();
      });
    });
    assertCurrent();
    if (captured !== generation) throw interrupted();
    const normalized = normalize(response, method);
    if (normalized?.success === true) {
      assertCurrent();
      if (captured !== generation) throw interrupted();
    }
    return normalized;
  }

  const TrezorConnect: Omit<TrezorConnection, 'subscribe'> = {
    ...calls,
    ethereumSignTransactionOwned(request, authority) {
      return signOwned(
        'ethereumSignTransaction',
        authority,
        (client, assertCurrent) =>
          client.ethereumSignTransaction(assertCurrent, request)
      );
    },
    signTransactionOwned(request, authority) {
      return signOwned('signTransaction', authority, (client, assertCurrent) =>
        client.signTransaction(assertCurrent, request)
      );
    },
    async init(): Promise<void> {
      if (cleanupPending || initializing) {
        throw Object.assign(
          new Error('Previous Trezor request is still pending'),
          {
            code: 'HARDWARE_SIGNER_BUSY',
          }
        );
      }
      const activeOwner = hostOwners.get(host);
      if (activeOwner && activeOwner !== owner)
        throw Object.assign(
          new Error('Trezor host is owned by another connection'),
          {
            code: 'HARDWARE_SIGNER_BUSY',
          }
        );
      hostOwners.set(host, owner);
      initializing = true;
      const captured = invalidate();
      try {
        if (captured !== generation) throw interrupted();
        await withClient(
          (client, assertCurrent) => client.init(assertCurrent),
          false
        );
        if (captured !== generation) throw interrupted();
        initialized = true;
      } finally {
        initializing = false;
      }
    },
    dispose(): Promise<void> {
      if (cleanupPending) {
        return inFlight.size ? Promise.resolve() : cleanupPromise;
      }
      const loaded = clientPromise;
      // Reserve cleanup before notifying observers, which may reenter init.
      cleanupPending = true;
      if (!loaded) {
        releaseHost();
        invalidate();
        cleanupPending = false;
        return Promise.resolve();
      }
      const outstanding = [...inFlight];
      cleanupPromise = cleanupPromise
        .catch(() => undefined)
        .then(async () => {
          const client = await loaded;
          if (hostOwners.get(host) !== owner) return;
          await client.dispose(outstanding);
          releaseHost();
        })
        .finally(() => {
          cleanupPending = false;
        });
      // Deferred cleanup may outlive the caller; preserve its failure for future
      // init while preventing an unhandled rejection when the host is locking.
      void cleanupPromise.catch(() => undefined);
      // Suite Web's upstream dispose is a no-op; local invalidation is required.
      invalidate();
      return outstanding.length ? Promise.resolve() : cleanupPromise;
    },
    async retire(): Promise<() => void> {
      const disposal = TrezorConnect.dispose();
      const captured = generation;
      await (cleanupPending ? cleanupPromise : disposal);
      const assertRetired = () => {
        if (
          captured !== generation ||
          initialized ||
          initializing ||
          cleanupPending ||
          hostOwners.has(host)
        )
          throw interrupted();
      };
      assertRetired();
      return assertRetired;
    },
  };

  return { ...TrezorConnect, subscribe: subscribeTrezorEvents };
}

export const trezorResponseError = (
  response: { payload?: { error?: string; code?: string } },
  prefix = ''
): Error =>
  Object.assign(
    new Error(prefix + (response.payload?.error || 'Trezor request failed')),
    { code: response.payload?.code }
  );
