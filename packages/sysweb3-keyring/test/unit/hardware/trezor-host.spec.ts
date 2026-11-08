import { TrezorKeyring } from '../../../src/trezor';
import { createTrezorConnection } from '../../../src/trezor/connect';
import {
  TREZOR_METHODS,
  type TrezorHost,
} from '../../../src/trezor/host-types';

jest.unmock('../../../src/trezor/connect');

const host = (model: string): TrezorHost =>
  ({
    ...Object.fromEntries(
      TREZOR_METHODS.map((method) => [
        method,
        jest.fn(async () => ({ success: true, payload: { model } })),
      ])
    ),
    init: jest.fn(async () => undefined),
    dispose: jest.fn(async (pending) => {
      await Promise.allSettled(pending);
    }),
  } as TrezorHost);

it('requires an explicit complete host', () => {
  expect(() => createTrezorConnection(undefined as any)).toThrow(
    'explicit host capabilities'
  );
  expect(() => createTrezorConnection({ init: jest.fn() } as any)).toThrow(
    'explicit host capabilities'
  );
});

it('uses a non-browser host without importing a platform implementation', async () => {
  const browser = Object.getOwnPropertyDescriptor(globalThis, 'chrome');
  delete (globalThis as any).chrome;
  const native = host('native');
  const connection = createTrezorConnection(native);
  try {
    await connection.init();
    await expect(connection.getFeatures()).resolves.toMatchObject({
      success: true,
      payload: { model: 'native' },
    });
    expect(native.init).toHaveBeenCalledTimes(1);
  } finally {
    await connection.dispose();
    if (browser) Object.defineProperty(globalThis, 'chrome', browser);
  }
});

it('isolates listeners, pending calls, and disposal between hosts', async () => {
  const firstHost = host('first');
  const secondHost = host('second');
  const first = createTrezorConnection(firstHost);
  const second = createTrezorConnection(secondHost);
  await first.init();
  await second.init();
  const firstEvents = jest.fn();
  const secondEvents = jest.fn();
  first.subscribe(firstEvents);
  second.subscribe(secondEvents);
  let release!: (value: any) => void;
  jest.spyOn(firstHost, 'getFeatures').mockImplementationOnce(
    () =>
      new Promise((resolve) => {
        release = resolve;
      })
  );
  const pending = first.getFeatures();
  const cancelled = expect(pending).rejects.toMatchObject({
    code: 'Method_Interrupted',
  });
  await new Promise(setImmediate);
  await first.dispose();
  await cancelled;
  await expect(second.getFeatures()).resolves.toMatchObject({
    payload: { model: 'second' },
  });
  expect(secondHost.dispose).not.toHaveBeenCalled();
  expect(secondEvents).not.toHaveBeenCalledWith({ type: 'disconnected' });
  release({ success: true, payload: { model: 'late' } });
  await new Promise(setImmediate);
  expect(firstEvents).not.toHaveBeenCalledWith({
    type: 'model',
    model: 'late',
  });
  expect(secondEvents).toHaveBeenCalledWith({ type: 'model', model: 'second' });
  await second.dispose();
});

it('fails closed when host cleanup rejects', async () => {
  const native = host('native');
  jest
    .spyOn(native, 'dispose')
    .mockRejectedValueOnce(new Error('Cleanup failed'));
  const connection = createTrezorConnection(native);
  await connection.init();
  await expect(connection.dispose()).rejects.toThrow('Cleanup failed');
  await expect(connection.getFeatures()).rejects.toMatchObject({
    code: 'Init_NotInitialized',
  });
  await expect(connection.init()).rejects.toThrow('Cleanup failed');
  const replacement = createTrezorConnection(native);
  await expect(replacement.init()).rejects.toMatchObject({
    code: 'HARDWARE_SIGNER_BUSY',
  });
  await connection.dispose();
  await replacement.init();
  await replacement.dispose();
});

it('leases a shared host to one connection and releases it for later reuse', async () => {
  const shared = host('shared');
  const first = createTrezorConnection(shared);
  const second = createTrezorConnection(shared);
  await first.init();
  await expect(second.init()).rejects.toMatchObject({
    code: 'HARDWARE_SIGNER_BUSY',
  });
  await second.dispose();
  expect(shared.dispose).not.toHaveBeenCalled();
  await expect(first.getFeatures()).resolves.toMatchObject({ success: true });
  await first.dispose();
  await second.init();
  await expect(first.init()).rejects.toMatchObject({
    code: 'HARDWARE_SIGNER_BUSY',
  });
  await second.dispose();
  await first.init();
  await first.dispose();
});

it('retains the lease until rejected initialization has been cleaned up', async () => {
  const shared = host('shared');
  jest
    .spyOn(shared, 'init')
    .mockRejectedValueOnce(new Error('Initialization failed'));
  const first = createTrezorConnection(shared);
  const second = createTrezorConnection(shared);
  await expect(first.init()).rejects.toThrow('Initialization failed');
  await expect(second.init()).rejects.toMatchObject({
    code: 'HARDWARE_SIGNER_BUSY',
  });
  await first.dispose();
  await second.init();
  await second.dispose();
});

it('does not release a host while its cleanup is pending', async () => {
  const shared = host('shared');
  let finish!: () => void;
  jest.spyOn(shared, 'dispose').mockImplementationOnce(
    () =>
      new Promise<void>((resolve) => {
        finish = resolve;
      })
  );
  const first = createTrezorConnection(shared);
  const second = createTrezorConnection(shared);
  await first.init();
  const cleanup = first.dispose();
  await new Promise(setImmediate);
  await expect(second.init()).rejects.toMatchObject({
    code: 'HARDWARE_SIGNER_BUSY',
  });
  finish();
  await cleanup;
  await second.init();
  await second.dispose();
});

it('releases a lease when disposal overtakes initialization before host I/O', async () => {
  const shared = host('shared');
  const first = createTrezorConnection(shared);
  const second = createTrezorConnection(shared);
  const initialization = first.init();
  const cancelled = expect(initialization).rejects.toMatchObject({
    code: 'Method_Interrupted',
  });
  await first.dispose();
  await cancelled;
  expect(shared.init).not.toHaveBeenCalled();
  await second.init();
  await second.dispose();
});

it('rejects concurrent initialization without invalidating the active attempt', async () => {
  const shared = host('shared');
  let finish!: () => void;
  jest.spyOn(shared, 'init').mockImplementationOnce(
    () =>
      new Promise<void>((resolve) => {
        finish = resolve;
      })
  );
  const connection = createTrezorConnection(shared);
  const initialization = connection.init();
  await new Promise(setImmediate);
  await expect(connection.init()).rejects.toMatchObject({
    code: 'HARDWARE_SIGNER_BUSY',
  });
  expect(shared.init).toHaveBeenCalledTimes(1);
  finish();
  await initialization;
  await expect(connection.getFeatures()).resolves.toMatchObject({
    success: true,
  });
  await connection.dispose();
  await connection.init();
  expect(shared.init).toHaveBeenCalledTimes(2);
  await connection.dispose();
});

it('allows a rebuilt keyring to claim the host after the old keyring is destroyed', async () => {
  const shared = host('shared');
  const first = new TrezorKeyring(createTrezorConnection(shared));
  const second = new TrezorKeyring(createTrezorConnection(shared));
  try {
    await expect(first.init()).resolves.toBe(true);
    await expect(second.init()).rejects.toMatchObject({
      code: 'HARDWARE_SIGNER_BUSY',
    });
    await first.destroy();
    await expect(second.init()).resolves.toBe(true);
    await second.destroy();
    await expect(first.init()).resolves.toBe(true);
  } finally {
    await first.destroy();
    await second.destroy();
  }
});

it('revokes the initialization guard before deferred host preparation reaches the device', async () => {
  const shared = host('shared');
  const prompt = jest.fn();
  let release!: () => void;
  const preparation = new Promise<void>((resolve) => {
    release = resolve;
  });
  jest.spyOn(shared, 'init').mockImplementationOnce(async (assertCurrent) => {
    await preparation;
    assertCurrent();
    prompt();
  });
  const connection = createTrezorConnection(shared);
  const initialization = connection.init();
  const cancelled = expect(initialization).rejects.toMatchObject({
    code: 'Method_Interrupted',
  });
  await new Promise(setImmediate);
  await connection.dispose();
  await cancelled;
  release();
  await new Promise(setImmediate);
  expect(prompt).not.toHaveBeenCalled();
  await connection.init();
  await connection.dispose();
});

it('reserves cleanup before a status observer can reinitialize', async () => {
  const shared = host('shared');
  const connection = createTrezorConnection(shared);
  await connection.init();
  let attempt!: Promise<unknown>;
  const stop = connection.subscribe(() => {
    attempt = connection.init().catch((error) => error);
  });
  await connection.dispose();
  expect(await attempt).toMatchObject({ code: 'HARDWARE_SIGNER_BUSY' });
  expect(shared.init).toHaveBeenCalledTimes(1);
  stop();
  await connection.init();
  await connection.dispose();
});

it('shares the reserved cleanup promise with a reentrant disposer', async () => {
  const shared = host('shared');
  const connection = createTrezorConnection(shared);
  await connection.init();
  let nested: Promise<void> | undefined;
  const stop = connection.subscribe(() => {
    nested = connection.dispose();
  });
  const cleanup = connection.dispose();
  expect(nested).toBe(cleanup);
  await cleanup;
  expect(shared.dispose).toHaveBeenCalledTimes(1);
  stop();
});

it('does not absorb disposal by an observer into a new initialization generation', async () => {
  const shared = host('shared');
  const connection = createTrezorConnection(shared);
  let disposed = false;
  const stop = connection.subscribe(() => {
    if (!disposed) {
      disposed = true;
      void connection.dispose();
    }
  });
  await expect(connection.init()).rejects.toMatchObject({
    code: 'Method_Interrupted',
  });
  expect(shared.init).not.toHaveBeenCalled();
  stop();
  await connection.init();
  await connection.dispose();
});

it('passes transaction cancellation through an asynchronous host preparation guard', async () => {
  const shared = host('shared');
  let release!: () => void;
  const preparation = new Promise<void>((resolve) => {
    release = resolve;
  });
  const dispatch = jest.fn();
  jest
    .spyOn(shared, 'ethereumSignTransaction')
    .mockImplementationOnce(async (assertCurrent) => {
      await preparation;
      assertCurrent();
      dispatch();
      return { success: true, payload: { v: '1b', r: '01', s: '02' } };
    });
  const connection = createTrezorConnection(shared);
  await connection.init();
  const controller = new AbortController();
  const pending = connection.ethereumSignTransactionOwned(
    { path: "m/44'/60'/0'/0/0", transaction: {} } as any,
    {
      signal: controller.signal,
      assertCurrent: () => undefined,
    }
  );
  const cancelled = expect(pending).rejects.toMatchObject({
    code: 'HARDWARE_REQUEST_CANCELLED',
  });
  await new Promise(setImmediate);
  controller.abort();
  release();
  await cancelled;
  expect(dispatch).not.toHaveBeenCalled();
  await connection.dispose();
});

it('rechecks connection ownership after a hardware guard synchronously disposes it', async () => {
  const shared = host('shared');
  const connection = createTrezorConnection(shared);
  const dispatch = jest.fn();
  let atDispatch = false;
  jest
    .spyOn(shared, 'ethereumSignTransaction')
    .mockImplementationOnce(async (assertCurrent) => {
      atDispatch = true;
      assertCurrent();
      dispatch();
      return { success: true, payload: { v: '1b', r: '01', s: '02' } };
    });
  await connection.init();
  const pending = connection.ethereumSignTransactionOwned(
    { path: "m/44'/60'/0'/0/0", transaction: {} } as any,
    {
      signal: new AbortController().signal,
      assertCurrent() {
        if (atDispatch) void connection.dispose();
      },
    }
  );
  await expect(pending).rejects.toMatchObject({ code: 'Method_Interrupted' });
  expect(dispatch).not.toHaveBeenCalled();
  await new Promise(setImmediate);
  await connection.dispose();
});

it('rejects a successful read when a model observer disposes the connection', async () => {
  const shared = host('shared');
  const connection = createTrezorConnection(shared);
  await connection.init();
  connection.subscribe((event) => {
    if (event.type === 'model') void connection.dispose();
  });
  await expect(connection.getFeatures()).rejects.toMatchObject({
    code: 'Method_Interrupted',
  });
  await connection.dispose();
});

it('rejects a signature when a model observer disposes the connection', async () => {
  const shared = host('shared');
  jest.spyOn(shared, 'ethereumSignTransaction').mockResolvedValueOnce({
    success: true,
    payload: { v: '1b', r: '01', s: '02' },
    device: { features: { model: 'shared' } },
  } as any);
  const connection = createTrezorConnection(shared);
  await connection.init();
  connection.subscribe((event) => {
    if (event.type === 'model') void connection.dispose();
  });
  await expect(
    connection.ethereumSignTransactionOwned(
      { path: "m/44'/60'/0'/0/0", transaction: {} } as any,
      {
        signal: new AbortController().signal,
        assertCurrent: () => undefined,
      }
    )
  ).rejects.toMatchObject({ code: 'Method_Interrupted' });
  await connection.dispose();
});

it('fully retires an outstanding host call before allowing a new owner', async () => {
  const shared = host('shared');
  const connection = createTrezorConnection(shared);
  let release!: (value: any) => void;
  jest.spyOn(shared, 'getFeatures').mockImplementationOnce(
    () =>
      new Promise((resolve) => {
        release = resolve;
      })
  );
  await connection.init();
  const pending = connection.getFeatures();
  const cancelled = expect(pending).rejects.toMatchObject({
    code: 'Method_Interrupted',
  });
  await new Promise(setImmediate);
  let retired = false;
  const retirement = connection.retire().then(() => {
    retired = true;
  });
  await cancelled;
  await new Promise(setImmediate);
  expect(retired).toBe(false);
  const next = createTrezorConnection(shared);
  await expect(next.init()).rejects.toMatchObject({
    code: 'HARDWARE_SIGNER_BUSY',
  });
  release({ success: true, payload: {} });
  await retirement;
  await next.init();
  await next.dispose();
});
