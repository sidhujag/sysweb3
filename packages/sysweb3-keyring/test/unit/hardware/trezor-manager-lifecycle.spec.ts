/* eslint-disable camelcase */
import ConnectMock from '@trezor/connect-webextension';

import type { HardwareWalletManager } from '../../../src/hardware-wallet-manager';
import type { LedgerHost } from '../../../src/ledger/host-types';
import type { TrezorKeyring } from '../../../src/trezor';

jest.unmock('../../../src/trezor/connect');

type Adapter = typeof import('../../../src/trezor/connect');
let adapter: Adapter;
let Manager: typeof HardwareWalletManager;
let Keyring: typeof TrezorKeyring;
let managers: HardwareWalletManager[];
let keyrings: TrezorKeyring[];
let releaseHeld: (() => void)[];
const chromeDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'chrome');
const tick = () => new Promise<void>((resolve) => setImmediate(resolve));
const held = () => {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => (resolve = done));
  releaseHeld.push(resolve);
  return { promise, resolve };
};
const waitFor = async (condition: () => boolean) => {
  for (let count = 0; count < 30 && !condition(); count++) await tick();
  expect(condition()).toBe(true);
};
const manager = (host?: LedgerHost) => {
  const value = new Manager(host);
  managers.push(value);
  return value;
};
const status = (value: HardwareWalletManager) =>
  value.getStatus().find((entry) => entry.type === 'trezor')!;
const evmRequest = {
  index: '0',
  coin: 'eth',
  slip44: 60,
  tx: {
    to: `0x${'11'.repeat(20)}`,
    chainId: 1,
    nonce: '0x0',
    gasPrice: '0x2',
    gasLimit: '0x5208',
    value: '0x1',
    data: '0x',
  },
};
const vendorSigner = () => {
  const device = jest.fn().mockResolvedValue({
    success: true,
    payload: { r: '0x01', s: '0x02', v: '0x1b' },
  });
  Object.defineProperty(ConnectMock, 'ethereumSignTransaction', {
    configurable: true,
    value: device,
  });
  releaseHeld.push(() => {
    Reflect.deleteProperty(ConnectMock, 'ethereumSignTransaction');
  });
  return device;
};

beforeEach(() => {
  jest.restoreAllMocks();
  jest.clearAllMocks();
  managers = [];
  keyrings = [];
  releaseHeld = [];
  (globalThis as any).chrome = {
    runtime: {
      id: 'synthetic-test-extension',
      getManifest: () => ({ manifest_version: 3 }),
      onConnect: { addListener: jest.fn() },
      onMessageExternal: { addListener: jest.fn() },
    },
    tabs: { get: jest.fn(), create: jest.fn(), update: jest.fn() },
    windows: { getCurrent: jest.fn() },
  };
  jest.isolateModules(() => {
    adapter = jest.requireActual('../../../src/trezor/connect');
    Manager = jest.requireActual(
      '../../../src/hardware-wallet-manager'
    ).HardwareWalletManager;
    Keyring = jest.requireActual('../../../src/trezor').TrezorKeyring;
  });
});

afterEach(async () => {
  for (const release of releaseHeld) release();
  await tick();
  for (const value of keyrings) await value.destroy();
  for (const value of managers) await value.destroy();
  jest.useRealTimers();
  if (chromeDescriptor)
    Object.defineProperty(globalThis, 'chrome', chromeDescriptor);
  else delete (globalThis as any).chrome;
});

it('keeps initialization ownership while a second caller waits and returns false', async () => {
  const initialization = held();
  jest.spyOn(ConnectMock, 'init').mockReturnValueOnce(initialization.promise);
  const value = manager();
  const first = value.initializeTrezor();
  await waitFor(() => (ConnectMock.init as jest.Mock).mock.calls.length === 1);
  expect(status(value).status).toBe('connecting');
  const delayed = held();
  const delay = jest
    .spyOn(value as any, 'delay')
    .mockReturnValueOnce(delayed.promise);
  const second = value.initializeTrezor();
  expect(delay).toHaveBeenCalledWith(1000);
  delayed.resolve();
  await expect(second).resolves.toBe(false);
  expect(ConnectMock.init).toHaveBeenCalledTimes(1);
  expect(ConnectMock.dispose).not.toHaveBeenCalled();
  initialization.resolve();
  await expect(first).resolves.toBe(true);
  expect(status(value).connected).toBe(true);
});

it('returns true to a waiting caller once the original initialization succeeds', async () => {
  const initialization = held();
  jest.spyOn(ConnectMock, 'init').mockReturnValueOnce(initialization.promise);
  const value = manager();
  const first = value.initializeTrezor();
  await waitFor(() => (ConnectMock.init as jest.Mock).mock.calls.length === 1);
  const delayed = held();
  jest.spyOn(value as any, 'delay').mockReturnValueOnce(delayed.promise);
  const second = value.initializeTrezor();
  initialization.resolve();
  await expect(first).resolves.toBe(true);
  delayed.resolve();
  await expect(second).resolves.toBe(true);
  expect(ConnectMock.init).toHaveBeenCalledTimes(1);
});

it('locks during held initialization without waiting for or reviving its raw result', async () => {
  const initialization = held();
  jest.spyOn(ConnectMock, 'init').mockReturnValueOnce(initialization.promise);
  const value = manager();
  const connected = jest.fn();
  value.on('connected', connected);
  const first = value.initializeTrezor();
  await waitFor(() => (ConnectMock.init as jest.Mock).mock.calls.length === 1);
  await value.destroy();
  await expect(first).resolves.toBe(false);
  expect(status(value).connected).toBe(false);
  expect(connected).not.toHaveBeenCalled();
  await expect(value.initializeTrezor()).rejects.toMatchObject({
    code: 'HARDWARE_SIGNER_BUSY',
  });
  initialization.resolve();
  await tick();
  await expect(value.initializeTrezor()).resolves.toBe(true);
  expect(ConnectMock.init).toHaveBeenCalledTimes(2);
  expect(status(value).connected).toBe(true);
});

it('does not retry or clean up a newer connection after destruction during backoff', async () => {
  jest.spyOn(ConnectMock, 'init').mockRejectedValueOnce(new Error('temporary'));
  const value = manager();
  const backoff = held();
  const delay = jest
    .spyOn(value as any, 'delay')
    .mockReturnValueOnce(backoff.promise);
  const first = value.initializeTrezor();
  await waitFor(() => delay.mock.calls.length === 1);
  await value.destroy();
  await expect(value.initializeTrezor()).resolves.toBe(true);
  const disposals = (ConnectMock.dispose as jest.Mock).mock.calls.length;
  backoff.resolve();
  await expect(first).resolves.toBe(false);
  expect(ConnectMock.init).toHaveBeenCalledTimes(2);
  expect(ConnectMock.dispose).toHaveBeenCalledTimes(disposals);
  expect(status(value).connected).toBe(true);
});

it('blocks initialization while cleanup is active and shares destruction completion', async () => {
  const value = manager();
  await expect(value.initializeTrezor()).resolves.toBe(true);
  const cleanup = held();
  jest.spyOn(ConnectMock, 'dispose').mockReturnValueOnce(cleanup.promise);
  const destruction = value.destroy();
  expect(value.destroy()).toBe(destruction);
  await expect(value.initializeTrezor()).rejects.toMatchObject({
    code: 'Method_Interrupted',
  });
  expect(status(value).connected).toBe(false);
  cleanup.resolve();
  await destruction;
  await expect(value.initializeTrezor()).resolves.toBe(true);
});

it('does not delete a replacement pool entry when old cleanup finishes', async () => {
  const value = manager();
  await expect(value.initializeTrezor()).resolves.toBe(true);
  const cleanup = held();
  jest.spyOn(ConnectMock, 'dispose').mockReturnValueOnce(cleanup.promise);
  const internal = value as any;
  const closing = internal.closeConnection('trezor-default');
  await waitFor(
    () => (ConnectMock.dispose as jest.Mock).mock.calls.length === 1
  );
  const replacement = {
    status: 'connected',
    lastActivity: Date.now(),
    retryCount: 0,
  };
  internal.connectionPool.set('trezor-default', replacement);
  cleanup.resolve();
  await closing;
  expect(internal.connectionPool.get('trezor-default')).toBe(replacement);
});

it('does not publish an old monitor snapshot after destruction begins', async () => {
  const cleanup = held();
  const close = jest.fn(() => cleanup.promise);
  const value = manager({
    disconnect: close,
    getStatus: () => ({ connected: true }),
  } as unknown as LedgerHost);
  await value.initializeTrezor();
  (value as any).connectionPool.set('ledger-default', {
    status: 'connected',
    lastActivity: 0,
    retryCount: 0,
  });
  const observer = jest.fn();
  value.on('statusUpdate', observer);
  const checking = (value as any).checkAllConnections();
  await waitFor(() => close.mock.calls.length === 1);
  const destruction = value.destroy();
  cleanup.resolve();
  await Promise.all([checking, destruction]);
  expect(observer).not.toHaveBeenCalled();
});

it('still invalidates a genuine adapter cancellation during initialization', async () => {
  const initialization = held();
  jest.spyOn(ConnectMock, 'init').mockReturnValueOnce(initialization.promise);
  const value = manager();
  const first = value.initializeTrezor();
  await waitFor(() => (ConnectMock.init as jest.Mock).mock.calls.length === 1);
  await adapter.default.dispose();
  await expect(first).resolves.toBe(false);
  expect(status(value).connected).toBe(false);
  initialization.resolve();
});

it('does not let an old waiting caller borrow a post-lock connection', async () => {
  const initialization = held();
  jest.spyOn(ConnectMock, 'init').mockReturnValueOnce(initialization.promise);
  const value = manager();
  const first = value.initializeTrezor();
  await waitFor(() => (ConnectMock.init as jest.Mock).mock.calls.length === 1);
  const delayed = held();
  jest.spyOn(value as any, 'delay').mockReturnValueOnce(delayed.promise);
  const second = value.initializeTrezor();
  await value.destroy();
  await expect(first).resolves.toBe(false);
  initialization.resolve();
  await tick();
  await expect(value.initializeTrezor()).resolves.toBe(true);
  delayed.resolve();
  await expect(second).resolves.toBe(false);
  expect(status(value).connected).toBe(true);
});

it('does not return initialization success when a connected observer destroys it', async () => {
  const value = manager();
  value.on('connected', () => {
    void value.destroy();
  });
  await expect(value.initializeTrezor()).resolves.toBe(false);
  await value.destroy();
  expect(status(value).connected).toBe(false);
});

it('revokes a queued Trezor reply synchronously before waiting for Ledger cleanup', async () => {
  const ledger = held();
  const value = manager({
    disconnect: () => ledger.promise,
    getStatus: () => ({ connected: true }),
  } as unknown as LedgerHost);
  (value as any).connectionPool.set('ledger-default', {
    status: 'connected',
    lastActivity: Date.now(),
    retryCount: 0,
  });
  await expect(value.initializeTrezor()).resolves.toBe(true);
  let reply!: (response: any) => void;
  jest.spyOn(ConnectMock, 'getAccountInfo').mockImplementationOnce(
    () =>
      new Promise((resolve) => {
        reply = resolve;
      }) as any
  );
  const request = adapter.default.getAccountInfo({
    coin: 'sys',
    path: "m/84'/57'/0'",
  });
  const rejected = expect(request).rejects.toMatchObject({
    code: 'Method_Interrupted',
  });
  await waitFor(() => !!reply);
  const observer = jest.fn();
  adapter.subscribeTrezorEvents(observer);
  // Queue the raw success first, but do not yield before destroying the owner.
  reply({
    success: true,
    payload: { descriptor: 'late' },
    device: { features: { model: 'LATE' } },
  });
  const destruction = value.destroy();
  expect(observer).toHaveBeenCalledWith({ type: 'disconnected' });
  await rejected;
  expect(observer).not.toHaveBeenCalledWith({ type: 'model', model: 'LATE' });
  let destroyed = false;
  void destruction.then(() => {
    destroyed = true;
  });
  await tick();
  expect(destroyed).toBe(false);
  ledger.resolve();
  await destruction;
});

it('reattaches exactly one keyring status callback after each lock and reconnect', async () => {
  const value = new Keyring();
  keyrings.push(value);
  const internal = value as any;
  const hardware: HardwareWalletManager = internal.hardwareWalletManager;
  for (let cycle = 0; cycle < 3; cycle++) {
    await expect(value.init()).resolves.toBe(true);
    await expect(value.init()).resolves.toBe(true);
    expect(hardware.listenerCount('connected')).toBe(1);
    expect(hardware.listenerCount('disconnected')).toBe(1);
    expect(internal.initialized).toBe(true);
    const previousCalls = (ConnectMock.init as jest.Mock).mock.calls.length;
    await adapter.default.dispose();
    expect(internal.initialized).toBe(false);
    await value.getAccountInfo({ coin: 'sys', slip44: 57 });
    expect(ConnectMock.init).toHaveBeenCalledTimes(previousCalls + 1);
    expect(hardware.listenerCount('connected')).toBe(1);
    expect(hardware.listenerCount('disconnected')).toBe(1);
    await value.destroy();
    expect(hardware.listenerCount('connected')).toBe(0);
    expect(hardware.listenerCount('disconnected')).toBe(0);
  }
});

it('does not start a keyring initialization after lock overtakes its startup delay', async () => {
  jest.useFakeTimers({ doNotFake: ['setImmediate'] });
  const value = new Keyring();
  keyrings.push(value);
  const initialization = value.init();
  await value.destroy();
  await jest.advanceTimersByTimeAsync(100);
  await expect(initialization).resolves.toBe(false);
  expect(ConnectMock.init).not.toHaveBeenCalled();
  expect((value as any).initialized).toBe(false);
  const reconnect = value.init();
  await jest.advanceTimersByTimeAsync(100);
  await expect(reconnect).resolves.toBe(true);
});

it('does not open the vendor signer when the review retires during the Trezor popup delay', async () => {
  jest.useFakeTimers({ doNotFake: ['setImmediate'] });
  const value = new Keyring();
  keyrings.push(value);
  const initialization = value.init();
  await jest.advanceTimersByTimeAsync(100);
  await expect(initialization).resolves.toBe(true);
  const device = vendorSigner();
  const cancellation = new AbortController();
  const pending = value.signEthTransaction(evmRequest, {
    signal: cancellation.signal,
    assertCurrent: () => undefined,
  });
  const outcome = pending.catch((error) => error);
  cancellation.abort();
  await jest.advanceTimersByTimeAsync(2_000);
  await expect(outcome).resolves.toMatchObject({
    code: 'HARDWARE_REQUEST_CANCELLED',
    transactionNotBroadcast: true,
  });
  expect(device).not.toHaveBeenCalled();
});

it('rejects a direct Trezor transaction without explicit approval before vendor dispatch', async () => {
  jest.useFakeTimers({ doNotFake: ['setImmediate'] });
  const value = new Keyring();
  keyrings.push(value);
  const initialization = value.init();
  await jest.advanceTimersByTimeAsync(100);
  await expect(initialization).resolves.toBe(true);
  const device = vendorSigner();
  const outcome = Reflect.apply(value.signEthTransaction, value, [
    evmRequest,
  ]).catch((error: unknown) => error);
  await jest.advanceTimersByTimeAsync(2_000);
  await expect(outcome).resolves.toMatchObject({
    code: 'HARDWARE_REQUEST_CANCELLED',
    transactionNotBroadcast: true,
  });
  expect(device).not.toHaveBeenCalled();
  expect('ethereumSignTransaction' in adapter.default).toBe(false);
});

it('rejects asynchronous approval before entering the Trezor transaction connector', async () => {
  const device = vendorSigner();
  await expect(
    adapter.default.ethereumSignTransactionOwned(
      { path: "m/44'/60'/0'/0/0", transaction: evmRequest.tx },
      {
        signal: new AbortController().signal,
        async assertCurrent() {
          throw new Error('Late rejection');
        },
      }
    )
  ).rejects.toMatchObject({
    code: 'HARDWARE_REQUEST_CANCELLED',
    transactionNotBroadcast: true,
  });
  expect(ConnectMock.init).not.toHaveBeenCalled();
  expect(device).not.toHaveBeenCalled();
});

it('checks the owner after the Connect adapter waits to enter the vendor method', async () => {
  const value = new Keyring();
  keyrings.push(value);
  await expect(value.init()).resolves.toBe(true);
  const device = vendorSigner();
  let current = true;
  const pending = adapter.default.ethereumSignTransactionOwned(
    { path: "m/44'/60'/0'/0/0", transaction: evmRequest.tx },
    {
      signal: new AbortController().signal,
      assertCurrent() {
        if (!current) throw new Error('Approval expired');
      },
    }
  );
  current = false;
  await expect(pending).rejects.toMatchObject({
    code: 'HARDWARE_REQUEST_CANCELLED',
    transactionNotBroadcast: true,
  });
  expect(device).not.toHaveBeenCalled();
});

it('checks UTXO approval after the Connect adapter waits to enter the vendor method', async () => {
  const value = new Keyring();
  keyrings.push(value);
  await expect(value.init()).resolves.toBe(true);
  const device = jest.spyOn(ConnectMock, 'signTransaction');
  let current = true;
  const pending = adapter.default.signTransactionOwned(
    { coin: 'sys', inputs: [], outputs: [] },
    {
      signal: new AbortController().signal,
      assertCurrent() {
        if (!current) throw new Error('Approval expired');
      },
    }
  );
  current = false;
  await expect(pending).rejects.toMatchObject({
    code: 'HARDWARE_REQUEST_CANCELLED',
    transactionNotBroadcast: true,
  });
  expect(device).not.toHaveBeenCalled();
  expect('signTransaction' in adapter.default).toBe(false);
});
