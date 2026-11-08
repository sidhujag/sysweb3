import { Subject } from 'rxjs';

import { HostKeyring } from '../../../src/host-keyring';
import { LedgerKeyring } from '../../../src/ledger';
import { createLedgerHostForDmk } from '../../../src/ledger/dmk-host';
import { TrezorKeyring } from '../../../src/trezor';
import { createTrezorConnection } from '../../../src/trezor/connect';
import { TREZOR_METHODS } from '../../../src/trezor/host-types';
import { createTestKeyringHost } from '../../helpers/keyring-host';

import type { LedgerHost } from '../../../src/ledger/host-types';
import type { TrezorHost } from '../../../src/trezor/host-types';

jest.unmock('../../../src/trezor/connect');
jest.mock('../../../src/ledger/dmk-evm', () => ({
  createLedgerEvmAdapter: () => ({}),
}));
jest.mock('../../../src/ledger/dmk-utxo', () => ({
  createLedgerUtxoAdapter: () => ({}),
}));

const phrase =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const password = 'public session transfer fixture';
const releases: (() => void)[] = [];
const gate = () => {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  releases.push(resolve);
  return { promise, resolve };
};
const deviceHost = (): TrezorHost =>
  ({
    ...Object.fromEntries(
      TREZOR_METHODS.map((method) => [
        method,
        jest.fn(async (assertCurrent) => {
          assertCurrent();
          return { success: true, payload: { model: 'synthetic' } };
        }),
      ])
    ),
    init: jest.fn(async (assertCurrent) => {
      assertCurrent();
    }),
    dispose: jest.fn(async (pending) => {
      await Promise.allSettled(pending);
    }),
  } as TrezorHost);

let device: TrezorHost;
let ledgerDevice: LedgerHost;
let ledgerConnected: boolean;
let source: HostKeyring<LedgerKeyring, TrezorKeyring>;
let target: typeof source;
beforeEach(async () => {
  device = deviceHost();
  ledgerConnected = false;
  ledgerDevice = {
    connect: jest.fn(async () => {
      ledgerConnected = true;
    }),
    disconnect: jest.fn(async () => {
      ledgerConnected = false;
    }),
    retire: jest.fn(async () => {
      await ledgerDevice.disconnect();
      return () => {
        if (ledgerConnected) throw new Error('Ledger reopened');
      };
    }),
    getStatus: () => ({ connected: ledgerConnected }),
    evm: {} as LedgerHost['evm'],
    utxo: {} as LedgerHost['utxo'],
  };
  const host = createTestKeyringHost();
  source = new HostKeyring(host, { captureEvmSubmission: null }, () => ({
    ledgerSigner: new LedgerKeyring(undefined, ledgerDevice),
    trezorSigner: new TrezorKeyring(createTrezorConnection(device)),
  }));
  target = new HostKeyring(host, { captureEvmSubmission: null }, () => ({
    ledgerSigner: new LedgerKeyring(undefined, ledgerDevice),
    trezorSigner: new TrezorKeyring(createTrezorConnection(device)),
  }));
  const state = {
    activeAccount: { id: 0, type: 'HDAccount' },
    activeNetwork: { kind: 'ethereum', chainId: 1, slip44: 60 },
    accounts: { HDAccount: { 0: { id: 0 } } },
  };
  source.setVaultStateGetter(() => state);
  target.setVaultStateGetter(() => state);
  await source.initializeSession(phrase, password);
  await source.ledgerSigner.ensureConnection();
  await source.trezorSigner.init();
});
afterEach(async () => {
  for (const release of releases.splice(0)) release();
  await source.destroy();
  await target.destroy();
});

const dmkFixture = async () => {
  await source.ledgerSigner.destroy();
  await target.ledgerSigner.destroy();
  const dmk = {
    connect: jest.fn().mockResolvedValue('next-session'),
    disconnect: jest.fn().mockResolvedValue(undefined),
    executeDeviceAction: jest.fn(),
    startDiscovering: jest.fn(),
    listenToAvailableDevices: jest.fn(),
    getDeviceSessionState: jest.fn(() => new Subject()),
  };
  const host = createLedgerHostForDmk(dmk, {}, true);
  source.ledgerSigner = new LedgerKeyring(undefined, host);
  target.ledgerSigner = new LedgerKeyring(undefined, host);
  const device = {
    id: 'selected-ledger',
    transport: 'RN_BLE',
    name: 'Ledger',
    deviceModel: { id: 'flex', name: 'Ledger Flex' },
  };
  return { dmk, host, device };
};

it('waits for hardware retirement before returning a synchronous, one-use buffer move', async () => {
  const closing = gate();
  jest.spyOn(device, 'dispose').mockImplementationOnce(() => closing.promise);
  const buffers = [
    (source as any).sessionPassword,
    (source as any).sessionMnemonic,
  ];
  const preparing = source.prepareSessionTransfer(target, () => undefined);
  await new Promise(setImmediate);
  expect(source.isUnlocked()).toBe(true);
  expect(target.isUnlocked()).toBe(false);
  closing.resolve();
  const prepared = await preparing;
  expect(source.isUnlocked()).toBe(true);
  prepared.transfer();
  expect(source.isUnlocked()).toBe(false);
  expect(target.isUnlocked()).toBe(true);
  expect((target as any).sessionPassword).toBe(buffers[0]);
  expect((target as any).sessionMnemonic).toBe(buffers[1]);
  expect(() => prepared.transfer()).toThrow('already been used');
  await expect(target.trezorSigner.init()).resolves.toBe(true);
  expect(await target.getSeed(password)).toBe(phrase);
  const back = await target.prepareSessionTransfer(source, () => undefined);
  back.transfer();
  await expect(source.trezorSigner.init()).resolves.toBe(true);
});

it('does not move either session when retirement fails', async () => {
  jest
    .spyOn(device, 'dispose')
    .mockRejectedValueOnce(new Error('Retirement failed'));
  const original = (source as any).sessionPassword;
  await expect(
    source.prepareSessionTransfer(target, () => undefined)
  ).rejects.toThrow('Retirement failed');
  expect(source.isUnlocked()).toBe(true);
  expect((source as any).sessionPassword).toBe(original);
  expect(target.isUnlocked()).toBe(false);
});

it.each(['source', 'target'] as const)(
  'cancels preparation promptly when %s locks during retirement',
  async (side) => {
    const closing = gate();
    jest.spyOn(device, 'dispose').mockImplementationOnce(() => closing.promise);
    const preparing = source.prepareSessionTransfer(target, () => undefined);
    const cancelled = expect(preparing).rejects.toThrow('session changed');
    await new Promise(setImmediate);
    void (side === 'source' ? source : target).lockWallet();
    await cancelled;
    expect(target.isUnlocked()).toBe(false);
    closing.resolve();
  }
);

it('rejects a prepared move after the source locks and unlocks again', async () => {
  const prepared = await source.prepareSessionTransfer(target, () => undefined);
  await source.lockWallet();
  await source.unlock(password);
  expect(() => prepared.transfer()).toThrow('session changed');
  expect(target.isUnlocked()).toBe(false);
});

it('rechecks ownership after an external guard locks the source during commit', async () => {
  let committing = false;
  const prepared = await source.prepareSessionTransfer(target, () => {
    if (committing) void source.lockWallet();
  });
  committing = true;
  expect(() => prepared.transfer()).toThrow('session changed');
  expect(source.isUnlocked()).toBe(false);
  expect(target.isUnlocked()).toBe(false);
});

it('rejects asynchronous preparation guards before retiring the device', async () => {
  await expect(
    source.prepareSessionTransfer(target, async () => undefined)
  ).rejects.toMatchObject({
    code: 'HARDWARE_REQUEST_CANCELLED',
  });
  expect(device.dispose).not.toHaveBeenCalled();
  expect(source.isUnlocked()).toBe(true);
  expect(target.isUnlocked()).toBe(false);
});

it.each(['trezor', 'ledger'] as const)(
  'rejects a prepared move after the source %s reopens and allows fresh preparation',
  async (kind) => {
    const prepared = await source.prepareSessionTransfer(
      target,
      () => undefined
    );
    if (kind === 'trezor') await source.trezorSigner.init();
    else await source.ledgerSigner.ensureConnection();
    expect(() => prepared.transfer()).toThrow();
    expect(source.isUnlocked()).toBe(true);
    expect(target.isUnlocked()).toBe(false);
    const retry = await source.prepareSessionTransfer(target, () => undefined);
    retry.transfer();
    expect(source.isUnlocked()).toBe(false);
    expect(target.isUnlocked()).toBe(true);
    if (kind === 'trezor')
      await expect(target.trezorSigner.init()).resolves.toBe(true);
    else
      await expect(
        target.ledgerSigner.ensureConnection()
      ).resolves.toBeUndefined();
  }
);

it.each(['trezor', 'ledger'] as const)(
  'rejects a prepared move as soon as source %s reopening starts',
  async (kind) => {
    const prepared = await source.prepareSessionTransfer(
      target,
      () => undefined
    );
    const opening = gate();
    if (kind === 'ledger')
      jest.spyOn(ledgerDevice, 'connect').mockImplementationOnce(async () => {
        await opening.promise;
        ledgerConnected = true;
      });
    const reopened =
      kind === 'trezor'
        ? source.trezorSigner.init()
        : source.ledgerSigner.ensureConnection();
    expect(() => prepared.transfer()).toThrow();
    expect(source.isUnlocked()).toBe(true);
    expect(target.isUnlocked()).toBe(false);
    opening.resolve();
    await reopened;
  }
);

it.each(['trezor', 'ledger'] as const)(
  'rejects a prepared move when another keyring reopens the shared %s host',
  async (kind) => {
    const prepared = await source.prepareSessionTransfer(
      target,
      () => undefined
    );
    if (kind === 'trezor') await target.trezorSigner.init();
    else await target.ledgerSigner.ensureConnection();
    expect(() => prepared.transfer()).toThrow();
    expect(source.isUnlocked()).toBe(true);
    expect(target.isUnlocked()).toBe(false);
  }
);

it('rejects a prepared move when a sibling starts reconnecting the shared Ledger host', async () => {
  const prepared = await source.prepareSessionTransfer(target, () => undefined);
  const opening = gate();
  jest.spyOn(ledgerDevice, 'connect').mockImplementationOnce(async () => {
    await opening.promise;
    ledgerConnected = true;
  });
  const reopened = target.ledgerSigner.ensureConnection();
  expect(ledgerDevice.getStatus().connected).toBe(false);
  expect(() => prepared.transfer()).toThrow();
  expect(source.isUnlocked()).toBe(true);
  expect(target.isUnlocked()).toBe(false);
  opening.resolve();
  await reopened;
});

it.each([
  ['missing', undefined],
  ['non-void', () => true],
  ['asynchronous', async () => undefined],
] as const)(
  'rejects a %s retirement proof before moving buffers',
  async (_, proof) => {
    const retire = source.trezorSigner.retire.bind(source.trezorSigner);
    jest
      .spyOn(source.trezorSigner, 'retire')
      .mockImplementationOnce(async () => {
        await retire();
        return proof as unknown as () => void;
      });
    await expect(
      source.prepareSessionTransfer(target, () => undefined)
    ).rejects.toMatchObject({ code: 'HARDWARE_REQUEST_CANCELLED' });
    expect(source.isUnlocked()).toBe(true);
    expect(target.isUnlocked()).toBe(false);
  }
);

it.each(['connected', 'rejected'] as const)(
  'joins a pending direct DMK picker before transfer after the vendor %s',
  async (result) => {
    const { dmk, host, device } = await dmkFixture();
    const connecting = gate();
    const closing = gate();
    dmk.connect.mockImplementationOnce(async () => {
      await connecting.promise;
      if (result === 'rejected') throw new Error('Vendor connection failed');
      return 'old-session';
    });
    dmk.disconnect.mockImplementationOnce(() => closing.promise);
    const picked = host.beginDeviceSelection()(device);
    const cancelled = expect(picked).rejects.toMatchObject({
      code: 'HARDWARE_REQUEST_CANCELLED',
    });
    await new Promise(setImmediate);
    let prepared = false;
    const preparing = source
      .prepareSessionTransfer(target, () => undefined)
      .then((value) => {
        prepared = true;
        return value;
      });
    await new Promise(setImmediate);
    expect(prepared).toBe(false);
    expect(source.isUnlocked()).toBe(true);
    expect(host.getStatus().connected).toBe(false);
    connecting.resolve();
    await new Promise(setImmediate);
    if (result === 'connected') {
      expect(prepared).toBe(false);
      expect(dmk.disconnect).toHaveBeenCalledWith({ sessionId: 'old-session' });
    }
    closing.resolve();
    const transfer = await preparing;
    await cancelled;
    transfer.transfer();
    expect(source.isUnlocked()).toBe(false);
    expect(target.isUnlocked()).toBe(true);
    await host.beginDeviceSelection()(device);
    await target.ledgerSigner.ensureConnection();
    expect(host.getStatus().connected).toBe(true);
    expect(dmk.connect).toHaveBeenCalledTimes(2);
  }
);

it('cancels transfer promptly on lock while a direct DMK picker is still pending', async () => {
  const { dmk, host, device } = await dmkFixture();
  const connecting = gate();
  dmk.connect.mockImplementationOnce(async () => {
    await connecting.promise;
    return 'old-session';
  });
  const picked = host.beginDeviceSelection()(device);
  const cancelledPicker = expect(picked).rejects.toMatchObject({
    code: 'HARDWARE_REQUEST_CANCELLED',
  });
  await new Promise(setImmediate);
  const preparing = source.prepareSessionTransfer(target, () => undefined);
  const cancelledTransfer =
    expect(preparing).rejects.toThrow('session changed');
  await new Promise(setImmediate);
  await source.lockWallet();
  await cancelledTransfer;
  expect(source.isUnlocked()).toBe(false);
  expect(target.isUnlocked()).toBe(false);
  expect(dmk.disconnect).not.toHaveBeenCalled();
  connecting.resolve();
  await cancelledPicker;
  await host.retire();
  await host.beginDeviceSelection()(device);
  expect(host.getStatus().connected).toBe(true);
});

it('keeps the source session when a late DMK connection cannot be closed', async () => {
  const { dmk, host, device } = await dmkFixture();
  const connecting = gate();
  dmk.connect.mockImplementationOnce(async () => {
    await connecting.promise;
    return 'old-session';
  });
  dmk.disconnect.mockRejectedValueOnce(new Error('Vendor close failed'));
  const picked = host.beginDeviceSelection()(device);
  const cancelledPicker = expect(picked).rejects.toMatchObject({
    code: 'HARDWARE_REQUEST_CANCELLED',
  });
  await new Promise(setImmediate);
  const original = (source as any).sessionPassword;
  const preparing = source.prepareSessionTransfer(target, () => undefined);
  const failedTransfer = expect(preparing).rejects.toThrow(
    'Vendor close failed'
  );
  await new Promise(setImmediate);
  connecting.resolve();
  await failedTransfer;
  await cancelledPicker;
  expect(source.isUnlocked()).toBe(true);
  expect((source as any).sessionPassword).toBe(original);
  expect(target.isUnlocked()).toBe(false);
});

it.each(['selected', 'pending', 'connected', 'disconnected'] as const)(
  'rejects a prepared transfer after a direct DMK picker is %s',
  async (phase) => {
    const { dmk, host, device } = await dmkFixture();
    const prepared = await source.prepareSessionTransfer(
      target,
      () => undefined
    );
    const connecting = gate();
    dmk.connect.mockImplementationOnce(async () => {
      await connecting.promise;
      return 'reopened-session';
    });
    const select = host.beginDeviceSelection();
    let picked: Promise<void> | undefined;
    if (phase !== 'selected') {
      picked = select(device);
      void picked.catch(() => undefined);
      await new Promise(setImmediate);
    }
    if (phase === 'connected' || phase === 'disconnected') {
      connecting.resolve();
      await picked;
      if (phase === 'disconnected') await host.disconnect();
    }
    expect(() => prepared.transfer()).toThrow();
    expect(source.isUnlocked()).toBe(true);
    expect(target.isUnlocked()).toBe(false);
    if (phase === 'pending') {
      expect(host.getStatus().connected).toBe(false);
      connecting.resolve();
      await picked;
    }
  }
);

it.each([
  ['missing', undefined],
  ['non-void', () => true],
  ['asynchronous', async () => undefined],
] as const)(
  'rejects a %s Ledger host retirement proof before moving buffers',
  async (_, proof) => {
    const retire = ledgerDevice.retire.bind(ledgerDevice);
    jest.spyOn(ledgerDevice, 'retire').mockImplementationOnce(async () => {
      await retire();
      return proof as unknown as () => void;
    });
    await expect(
      source.prepareSessionTransfer(target, () => undefined)
    ).rejects.toMatchObject({ code: 'HARDWARE_REQUEST_CANCELLED' });
    expect(source.isUnlocked()).toBe(true);
    expect(target.isUnlocked()).toBe(false);
  }
);
