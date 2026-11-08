import { HostKeyring } from '../../../src/host-keyring';
import { createKeyringHost } from '../../../src/keyring-host';
import { createTestKeyringHost } from '../../helpers/keyring-host';

it('requires the fixed host and explicit capabilities before hardware starts', () => {
  const createHardware = jest.fn(() => ({
    ledgerSigner: undefined,
    trezorSigner: undefined,
  }));
  expect(
    () =>
      new HostKeyring({} as any, { captureEvmSubmission: null }, createHardware)
  ).toThrow('Invalid keyring host');
  expect(createHardware).not.toHaveBeenCalled();
  expect(
    () => new HostKeyring(createTestKeyringHost(), {} as any, createHardware)
  ).toThrow('explicit EVM submission');
  expect(createHardware).not.toHaveBeenCalled();
});

it('loads the native hardware facade without browser or Trezor initialization', async () => {
  const forbidden = [
    '../../../src/hardware-wallet-manager',
    '../../../src/trezor',
    '../../../src/trezor/connect',
    '@trezor/connect-webextension',
    '@ledgerhq/device-transport-kit-web-hid',
  ];
  const loaded: string[] = [];
  for (const name of forbidden)
    jest.doMock(
      name,
      () => {
        loaded.push(name);
        throw new Error(`Native hardware loaded ${name}`);
      },
      { virtual: true }
    );
  let ring: HostKeyring<any, undefined> | undefined;
  try {
    jest.isolateModules(() => {
      const {
        HostKeyring: NativeKeyring,
        createKeyringHost: createHost,
      } = require('../../../src/host-keyring');
      const { createLedgerHardware } = require('../../../src/ledger-hardware');
      const host = {
        connect: jest.fn(),
        disconnect: jest.fn(async () => undefined),
        getStatus: () => ({ connected: false }),
        evm: {},
        utxo: {},
      };
      const storage = {
        get: async () => undefined,
        set: async () => undefined,
        deleteItem: async () => undefined,
        createManyIfAbsent: async () => true,
      };
      ring = new NativeKeyring(
        createHost(storage),
        { captureEvmSubmission: null },
        () => createLedgerHardware(host)
      );
      expect(ring!.ledgerSigner).toBeDefined();
      expect(ring!.trezorSigner).toBeUndefined();
      expect(ring!.deriveEvmHdRuntimeAccount).toBeInstanceOf(Function);
      expect(ring!.signPreparedEvmTransaction).toBeInstanceOf(Function);
    });
    expect(loaded).toEqual([]);
  } finally {
    await ring?.destroy();
    for (const name of forbidden) jest.dontMock(name);
  }
});

it('requires an explicit software-only hardware result', () => {
  const host = createKeyringHost({
    get: async () => undefined,
    set: async () => undefined,
    deleteItem: async () => undefined,
    createManyIfAbsent: async () => true,
  });
  expect(
    () =>
      new HostKeyring(host, { captureEvmSubmission: null }, () => ({} as any))
  ).toThrow('explicit hardware capabilities');
});
