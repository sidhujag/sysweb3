import { createTestSubmissionCapture } from './evm-submission';
import { HardwareWalletManager } from '../../src/hardware-wallet-manager';
import { createKeyringHost } from '../../src/keyring-host';
import { KeyringManager } from '../../src/keyring-manager';

import type { KeyringHost } from '../../src/keyring-host';
import type { KeyringManagerOptions } from '../../src/keyring-manager';

export const testStorage = () =>
  jest.requireMock('@sidhujag/sysweb3-core').sysweb3Di.getStateStorageDb();

export function createTestKeyringHost(storage = testStorage()) {
  return createKeyringHost({
    get: storage.get.bind(storage),
    set: storage.set.bind(storage),
    deleteItem: storage.deleteItem.bind(storage),
    createManyIfAbsent: storage.createManyIfAbsent.bind(storage),
  });
}

export const testHardware = () => ({
  hardwareManager: new HardwareWalletManager(),
  trezorHost: jest.requireMock('@trezor/connect-webextension'),
  captureEvmSubmission: createTestSubmissionCapture(),
});

export function createTestKeyring(host = createTestKeyringHost()) {
  return new KeyringManager(host, testHardware());
}

export async function createInitializedTestKeyring(
  seed: string,
  password: string,
  getter: () => any,
  host: KeyringHost = createTestKeyringHost(),
  hardware: KeyringManagerOptions = testHardware()
) {
  const keyring = new KeyringManager(host, hardware);
  keyring.setVaultStateGetter(getter);
  try {
    await keyring.initializeWalletSecurely(seed, password);
    return keyring;
  } catch (error) {
    await keyring.destroy();
    throw error;
  }
}
