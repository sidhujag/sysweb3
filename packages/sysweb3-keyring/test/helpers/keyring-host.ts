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
});

export function createTestKeyring(host = createTestKeyringHost()) {
  return new KeyringManager(host, testHardware());
}

export function createInitializedTestKeyring(
  seed: string,
  password: string,
  getter: () => any,
  host: KeyringHost = createTestKeyringHost(),
  hardware: KeyringManagerOptions = testHardware()
) {
  return KeyringManager.createInitialized(
    host,
    seed,
    password,
    getter,
    hardware
  );
}
