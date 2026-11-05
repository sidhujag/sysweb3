import { createVaultPersistence } from './storage-core';

import type {
  DeviceUnlockControls,
  DeviceUnlockPort,
  KeyringStoragePort,
} from './keyring-core';
import type { VaultPersistence } from './storage-core';
import type { CaptureEvmSubmission } from './transactions/evm-submission';

declare const keyringHostBrand: unique symbol;
/** Opaque identity for one fixed wallet store and its unlock session. */
export interface KeyringHost {
  readonly [keyringHostBrand]: true;
}

export type SessionOwner = { current?: symbol; epoch: number };

type BoundHost = {
  storage: KeyringStoragePort;
  vaultPersistence: VaultPersistence;
  sessionOwner: SessionOwner;
  deviceUnlockPort?: DeviceUnlockPort;
};

const hosts = new WeakMap<KeyringHost, BoundHost>();

export function createKeyringHost(
  storage: KeyringStoragePort,
  options?: { deviceUnlock?: DeviceUnlockPort }
): KeyringHost {
  if (
    !storage ||
    'setClient' in storage ||
    typeof storage.get !== 'function' ||
    typeof storage.set !== 'function' ||
    typeof storage.deleteItem !== 'function' ||
    typeof storage.createManyIfAbsent !== 'function'
  ) {
    throw new TypeError('Keyring host requires fixed wallet storage');
  }
  const { deviceUnlock } = options ?? {};
  const readPair = storage.readDeviceUnlockVaultPair;
  if (deviceUnlock !== undefined) {
    if (typeof readPair !== 'function')
      throw new TypeError('Device unlock requires an atomic vault pair reader');
    if (
      typeof deviceUnlock?.readCredential !== 'function' ||
      typeof deviceUnlock.writeCredential !== 'function'
    ) {
      throw new TypeError('Device unlock requires a protected credential port');
    }
  }

  const fixedStorage = Object.freeze({
    get: storage.get.bind(storage),
    set: storage.set.bind(storage),
    deleteItem: storage.deleteItem.bind(storage),
    createManyIfAbsent: storage.createManyIfAbsent.bind(storage),
    ...(typeof readPair === 'function'
      ? { readDeviceUnlockVaultPair: readPair.bind(storage) }
      : {}),
  });
  const host = Object.freeze({}) as KeyringHost;
  hosts.set(host, {
    storage: fixedStorage,
    vaultPersistence: createVaultPersistence(fixedStorage),
    sessionOwner: { epoch: 0 },
    deviceUnlockPort:
      deviceUnlock &&
      Object.freeze({
        readCredential: deviceUnlock.readCredential.bind(deviceUnlock),
        writeCredential: deviceUnlock.writeCredential.bind(deviceUnlock),
      }),
  });
  return host;
}

export type KeyringOptions = {
  captureEvmSubmission: CaptureEvmSubmission | null;
  receiveDeviceUnlock?(controls: DeviceUnlockControls): void;
};

declare const bindingBrand: unique symbol;
export interface KeyringHostBinding {
  readonly [bindingBrand]: true;
}

type PreparedHost = Omit<BoundHost, 'deviceUnlockPort'> & {
  authority: KeyringHost;
  captureEvmSubmission: CaptureEvmSubmission | null;
  deviceUnlock?: {
    port: DeviceUnlockPort;
    receive(controls: DeviceUnlockControls): void;
  };
};

const bindings = new WeakMap<KeyringHostBinding, PreparedHost>();

function bindHost(prepared: PreparedHost): KeyringHostBinding {
  const binding = Object.freeze({}) as KeyringHostBinding;
  bindings.set(binding, prepared);
  return binding;
}

export function takeKeyringHostBinding(binding: KeyringHostBinding) {
  const prepared = bindings.get(binding);
  if (!prepared) throw new TypeError('Invalid keyring host binding');
  bindings.delete(binding);
  return prepared;
}

export function prepareKeyringHost(host: KeyringHost, options: KeyringOptions) {
  const bound = hosts.get(host);
  if (!bound) throw new TypeError('Invalid keyring host');
  const { deviceUnlockPort, ...storage } = bound;
  const { captureEvmSubmission, receiveDeviceUnlock } = options ?? {};
  if (
    captureEvmSubmission !== null &&
    typeof captureEvmSubmission !== 'function'
  )
    throw new TypeError(
      'Keyring host requires an explicit EVM submission capability'
    );
  const dependencies = { ...storage, authority: host, captureEvmSubmission };
  if (receiveDeviceUnlock === undefined)
    return { binding: bindHost(dependencies) };
  if (!deviceUnlockPort || typeof receiveDeviceUnlock !== 'function')
    throw new TypeError('Device unlock is unavailable in this host');

  // Expose only a sealed handle until construction succeeds for either entry.
  let controls: DeviceUnlockControls | undefined;
  let ready = false;
  const requireControls = () => {
    if (!ready || !controls)
      throw new Error('Device unlock controls are unavailable');
    return controls;
  };
  const result: unknown = receiveDeviceUnlock(
    Object.freeze<DeviceUnlockControls>({
      async issue(password, assertCurrent) {
        return requireControls().issue(password, assertCurrent);
      },
      async resume(assertCurrent) {
        return requireControls().resume(assertCurrent);
      },
    })
  );
  if (result !== undefined) {
    void Promise.resolve(result).catch(() => undefined);
    throw new TypeError('Device unlock receiver must complete synchronously');
  }

  return {
    binding: bindHost({
      ...dependencies,
      deviceUnlock: {
        port: deviceUnlockPort,
        receive(value: DeviceUnlockControls) {
          controls = value;
        },
      },
    }),
    publishControls() {
      if (!controls) throw new Error('Device unlock controls are unavailable');
      ready = true;
    },
  };
}
