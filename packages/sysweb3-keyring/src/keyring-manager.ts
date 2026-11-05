import * as sysweb3 from '@sidhujag/sysweb3-core';

import { HardwareWalletManager } from './hardware-wallet-manager';
import { HardwareWalletManagerSingleton } from './hardware-wallet-manager-singleton';
import { KeyringCore } from './keyring-core';
import { LedgerKeyring } from './ledger';
import { getDecryptedVault, setEncryptedVault } from './storage';
import { createVaultPersistence } from './storage-core';
import {
  createLedgerPsbtSigner,
  createTrezorPsbtSigner,
} from './transactions/hardware-psbt';
import { TrezorKeyring } from './trezor';

import type {
  DeviceUnlockControls,
  DeviceUnlockPort,
  KeyringCoreDependencies,
  KeyringStoragePort,
} from './keyring-core';
import type { LedgerHost } from './ledger/host-types';
import type { CaptureEvmSubmission } from './transactions/evm-submission';
import type { IKeyringManager } from './types';

export type { ISysAccount } from './keyring-core';
export type {
  DeviceUnlockControls,
  DeviceUnlockPort,
  DeviceUnlockVaultPair,
  KeyringStoragePort,
} from './keyring-core';

const legacyAuthority = Object.freeze({});
const legacyVaultPersistence = { getDecryptedVault, setEncryptedVault };

declare const keyringManagerHostBrand: unique symbol;
/** Opaque identity for one explicitly configured browser wallet authority. */
export interface KeyringManagerHost {
  readonly [keyringManagerHostBrand]: true;
}

type ManagerDependencies = KeyringCoreDependencies<
  LedgerKeyring,
  TrezorKeyring
>;
const managerHosts = new WeakMap<
  KeyringManagerHost,
  Pick<ManagerDependencies, 'storage' | 'vaultPersistence'> & {
    sessionOwner: NonNullable<ManagerDependencies['sessionOwner']>;
    port: DeviceUnlockPort;
  }
>();

/** Create once for a fixed wallet store and share across replacement managers. */
export function createKeyringManagerHost(
  storage: KeyringStoragePort,
  deviceUnlock: DeviceUnlockPort
): KeyringManagerHost {
  if (
    !storage ||
    storage.setClient !== undefined ||
    typeof storage.get !== 'function' ||
    typeof storage.set !== 'function' ||
    typeof storage.deleteItem !== 'function' ||
    typeof storage.createManyIfAbsent !== 'function'
  ) {
    throw new TypeError('Device unlock requires fixed wallet storage');
  }
  if (typeof storage.readDeviceUnlockVaultPair !== 'function')
    throw new TypeError('Device unlock requires an atomic vault pair reader');
  if (
    typeof deviceUnlock?.readCredential !== 'function' ||
    typeof deviceUnlock.writeCredential !== 'function'
  ) {
    throw new TypeError('Device unlock requires a protected credential port');
  }

  const fixedStorage = Object.freeze({
    get: storage.get.bind(storage),
    set: storage.set.bind(storage),
    deleteItem: storage.deleteItem.bind(storage),
    createManyIfAbsent: storage.createManyIfAbsent.bind(storage),
    readDeviceUnlockVaultPair: storage.readDeviceUnlockVaultPair.bind(storage),
  });
  const host = Object.freeze({}) as KeyringManagerHost;
  managerHosts.set(host, {
    storage: fixedStorage,
    vaultPersistence: createVaultPersistence(fixedStorage),
    sessionOwner: { epoch: 0 },
    port: Object.freeze({
      readCredential: deviceUnlock.readCredential.bind(deviceUnlock),
      writeCredential: deviceUnlock.writeCredential.bind(deviceUnlock),
    }),
  });
  return host;
}

export type KeyringManagerOptions = {
  captureEvmSubmission?: CaptureEvmSubmission;
  host?: KeyringManagerHost;
  receiveDeviceUnlock?(controls: DeviceUnlockControls): void;
};

function prepareDeviceUnlockReceiver(
  receive: NonNullable<KeyringManagerOptions['receiveDeviceUnlock']>
): (controls: DeviceUnlockControls) => void {
  let controls: DeviceUnlockControls | undefined;
  const requireControls = () => {
    if (!controls) throw new Error('Device unlock controls are unavailable');
    return controls;
  };
  // The caller can capture the handle now. It only becomes usable once the
  // manager has been constructed successfully.
  const result: unknown = receive(
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
  return (value) => {
    controls = value;
  };
}

/** Existing browser entry. Native/software hosts must use the software entry. */
export class KeyringManager
  extends KeyringCore<LedgerKeyring, TrezorKeyring>
  implements IKeyringManager
{
  constructor(
    sharedHardwareWalletManager?: HardwareWalletManager,
    ledgerHost?: LedgerHost,
    options?: KeyringManagerOptions
  ) {
    if (sharedHardwareWalletManager && ledgerHost) {
      throw new Error(
        'Supply a shared hardware manager or a Ledger host, not both'
      );
    }
    const authority = options?.host;
    const host =
      authority === undefined ? undefined : managerHosts.get(authority);
    const receive = options?.receiveDeviceUnlock;
    if (authority !== undefined && !host)
      throw new TypeError('Invalid browser keyring host');
    if (receive !== undefined && (!host || typeof receive !== 'function'))
      throw new TypeError(
        'Device unlock requires an explicit browser keyring host'
      );
    // Reject failed receivers before setting up any shared hardware authority.
    const publishControls = receive
      ? prepareDeviceUnlockReceiver(receive)
      : undefined;
    const storage = host?.storage ?? sysweb3.sysweb3Di.getStateStorageDb();
    const hardwareManager =
      sharedHardwareWalletManager ||
      (ledgerHost
        ? new HardwareWalletManager(ledgerHost)
        : HardwareWalletManagerSingleton.getInstance());
    const trezorSigner = new TrezorKeyring();
    const ledgerSigner = new LedgerKeyring(hardwareManager, ledgerHost);
    let controls: DeviceUnlockControls | undefined;
    const deviceUnlock =
      host && publishControls
        ? {
            port: host.port,
            receive(value: DeviceUnlockControls) {
              controls = value;
            },
          }
        : undefined;
    super({
      authority: authority ?? legacyAuthority,
      captureEvmSubmission: options?.captureEvmSubmission,
      storage,
      vaultPersistence: host?.vaultPersistence ?? legacyVaultPersistence,
      ledgerSigner,
      trezorSigner,
      syscoinHardwareSigners: {
        ledger: createLedgerPsbtSigner(ledgerSigner),
        trezor: createTrezorPsbtSigner(trezorSigner),
      },
      ...(host ? { sessionOwner: host.sessionOwner, deviceUnlock } : {}),
    });
    if (host) {
      this.receiveSessionOwnership = () => {
        throw new Error('Direct session injection is unavailable in this host');
      };
    }
    if (publishControls) {
      if (!controls) throw new Error('Device unlock controls are unavailable');
      publishControls(controls);
    }
  }

  public static async createInitialized(
    seed: string,
    password: string,
    vaultStateGetter: () => any,
    options?: { captureEvmSubmission?: CaptureEvmSubmission }
  ): Promise<KeyringManager> {
    const keyring = new KeyringManager(undefined, undefined, {
      captureEvmSubmission: options?.captureEvmSubmission,
    });
    keyring.setVaultStateGetter(vaultStateGetter);
    await keyring.initializeWalletSecurely(seed, password);
    return keyring;
  }
}
