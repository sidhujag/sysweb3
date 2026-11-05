import { HardwareWalletManager } from './hardware-wallet-manager';
import { KeyringCore } from './keyring-core';
import { prepareKeyringHost } from './keyring-host';
import { LedgerKeyring } from './ledger';
import {
  createLedgerPsbtSigner,
  createTrezorPsbtSigner,
} from './transactions/hardware-psbt';
import { TrezorKeyring } from './trezor';

import type { KeyringHost, KeyringOptions } from './keyring-host';
import type { LedgerHost } from './ledger/host-types';
import type { IKeyringManager } from './types';

export type { ISysAccount } from './keyring-core';
export type {
  DeviceUnlockControls,
  DeviceUnlockPort,
  DeviceUnlockVaultPair,
  KeyringStoragePort,
} from './keyring-core';

export type KeyringManagerOptions = KeyringOptions &
  (
    | { ledgerHost: LedgerHost; hardwareManager?: never }
    | { ledgerHost?: never; hardwareManager: HardwareWalletManager }
  );

/** Browser keyring with an explicit wallet authority and hardware adapter. */
export class KeyringManager
  extends KeyringCore<LedgerKeyring, TrezorKeyring>
  implements IKeyringManager
{
  constructor(host: KeyringHost, options: KeyringManagerOptions) {
    const { hardwareManager, ledgerHost } = options ?? {};
    if ((!hardwareManager && !ledgerHost) || (hardwareManager && ledgerHost)) {
      throw new Error('Supply exactly one hardware manager or Ledger host');
    }
    const { binding, publishControls } = prepareKeyringHost(host, options);
    const manager = hardwareManager ?? new HardwareWalletManager(ledgerHost);
    const trezorSigner = new TrezorKeyring();
    const ledgerSigner = new LedgerKeyring(manager, ledgerHost);
    super(binding, {
      ledgerSigner,
      trezorSigner,
      syscoinHardwareSigners: {
        ledger: createLedgerPsbtSigner(ledgerSigner),
        trezor: createTrezorPsbtSigner(trezorSigner),
      },
    });
    publishControls?.();
  }

  public static async createInitialized(
    host: KeyringHost,
    seed: string,
    password: string,
    vaultStateGetter: () => any,
    options: KeyringManagerOptions
  ): Promise<KeyringManager> {
    const keyring = new KeyringManager(host, options);
    keyring.setVaultStateGetter(vaultStateGetter);
    await keyring.initializeWalletSecurely(seed, password);
    return keyring;
  }
}
