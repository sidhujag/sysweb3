import * as sysweb3 from '@sidhujag/sysweb3-core';

import { HardwareWalletManager } from './hardware-wallet-manager';
import { HardwareWalletManagerSingleton } from './hardware-wallet-manager-singleton';
import { KeyringCore } from './keyring-core';
import { LedgerKeyring } from './ledger';
import { getDecryptedVault, setEncryptedVault } from './storage';
import {
  createLedgerPsbtSigner,
  createTrezorPsbtSigner,
} from './transactions/hardware-psbt';
import { TrezorKeyring } from './trezor';

import type { LedgerHost } from './ledger/host-types';
import type { CaptureEvmSubmission } from './transactions/evm-submission';
import type { IKeyringManager } from './types';

export type { ISysAccount } from './keyring-core';

const legacyAuthority = Object.freeze({});
const legacyVaultPersistence = { getDecryptedVault, setEncryptedVault };

/** Existing browser entry. Native/software hosts must use the software entry. */
export class KeyringManager
  extends KeyringCore<LedgerKeyring, TrezorKeyring>
  implements IKeyringManager
{
  constructor(
    sharedHardwareWalletManager?: HardwareWalletManager,
    ledgerHost?: LedgerHost,
    options?: { captureEvmSubmission?: CaptureEvmSubmission }
  ) {
    if (sharedHardwareWalletManager && ledgerHost) {
      throw new Error(
        'Supply a shared hardware manager or a Ledger host, not both'
      );
    }
    const storage = sysweb3.sysweb3Di.getStateStorageDb();
    const hardwareManager =
      sharedHardwareWalletManager ||
      (ledgerHost
        ? new HardwareWalletManager(ledgerHost)
        : HardwareWalletManagerSingleton.getInstance());
    const trezorSigner = new TrezorKeyring();
    const ledgerSigner = new LedgerKeyring(hardwareManager, ledgerHost);
    super({
      authority: legacyAuthority,
      captureEvmSubmission: options?.captureEvmSubmission,
      storage,
      vaultPersistence: legacyVaultPersistence,
      ledgerSigner,
      trezorSigner,
      syscoinHardwareSigners: {
        ledger: createLedgerPsbtSigner(ledgerSigner),
        trezor: createTrezorPsbtSigner(trezorSigner),
      },
    });
  }

  public static async createInitialized(
    seed: string,
    password: string,
    vaultStateGetter: () => any,
    options?: { captureEvmSubmission?: CaptureEvmSubmission }
  ): Promise<KeyringManager> {
    const keyring = new KeyringManager(undefined, undefined, options);
    keyring.setVaultStateGetter(vaultStateGetter);
    await keyring.initializeWalletSecurely(seed, password);
    return keyring;
  }
}
