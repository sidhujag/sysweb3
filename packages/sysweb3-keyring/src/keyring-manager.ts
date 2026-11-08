import { HardwareWalletManager } from './hardware-wallet-manager';
import { HostKeyring } from './host-keyring';
import { LedgerKeyring } from './ledger';
import { createLedgerPsbtSigner } from './transactions/hardware-psbt';
import { TrezorKeyring } from './trezor';
import { createTrezorHardware } from './trezor-hardware';

import type { KeyringHost, KeyringOptions } from './keyring-host';
import type { LedgerHost } from './ledger/host-types';
import type { CaptureEvmSubmission } from './transactions/evm-submission';
import type { TrezorHost } from './trezor/host-types';
import type { IKeyringManager } from './types';

export type { ISysAccount } from './keyring-core';
export type {
  DeviceUnlockControls,
  DeviceUnlockPort,
  DeviceUnlockVaultPair,
  KeyringStoragePort,
  PreparedSessionTransfer,
} from './keyring-core';

export type KeyringManagerOptions = Omit<
  KeyringOptions,
  'captureEvmSubmission'
> & {
  captureEvmSubmission: CaptureEvmSubmission;
  trezorHost: TrezorHost;
} & (
    | { ledgerHost: LedgerHost; hardwareManager?: never }
    | { ledgerHost?: never; hardwareManager: HardwareWalletManager }
  );

/** Browser keyring with an explicit wallet authority and hardware adapter. */
export class KeyringManager
  extends HostKeyring<LedgerKeyring, TrezorKeyring>
  implements IKeyringManager
{
  constructor(host: KeyringHost, options: KeyringManagerOptions) {
    const { hardwareManager, ledgerHost } = options ?? {};
    if ((!hardwareManager && !ledgerHost) || (hardwareManager && ledgerHost)) {
      throw new Error('Supply exactly one hardware manager or Ledger host');
    }
    if (typeof options.captureEvmSubmission !== 'function')
      throw new TypeError('Browser keyring requires durable EVM submission');
    super(host, options, () => {
      const { trezorSigner, syscoinHardwareSigners } = createTrezorHardware(
        options.trezorHost
      );
      const manager = hardwareManager ?? new HardwareWalletManager(ledgerHost);
      const ledgerSigner = new LedgerKeyring(manager, ledgerHost);
      return {
        ledgerSigner,
        trezorSigner,
        syscoinHardwareSigners: {
          ...syscoinHardwareSigners,
          ledger: createLedgerPsbtSigner(ledgerSigner),
        },
      };
    });
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
