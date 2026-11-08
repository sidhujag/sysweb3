import { LedgerKeyring } from './ledger';
import { createLedgerPsbtSigner } from './transactions/hardware-psbt';

import type { KeyringHardware } from './keyring-core';
import type { LedgerHost } from './ledger/host-types';

/** Use the same Ledger account and transaction adapters on every host. */
export function createLedgerHardware(
  host: LedgerHost
): KeyringHardware<LedgerKeyring, undefined> {
  const ledgerSigner = new LedgerKeyring(undefined, host);
  return {
    ledgerSigner,
    trezorSigner: undefined,
    syscoinHardwareSigners: { ledger: createLedgerPsbtSigner(ledgerSigner) },
  };
}
