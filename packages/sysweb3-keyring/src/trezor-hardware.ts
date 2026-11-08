import { createTrezorPsbtSigner } from './transactions/hardware-psbt';
import { TrezorKeyring } from './trezor';
import { createTrezorConnection } from './trezor/connect';

import type { KeyringHardware } from './keyring-core';
import type { TrezorHost } from './trezor/host-types';

/** Use the same Trezor account and transaction adapters on every host. */
export function createTrezorHardware(
  host: TrezorHost
): KeyringHardware<undefined, TrezorKeyring> {
  const trezorSigner = new TrezorKeyring(createTrezorConnection(host));
  return {
    ledgerSigner: undefined,
    trezorSigner,
    syscoinHardwareSigners: { trezor: createTrezorPsbtSigner(trezorSigner) },
  };
}

export type { TrezorHost } from './trezor/host-types';
