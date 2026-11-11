import { KeyringCore } from './keyring-core';
import { prepareKeyringHost } from './keyring-host';

import type {
  KeyringHardware,
  KeyringLedgerSigner,
  KeyringTrezorSigner,
} from './keyring-core';
import type { KeyringHost, KeyringOptions } from './keyring-host';
import type {
  EncryptedEvmHdRuntimeAccount,
  EvmHdRuntimeAccountOptions,
  EvmHdRuntimeAccountRequest,
} from './software-hd-account';
import type {
  PreparedEvmSigningOptions,
  PreparedSoftwareEvmSigningRequest,
  SignedPreparedEvmTransaction,
} from './transactions/prepared-evm';

/** Shared wallet engine with explicit host authority and hardware capabilities. */
export class HostKeyring<
  TLedger extends KeyringLedgerSigner | undefined,
  TTrezor extends KeyringTrezorSigner | undefined
> extends KeyringCore<TLedger, TTrezor> {
  constructor(
    host: KeyringHost,
    options: KeyringOptions,
    createHardware: () => KeyringHardware<TLedger, TTrezor>
  ) {
    if (typeof createHardware !== 'function')
      throw new TypeError('Keyring requires explicit hardware capabilities');
    const { binding, publishControls } = prepareKeyringHost(host, options);
    const hardware = createHardware();
    if (
      !hardware ||
      !('ledgerSigner' in hardware) ||
      !('trezorSigner' in hardware)
    )
      throw new TypeError('Keyring requires explicit hardware capabilities');
    super(binding, hardware);
    publishControls?.();
  }

  /** Derive runtime state using the shared software account implementation. */
  public deriveEvmHdRuntimeAccount(
    request: EvmHdRuntimeAccountRequest,
    options: EvmHdRuntimeAccountOptions
  ): Promise<EncryptedEvmHdRuntimeAccount> {
    return this.deriveSoftwareEvmHdRuntimeAccount(request, options);
  }

  /** Sign the prepared software envelope; the host retains it before broadcast. */
  public signPreparedEvmTransaction(
    request: PreparedSoftwareEvmSigningRequest,
    options: PreparedEvmSigningOptions
  ): SignedPreparedEvmTransaction {
    return this.signPreparedSoftwareEvmTransaction(request, options);
  }
}

export { createKeyringHost } from './keyring-host';
export type { KeyringHost, KeyringOptions } from './keyring-host';
export type {
  KeyringHardware,
  KeyringLedgerSigner,
  KeyringTrezorSigner,
  PreparedSessionTransfer,
} from './keyring-core';

export type {
  SecretOperationCredentialPort,
  SecretOperationOptions,
} from './keyring-core';
export type { SecretLifetimePolicy } from './keyring-host';

export type {
  PublicSessionCheckpointRequest,
  PublicSessionCredentialPort,
  PublicSessionRestoreRequest,
} from './public-session';
export { MAX_PUBLIC_SESSION_STATE_BYTES } from './public-session';
