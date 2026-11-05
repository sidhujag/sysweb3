/** Software-only entry: explicit host storage, no browser/device initialization. */
import { KeyringCore } from './keyring-core';
import { prepareKeyringHost } from './keyring-host';

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

export class SoftwareKeyring extends KeyringCore<undefined, undefined> {
  constructor(host: KeyringHost, options: KeyringOptions) {
    const { binding, publishControls } = prepareKeyringHost(host, options);
    super(binding, {
      ledgerSigner: undefined,
      trezorSigner: undefined,
    });
    publishControls?.();
  }

  /**
   * Derive a fixed-path Ethereum HD runtime account without network or storage
   * writes. The returned password-encrypted xprv is internal runtime state,
   * never a public account/catalogue DTO. The host owns index allocation.
   */
  public deriveEvmHdRuntimeAccount(
    request: EvmHdRuntimeAccountRequest,
    options: EvmHdRuntimeAccountOptions
  ): Promise<EncryptedEvmHdRuntimeAccount> {
    return this.deriveSoftwareEvmHdRuntimeAccount(request, options);
  }

  /**
   * Sign exactly the prepared envelope without RPC, fee/nonce discovery or
   * broadcasting. The host must journal the result before submitting it.
   * A later lock cannot revoke already returned signed bytes.
   */
  public signPreparedEvmTransaction(
    request: PreparedSoftwareEvmSigningRequest,
    options: PreparedEvmSigningOptions
  ): SignedPreparedEvmTransaction {
    return this.signPreparedSoftwareEvmTransaction(request, options);
  }

  public static async createInitialized(
    host: KeyringHost,
    seed: string,
    password: string,
    vaultStateGetter: () => any,
    options: KeyringOptions
  ): Promise<SoftwareKeyring> {
    const keyring = new SoftwareKeyring(host, options);
    keyring.setVaultStateGetter(vaultStateGetter);
    await keyring.initializeWalletSecurely(seed, password);
    return keyring;
  }
}

export { createKeyringHost } from './keyring-host';
export type { KeyringHost, KeyringOptions } from './keyring-host';
export { KeyringAccountType } from './types';
export { INetworkType } from '@sidhujag/sysweb3-network';
export type { INetwork } from '@sidhujag/sysweb3-network';
export type {
  DeviceUnlockControls,
  DeviceUnlockCredential,
  DeviceUnlockPort,
  DeviceUnlockVaultPair,
  KeyringStoragePort,
} from './keyring-core';
export type {
  IKeyringAccountState,
  SyscoinOwnedReadOptions,
  SyscoinOwnedSubmissionOptions,
  SyscoinSubmissionDescriptor,
} from './types';

export type {
  PreparedEvmTransaction,
  PreparedEvmSigningOptions,
  PreparedSoftwareEvmSigningRequest,
  SignedPreparedEvmTransaction,
} from './transactions/prepared-evm';

export type {
  EncryptedEvmHdRuntimeAccount,
  EvmHdRuntimeAccountOptions,
  EvmHdRuntimeAccountRequest,
} from './software-hd-account';

export {
  captureEvmSubmission,
  submitSignedEvmTransaction,
  evmSubmissionFailure,
} from './transactions/evm-submission';
export type {
  CaptureEvmSubmission,
  EvmSubmissionContext,
  EvmSubmissionLifecycle,
  EvmSignedSubmission,
  EvmSubmissionBoundary,
} from './transactions/evm-submission';
