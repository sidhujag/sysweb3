/** Software-only entry: explicit host storage, no browser/device initialization. */
import { HostKeyring } from './host-keyring';

import type { KeyringHost, KeyringOptions } from './keyring-host';

export class SoftwareKeyring extends HostKeyring<undefined, undefined> {
  constructor(host: KeyringHost, options: KeyringOptions) {
    super(host, options, () => ({
      ledgerSigner: undefined,
      trezorSigner: undefined,
    }));
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
  EvmRetainedCancellationOrigin,
  IKeyringAccountState,
  SyscoinOwnedReadOptions,
  SyscoinOwnedSubmissionOptions,
  SyscoinSubmissionDescriptor,
} from './types';

export type {
  EvmAccessList,
  PreparedEvmTransaction,
} from './transactions/evm-envelope';
export type {
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

export type {
  SecretOperationCredentialPort,
  SecretOperationOptions,
} from './keyring-core';
export type { SecretLifetimePolicy } from './keyring-host';

export type {
  IPrivateRecordAccess,
  PrivateRecordAccessOptions,
} from './private-records';

export type {
  PublicSessionCheckpointRequest,
  PublicSessionCredentialPort,
  PublicSessionRestoreRequest,
} from './public-session';
export { MAX_PUBLIC_SESSION_STATE_BYTES } from './public-session';
