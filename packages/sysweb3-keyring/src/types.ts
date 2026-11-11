import {
  TypedDataV1,
  TypedMessage,
  SignTypedDataVersion,
} from '@metamask/eth-sig-util';
import { INetwork, INetworkType } from '@sidhujag/sysweb3-network';
import { ITxid } from '@sidhujag/sysweb3-utils';
import { CustomJsonRpcProvider } from 'providers';

import {
  BigNumber,
  BigNumberish,
  BytesLike,
  TransactionResponse,
} from './ethers-v6';
import { LedgerKeyring } from './ledger';
import {
  IPrivateRecordAccess,
  PrivateRecordAccessOptions,
  IDecryptPrivateRecordParams,
  IEncryptedPrivateRecord,
  IEncryptPrivateRecordParams,
} from './private-records';
import { SyscoinHDSigner } from './signers';
import { TrezorKeyring } from './trezor';

import type { KeyringCore, PreparedSessionTransfer } from './keyring-core';
import type { PreparedEvmTransaction } from './transactions/evm-envelope';
import type { OwnedUtxoRpcVerification } from '@sidhujag/sysweb3-network';

export type AccessListish =
  | Array<{ address: string; storageKeys: string[] }>
  | Array<[string, string[]]>
  | Record<string, string[]>;

export type SimpleTransactionRequest = {
  accessList?: AccessListish;
  ccipReadEnabled?: boolean;
  chainId: number;
  customData?: Record<string, any>;
  data?: BytesLike;

  from: string;
  gasLimit?: BigNumberish;
  gasPrice?: BigNumberish;

  maxFeePerGas: BigNumberish;
  maxPriorityFeePerGas: BigNumberish;

  nonce?: BigNumberish;
  r?: string;

  s?: string;
  to: string;
  type?: number;
  v?: string;
  value?: BigNumberish;
};

export type EvmLocalAccount = {
  address: string;
  privateKey: string;
  publicKey: string;
};

export type EvmWalletNonce = Readonly<{
  nonce: number;
  source: 'automatic' | 'manual';
}>;

export interface IEvmSendOptions {
  selectedAccount: import('./transactions/prepared-evm').EvmSigningIdentity;
  targetAccount: import('./transactions/prepared-evm').EvmSigningIdentity;
  /** Synchronous host admission, rechecked immediately before signing and broadcast. */
  assertCurrent: () => void;
  mode: 'reviewed-native' | 'reviewed-generic' | 'specialized';
  walletNonce?: EvmWalletNonce;
}

export type EvmFormattedSendArguments =
  | [
      approvedTransaction: PreparedEvmTransaction,
      isLegacy: boolean | undefined,
      options: IEvmSendOptions & {
        mode: 'reviewed-generic';
        reviewId: string;
        walletNonce: EvmWalletNonce;
      }
    ]
  | [
      approvedTransaction: PreparedEvmTransaction,
      isLegacy: boolean | undefined,
      options: IEvmSendOptions & { mode: 'reviewed-native' }
    ]
  | [
      transaction: SimpleTransactionRequest,
      isLegacy: boolean | undefined,
      options: IEvmSendOptions & { mode: 'specialized' }
    ];

export type EvmReplacementFeeApproval =
  | { previewOnly: true; approvedMaximumFee?: never }
  | { previewOnly?: false; approvedMaximumFee: string };

type EvmOriginalAdmission<Original> = {
  /** Select a distinct locally controlled gas payer for a smart account. */
  targetAccount?: { id: number; type: KeyringAccountType };
  /** Synchronous host guard for the current account, network, session and pending original. */
  assertCurrentContext: () => void;
  /** Receives authenticated signed fields. Null requires explicit cancellation fallback admission. */
  validateOriginal: (transaction: Original) => void;
};

export type IEvmReplacementOptions = EvmReplacementFeeApproval &
  EvmOriginalAdmission<TransactionResponse> & {
    beforeBroadcast?: () => void;
    /** Exact signed original obtained from the host's protected cancellation lineage. */
    retainedCancellation?: string;
  };

export type EvmRetainedCancellationOrigin = Readonly<{
  kind: 'retained';
  rawTransaction: string;
  nonce: number;
  tipHash: string;
  feeFloor: Readonly<
    | { type: 0; gasPrice: bigint }
    | { type: 2; maxFeePerGas: bigint; maxPriorityFeePerGas: bigint }
  >;
}>;

export type IEvmCancellationOptions = EvmReplacementFeeApproval &
  (
    | (EvmOriginalAdmission<TransactionResponse | null> & { origin?: never })
    | (Omit<EvmOriginalAdmission<never>, 'validateOriginal'> & {
        /** The host owns the protected journal lineage and its live admission. */
        origin: EvmRetainedCancellationOrigin;
        validateOriginal?: never;
      })
  );

// Version type is now replaced by SignTypedDataVersion from @metamask/eth-sig-util

export interface IEthereumTransactions {
  cancelSentTransaction: (
    txHash: string,
    isLegacy: boolean | undefined,
    fallbackNonce: number | undefined,
    options: IEvmCancellationOptions
  ) => Promise<{
    error?: boolean;
    isCanceled: boolean;
    transactionNotBroadcast?: boolean;
    signedTransactionHash?: string;
    maximumFee?: string;
    transaction?: TransactionResponse;
  }>;
  decryptMessage: (msgParams: string[]) => string;
  ethSign: (
    params: string[],
    options: import('./transactions/prepared-evm').EvmDigestSignOptions
  ) => Promise<string>;
  signPreparedEvmTransaction: (
    request: import('./transactions/prepared-evm').PreparedSoftwareEvmSigningRequest,
    options: import('./transactions/prepared-evm').PreparedEvmSigningOptions
  ) => import('./transactions/prepared-evm').SignedPreparedEvmTransaction;
  getBalance: (address: string) => Promise<number>;
  getEncryptedPubKey: () => string;
  getErc20TokensByAddress?: (
    address: string,
    isSupported: boolean,
    apiUrl: string
  ) => Promise<any[]>;
  getFeeByType: (type: string) => Promise<string>;
  getFeeDataWithDynamicMaxPriorityFeePerGas: (
    provider?: CustomJsonRpcProvider
  ) => Promise<any>;
  getGasLimit: (toAddress: string) => Promise<number>;
  getGasOracle?: () => Promise<any>;
  getRecommendedNonce: (address: string) => Promise<number>;
  signTypedData: (
    addr: string,
    typedData: TypedDataV1 | TypedMessage<any>,
    version: SignTypedDataVersion,
    authority: import('./hardware-transaction-authority').HardwareTransactionAuthority
  ) => Promise<string>;

  importAccount: (mnemonicOrPrivKey: string) => EvmLocalAccount;
  parsePersonalMessage: (hexMsg: string) => string;
  sendFormattedTransaction: (
    ...args: EvmFormattedSendArguments
  ) => Promise<TransactionResponse>;
  sendSignedErc1155Transaction: (
    params: ISendSignedErc1155TransactionProps,
    approval: IReviewedEvmTokenApproval
  ) => Promise<IResponseFromSendErcSignedTransaction>;
  verifyPersonalMessage: (msg: string, sign: string) => string;
  toBigNumber: (aBigNumberish: string | number) => BigNumber;
  sendSignedErc20Transaction: (
    params: ISendSignedErc20TransactionProps,
    approval: IReviewedEvmTokenApproval
  ) => Promise<IResponseFromSendErcSignedTransaction>;

  sendSignedErc721Transaction: (
    params: ISendSignedErc721TransactionProps,
    approval: IReviewedEvmTokenApproval
  ) => Promise<IResponseFromSendErcSignedTransaction>;

  sendTransactionWithEditedFee: (
    txHash: string,
    isLegacy: boolean | undefined,
    options: IEvmReplacementOptions
  ) => Promise<{
    maximumFee?: string;
    isSpeedUp: boolean;
    transactionNotBroadcast?: boolean;
    signedTransactionHash?: string;
    transaction?: TransactionResponse;
    error?: boolean;
  }>;

  signPersonalMessage: (
    params: string[],
    authority: import('./hardware-transaction-authority').HardwareTransactionAuthority
  ) => Promise<string>;
  verifyTypedSignature: (
    data: TypedDataV1 | TypedMessage<any>,
    signature: string,
    version: SignTypedDataVersion
  ) => string;
  // HW-agnostic helper: verify and display UTXO address on device
  verifyUtxoAddress: (
    accountIndex: number,
    currency: string,
    slip44: number
  ) => Promise<string | undefined>;
  setWeb3Provider: (network: INetwork) => void;
  getRecommendedGasPrice: (formatted?: boolean) => Promise<
    | string
    | {
        ethers: string;
        gwei: string;
      }
  >;
  web3Provider: CustomJsonRpcProvider;
  getTxGasLimit: (tx: SimpleTransactionRequest) => Promise<BigNumber>;
}

export interface ISyscoinTransactionFeeQuote {
  fee: number;
  psbt: any;
  /** Exact decimal SYS amounts, present only for an explicit native sweep. */
  grossAmount?: string;
  recipientAmount?: string;
}

/** A trusted wallet host owns the lifetime and HTTP policy of these reads. */
export type SyscoinOwnedReadOptions = Readonly<{
  assertCurrent: () => void;
  fetch: typeof globalThis.fetch;
  signal: AbortSignal;
}>;

/** Exact signed bytes presented to a wallet host before the only POST. */
export type SyscoinSubmissionDescriptor = Readonly<{
  rawTransaction: string;
  txid: string;
  url: string;
}>;

export type SyscoinOwnedSubmissionOptions = SyscoinOwnedReadOptions &
  Readonly<{
    prepare: (descriptor: SyscoinSubmissionDescriptor) => Promise<void>;
  }>;

export type SyscoinRetainedSubmissionOwner = Readonly<{
  account: Readonly<{ id: number; type: string; xpub: string }>;
  chainId: number;
  genesisHash: string;
  slip44: number;
}>;

export type SyscoinRetainedSubmission = SyscoinSubmissionDescriptor &
  Readonly<{ owner: SyscoinRetainedSubmissionOwner }>;

/** The trusted wallet host reads the authenticated journal, not a UI payload. */
export type SyscoinRetainedSubmissionOptions = SyscoinOwnedSubmissionOptions &
  Pick<OwnedUtxoRpcVerification, 'readJson'> &
  Readonly<{
    readRetained: (
      owner: SyscoinRetainedSubmissionOwner,
      txid: string
    ) => Promise<SyscoinRetainedSubmission | undefined>;
  }>;

export interface ISyscoinTransactions {
  getEstimateSysTransactionFee: (
    {
      txOptions,
      amount,
      receivingAddress,
      feeRate,
      token,
      isMax,
      nativeSweep,
      excludedOutpoints,
    }: {
      amount: number | string;
      feeRate?: number;
      receivingAddress: string;
      token?: { guid: string; symbol?: string } | null;
      txOptions?: any;
      isMax?: boolean | false;
      /** Resolve explicit native MAX from one current funding snapshot. Requires isMax and token:null. */
      nativeSweep?: boolean;
      /** Coin-control exclusions supplied by a trusted wallet policy, not transaction outputs. */
      excludedOutpoints?: readonly { txid: string; vout: number }[];
    },
    ownedRead: SyscoinOwnedReadOptions
  ) => Promise<ISyscoinTransactionFeeQuote>; // Returns UNSIGNED psbt - may throw ISyscoinTransactionError
  getRecommendedFee: (
    explorerUrl: string,
    ownedRead: SyscoinOwnedReadOptions
  ) => Promise<number>;
  decodeRawTransaction: (psbtOrHex: any, isRawHex?: boolean) => any;
  // Sign PSBT separately
  sendTransaction: (
    rawTransaction: string,
    authority: SyscoinOwnedSubmissionOptions
  ) => Promise<ITxid>;
  replayRetainedTransaction: (
    txid: string,
    authority: SyscoinRetainedSubmissionOptions
  ) => Promise<ITxid>;
  /** Resolve public signing paths before entering an operation-scoped lease. */
  preparePSBTForSigning: (
    input: { psbt: any },
    ownedRead: SyscoinOwnedReadOptions
  ) => Promise<any>;
  signPSBT: (
    {
      psbt,
      isTrezor,
      isLedger,
    }: {
      isLedger?: boolean;
      isTrezor?: boolean;
      psbt: any;
    },
    ownedRead: SyscoinOwnedReadOptions
  ) => Promise<any>;
}

export interface IKeyringManager {
  // Core keyring functionality
  addNewAccount: (label?: string) => Promise<IKeyringAccountState>;
  createSmartAccount: (
    params: ICreateSmartAccountParams
  ) => Promise<IKeyringAccountState>;
  ethereumTransaction: IEthereumTransactions;
  forgetMainWallet: (pwd: string) => void;
  getAccountById: (
    id: number,
    accountType: KeyringAccountType
  ) => Omit<IKeyringAccountState, 'xprv'>;
  getAccountXpub: () => string;
  getEncryptedXprv: (hd: SyscoinHDSigner) => string;
  unlock: (
    password: string,
    isForPvtKey?: boolean
  ) => Promise<{
    canLogin: boolean;
    needsAccountCreation?: boolean;
  }>;
  isUnlocked: () => boolean;
  captureUnlockedSessionGuard: () => () => void;
  logout: () => void;
  ledgerSigner: LedgerKeyring;
  trezorSigner: TrezorKeyring;
  setSignerNetwork: (network: INetwork) => Promise<{
    success: boolean;
  }>;
  getPrivateKeyByAccountId: (
    id: number,
    accountType: KeyringAccountType,
    pwd: string
  ) => Promise<string>;
  syscoinTransaction: ISyscoinTransactions;
  isSeedValid: (seedPhrase: string) => boolean;
  getSeed: (pwd: string) => Promise<string>;
  createPublicSessionCheckpoint: (
    input: import('./public-session').PublicSessionCheckpointRequest,
    wrappingKey: Uint8Array,
    assertCurrent: () => void
  ) => Promise<import('./private-records').IEncryptedPrivateRecord>;
  restorePublicSession: <T>(
    credential: import('./public-session').PublicSessionCredentialPort,
    input: import('./public-session').PublicSessionRestoreRequest,
    options: import('./keyring-core').SecretOperationOptions,
    work: (authenticatedPublicState: Uint8Array) => T | Promise<T>
  ) => Promise<T>;
  createPrivateRecordAccess: (
    domains: readonly string[],
    options: PrivateRecordAccessOptions
  ) => Promise<IPrivateRecordAccess>;
  getPrivateRecordAccess: (domains: readonly string[]) => IPrivateRecordAccess;
  getPrivateRecordProfileId: () => Promise<string>;
  encryptPrivateRecord: (
    params: IEncryptPrivateRecordParams
  ) => Promise<IEncryptedPrivateRecord>;
  decryptPrivateRecord: (
    params: IDecryptPrivateRecordParams
  ) => Promise<Uint8Array>;
  deriveSLHDSASetupSecretForAccount: (params: {
    accountIndex: number;
  }) => Promise<{
    derivationLabel: string;
    setupSecretHex: string;
  }>;
  decryptSLHDSASessionState: (cipherText: string) => string;
  encryptSLHDSASessionState: (plainText: string) => string;
  importTrezorAccount: (label?: string) => Promise<IKeyringAccountState>;
  utf8Error: boolean;
  validateZprv: (
    zprv: string,
    targetNetwork?: INetwork
  ) => IValidateZprvResponse;
  validateWif: (
    wif: string,
    targetNetwork?: INetwork
  ) => { isValid: boolean; message?: string };
  // Account management
  importAccount: (
    privKey: string,
    label?: string,
    options?: { utxoAddressType?: 'p2wpkh' | 'p2pkh' }
  ) => Promise<IKeyringAccountState>;
  getNewChangeAddress: (ownedRead: SyscoinOwnedReadOptions) => Promise<string>;
  getChangeAddress: (
    id: number,
    ownedRead: SyscoinOwnedReadOptions
  ) => Promise<string>;
  getPubkey: (
    id: number,
    isChangeAddress: boolean,
    ownedRead: SyscoinOwnedReadOptions
  ) => Promise<string>;
  getBip32Path: (
    id: number,
    isChangeAddress: boolean,
    ownedRead: SyscoinOwnedReadOptions
  ) => Promise<string>;
  updateReceivingAddress: (
    ownedRead: SyscoinOwnedReadOptions
  ) => Promise<string>;
  getActiveAccount: () => {
    activeAccount: Omit<IKeyringAccountState, 'xprv'>;
    activeAccountType: KeyringAccountType;
  };
  importWeb3Account: (mnemonicOrPrivKey: string) => any;
  createNewSeed: (wordCount?: number) => string;
  getUTXOState: () => any;
  importLedgerAccount: (
    label?: string
  ) => Promise<IKeyringAccountState | undefined>;
  getActiveUTXOAccountState: () => any;
  createEthAccount: (privateKey: string) => any;
  getAddress: (
    xpub: string,
    isChangeAddress: boolean,
    ownedRead: SyscoinOwnedReadOptions
  ) => Promise<string>;
  // Secure initialization and password management
  initializeWalletSecurely: (
    seedPhrase: string,
    password: string,
    prvPassword?: string
  ) => Promise<IKeyringAccountState>;
  // NEW: Separated initialization methods
  initializeSession: (seedPhrase: string, password: string) => Promise<void>;
  createFirstAccount: (label?: string) => Promise<IKeyringAccountState>;
  prepareSessionTransfer: (
    targetKeyring: KeyringCore,
    assertCurrent: () => void
  ) => Promise<PreparedSessionTransfer>;
  lockWallet: () => Promise<void>;
  // NEW: Store access for stateless keyring
  setVaultStateGetter: (getter: () => any) => void;
}

export enum KeyringAccountType {
  HDAccount = 'HDAccount',
  Imported = 'Imported',
  Ledger = 'Ledger',
  SmartAccount = 'SmartAccount',
  Trezor = 'Trezor',
}

export enum PasskeyBackupStatus {
  BackupCapable = 'backupCapable',
  DeviceBound = 'deviceBound',
  Synced = 'synced',
  Unavailable = 'unavailable',
}

export interface IPasskeyCredentialProfile {
  backupStatus?: PasskeyBackupStatus;
  credentialId: string;
  credentialIdHash: string;
  passkeyName: string;
  publicKey: {
    originHash: string;
    originLength: number;
    rpIdHash: string;
    x: string;
    y: string;
  };
}

export interface ICreateSmartAccountParams<TSmartAccountMetadata = any> {
  address?: string;
  deriveAccount?: (accountIndex: number) => Promise<{
    address: string;
    metadata: TSmartAccountMetadata;
  }>;
  label?: string;
  metadata?: TSmartAccountMetadata;
}

export type IKeyringDApp = {
  active: boolean;
  id: number;
  url: string;
};

export type accountType = {
  [id: number]: IKeyringAccountState;
};

export type IKeyringBalances = {
  [INetworkType.Syscoin]: number;
  [INetworkType.Ethereum]: number;
};

interface INetworkParams {
  bech32: string;
  bip32: {
    private: number;
    public: number;
  };
  messagePrefix: string;
  pubKeyHash: number;
  scriptHash: number;
  slip44: number;
  wif: number;
}

interface IValidateZprvResponse {
  isValid: boolean;
  message: string;
  network?: INetworkParams | null;
  node?: any;
}

export interface IKeyringAccountState<TSmartAccountMetadata = any> {
  address: string;
  balances: IKeyringBalances;
  id: number;
  isImported: boolean;
  isLedgerWallet: boolean;
  isSmartAccount?: boolean;
  isTrezorWallet: boolean;
  label: string;
  smartAccount?: TSmartAccountMetadata;
  xprv: string;
  xpub: string;
}

export interface ISyscoinBackendAccount {
  address: string;
  balance: string;
  itemsOnPage: number;
  page: number;
  totalPages: number;
  totalReceived: string;
  totalSent: string;
  txs: number;
  unconfirmedBalance: string;
  unconfirmedTxs: number;
}

export interface ILatestUpdateForSysAccount {
  balances: {
    ethereum: number;
    syscoin: number;
  };
  receivingAddress: any;
  xpub: any;
}

export type IReviewedEvmTokenApproval = Readonly<{
  /** Nonce selected by the host's ordinary wallet policy before signing. */
  nonce: number;
  assertCurrent: () => void;
  signal: AbortSignal;
}>;

export type IReviewedEvmTokenFees = { gasLimit: BigNumberish } & (
  | {
      isLegacy: true;
      gasPrice: BigNumberish;
      maxFeePerGas?: never;
      maxPriorityFeePerGas?: never;
    }
  | {
      isLegacy: false;
      maxFeePerGas: BigNumberish;
      maxPriorityFeePerGas: BigNumberish;
      gasPrice?: never;
    }
);

type ISendReviewedTokenBase = IReviewedEvmTokenFees & {
  networkUrl: string;
  receiver: string;
  tokenAddress: string;
};

/** Integer amounts and token identifiers are canonical uint256 strings. */
export type ISendSignedErc20TransactionProps = ISendReviewedTokenBase & {
  tokenAmountUnits: string;
  saveTrezorTx?: (tx: any) => void;
};
export type ISendSignedErc721TransactionProps = ISendReviewedTokenBase & {
  tokenId: string;
};
export type ISendSignedErc1155TransactionProps =
  ISendSignedErc721TransactionProps & {
    tokenAmount: string;
  };

export interface IResponseFromSendErcSignedTransaction {
  accessList: any[];
  chainId: number;
  confirmations: number | null;
  data: string;
  from: string;
  gasLimit: BigNumber;
  gasPrice: BigNumber | null;
  hash: string;
  maxFeePerGas: BigNumber;
  maxPriorityFeePerGas: BigNumber;
  nonce: number;
  r: string;
  s: string;
  to: string;
  type: number;
  v: number | null;
  value: BigNumber;
  wait: any;
}

export interface IGasParams {
  gasLimit?: BigNumber;
  gasPrice?: BigNumber;
  maxFeePerGas?: BigNumber;
  maxPriorityFeePerGas?: BigNumber;
}
