import { TransactionResponse } from '@ethersproject/abstract-provider';
import { BigNumber, BigNumberish } from '@ethersproject/bignumber';
import { BytesLike } from '@ethersproject/bytes';
import { AccessListish } from '@ethersproject/transactions';
import { Wallet } from '@ethersproject/wallet';
import {
  TypedDataV1,
  TypedMessage,
  SignTypedDataVersion,
} from '@metamask/eth-sig-util';
import { INetwork, INetworkType } from '@sidhujag/sysweb3-network';
import { ITxid } from '@sidhujag/sysweb3-utils';
import { CustomJsonRpcProvider } from 'providers';

import { LedgerKeyring } from './ledger';
import { SyscoinHDSigner } from './signers';
import { TrezorKeyring } from './trezor';

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

// Version type is now replaced by SignTypedDataVersion from @metamask/eth-sig-util

export interface IEthereumTransactions {
  cancelSentTransaction: (
    txHash: string,
    isLegacy?: boolean,
    fallbackNonce?: number
  ) => Promise<{
    error?: boolean;
    isCanceled: boolean;
    transaction?: TransactionResponse;
  }>;
  decryptMessage: (msgParams: string[]) => string;
  ethSign: (params: string[]) => Promise<string>;
  getBalance: (address: string) => Promise<number>;
  getEncryptedPubKey: () => string;
  getErc20TokensByAddress?: (
    address: string,
    isSupported: boolean,
    apiUrl: string
  ) => Promise<any[]>;
  getFeeByType: (type: string) => Promise<string>;
  getFeeDataWithDynamicMaxPriorityFeePerGas: () => Promise<any>;
  getGasLimit: (toAddress: string) => Promise<number>;
  getGasOracle?: () => Promise<any>;
  getRecommendedNonce: (address: string) => Promise<number>;
  signTypedData: (
    addr: string,
    typedData: TypedDataV1 | TypedMessage<any>,
    version: SignTypedDataVersion
  ) => Promise<string>;

  importAccount: (mnemonicOrPrivKey: string) => Wallet;
  parsePersonalMessage: (hexMsg: string) => string;
  sendFormattedTransaction: (
    params: SimpleTransactionRequest,
    isLegacy?: boolean
  ) => Promise<TransactionResponse>;
  sendSignedErc1155Transaction: ({
    receiver,
    tokenAddress,
    tokenId,
    isLegacy,
    gasPrice,
    gasLimit,
    maxFeePerGas,
    maxPriorityFeePerGas,
  }: ISendSignedErcTransactionProps) => Promise<IResponseFromSendErcSignedTransaction>;
  verifyPersonalMessage: (msg: string, sign: string) => string;
  toBigNumber: (aBigNumberish: string | number) => BigNumber;
  sendSignedErc20Transaction: ({
    networkUrl,
    receiver,
    tokenAddress,
    tokenAmount,
  }: ISendSignedErcTransactionProps) => Promise<IResponseFromSendErcSignedTransaction>;

  sendSignedErc721Transaction: ({
    networkUrl,
    receiver,
    tokenAddress,
    tokenId,
  }: ISendSignedErcTransactionProps) => Promise<IResponseFromSendErcSignedTransaction>;

  sendTransactionWithEditedFee: (
    txHash: string,
    isLegacy?: boolean
  ) => Promise<{
    isSpeedUp: boolean;
    transaction?: TransactionResponse;
    error?: boolean;
  }>;

  signPersonalMessage: (params: string[]) => Promise<string>;
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

export interface ISyscoinTransactions {
  getEstimateSysTransactionFee: ({
    txOptions,
    amount,
    receivingAddress,
    feeRate,
    token,
    isMax,
  }: {
    amount: number;
    feeRate?: number;
    receivingAddress: string;
    token?: { guid: string; symbol?: string } | null;
    txOptions?: any;
    isMax?: boolean | false;
  }) => Promise<{ fee: number; psbt: any }>; // Returns UNSIGNED psbt - may throw ISyscoinTransactionError
  getRecommendedFee: (explorerUrl: string) => Promise<number>;
  decodeRawTransaction: (psbtOrHex: any, isRawHex?: boolean) => any;
  // Sign PSBT separately
  sendTransaction: (psbt: any) => Promise<ITxid>;
  signPSBT: ({
    psbt,
    isTrezor,
    isLedger,
  }: {
    isLedger?: boolean;
    isTrezor?: boolean;
    psbt: any;
  }) => Promise<any>;
}

export interface IKeyringManager {
  // Core keyring functionality
  addNewAccount: (label?: string) => Promise<IKeyringAccountState>;
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
  setStorage: (client: any) => void;
  syscoinTransaction: ISyscoinTransactions;
  isSeedValid: (seedPhrase: string) => boolean;
  getSeed: (pwd: string) => Promise<string>;
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
  getNewChangeAddress: () => Promise<string>;
  getChangeAddress: (id: number) => Promise<string>;
  getPubkey: (id: number, isChangeAddress: boolean) => Promise<string>;
  getBip32Path: (id: number, isChangeAddress: boolean) => Promise<string>;
  updateReceivingAddress: () => Promise<string>;
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
  getAddress: (xpub: string, isChangeAddress: boolean) => Promise<string>;
  // Secure initialization and password management
  initializeWalletSecurely: (
    seedPhrase: string,
    password: string,
    prvPassword?: string
  ) => Promise<IKeyringAccountState>;
  // NEW: Separated initialization methods
  initializeSession: (seedPhrase: string, password: string) => Promise<void>;
  createFirstAccount: (label?: string) => Promise<IKeyringAccountState>;
  transferSessionTo: (targetKeyring: IKeyringManager) => void;
  receiveSessionOwnership: (sessionPassword: any, sessionMnemonic: any) => void;
  lockWallet: () => Promise<void>;
  // NEW: Store access for stateless keyring
  setVaultStateGetter: (getter: () => any) => void;
}

export enum KeyringAccountType {
  HDAccount = 'HDAccount',
  Imported = 'Imported',
  Ledger = 'Ledger',
  Trezor = 'Trezor',
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

export interface IKeyringAccountState {
  address: string;
  balances: IKeyringBalances;
  id: number;
  isImported: boolean;
  isLedgerWallet: boolean;
  isTrezorWallet: boolean;
  label: string;
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

export interface ISendSignedErcTransactionProps {
  decimals?: number;
  gasLimit?: BigNumberish;
  gasPrice?: BigNumberish;
  isLegacy?: boolean;
  maxFeePerGas?: BigNumberish;
  maxPriorityFeePerGas?: BigNumberish;
  networkUrl: string;
  receiver: string;
  saveTrezorTx?: (tx: any) => void;
  tokenAddress: string;
  tokenAmount?: string;
  tokenId?: number;
}

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
