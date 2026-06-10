import * as syscoinjs from 'syscoinjs-lib';

// import { web3Provider } from '@sidhujag/sysweb3-network';

// Short-TTL cache + in-flight dedup for Blockbook /api/v2/tx lookups.
// The fields consumers rely on (hex, vin/vout) are immutable per txid, but the
// response also carries mutable fields (confirmations), so entries expire
// quickly instead of being cached forever.
const RAW_TX_CACHE_TTL_MS = 60_000;
const RAW_TX_CACHE_MAX_ENTRIES = 100;
const rawTxCache = new Map<
  string,
  { promise: Promise<any>; timestamp: number }
>();

const getRawTransactionCached = (
  explorerUrl: string,
  txid: string
): Promise<any> => {
  const key = `${explorerUrl}::${txid}`;
  const now = Date.now();

  const cached = rawTxCache.get(key);
  if (cached && now - cached.timestamp < RAW_TX_CACHE_TTL_MS) {
    return cached.promise;
  }

  if (!rawTxCache.has(key) && rawTxCache.size >= RAW_TX_CACHE_MAX_ENTRIES) {
    const oldestKey = rawTxCache.keys().next().value;
    if (oldestKey !== undefined) {
      rawTxCache.delete(oldestKey);
    }
  }

  const promise = Promise.resolve(
    syscoinjs.utils.fetchBackendRawTx(explorerUrl, txid)
  );
  rawTxCache.set(key, { promise, timestamp: now });

  // Never cache failures or empty responses (e.g. tx not indexed yet) -
  // the next caller should retry
  const dropEntry = () => {
    const entry = rawTxCache.get(key);
    if (entry && entry.promise === promise) {
      rawTxCache.delete(key);
    }
  };
  promise.then((value) => {
    if (value === null || value === undefined) {
      dropEntry();
    }
  }, dropEntry);

  return promise;
};

export const clearRawTransactionCache = () => {
  rawTxCache.clear();
};

export const txUtils = () => {
  const getRawTransaction = (explorerUrl: string, txid: string) =>
    getRawTransactionCached(explorerUrl, txid);

  return {
    getRawTransaction,
    // getGasUsedInTransaction,
  };
};

export type ISyscoinVIn = {
  addresses: string[];
  isAddress: boolean;
  n: number;
  sequence: number;
  txid: string;
  value: number;
  vout: number;
};

export type ISyscoinVOut = {
  addresses: string[];
  hex: string;
  isAddress: boolean;
  n: number;
  spent: boolean;
  value: number;
};

export type ISyscoinTokenTxInfo = {
  tokenId: string;
  value: number;
  valueStr: string;
};

export type ISyscoinTransaction = {
  [txid: string]: {
    blockHash: string;
    blockHeight: number;
    blockTime: number;
    confirmations: number;
    fees: number;
    hex: string;
    tokenType: string;
    txid: string;
    value: number;
    valueIn: number;
    version: number;
    vin: ISyscoinVIn[];
    vout: ISyscoinVOut[];
  };
};

export type ITxid = { txid: string };

export type IETHTxConfig = {
  gasLimit?: number;
  gasPrice: number;
  memo?: string;
  nonce?: number;
  txData?: string;
};

export type IETHNetwork = 'testnet' | 'mainnet';

export interface IETHPendingTx {
  amount: string;
  assetId: string;
  data?: string;
  fromAddress: string;
  gasPrice: number;
  network: IETHNetwork;
  nonce: number;
  onConfirmed?: () => void;
  timestamp: number;
  toAddress: string;
  txHash: string;
}
