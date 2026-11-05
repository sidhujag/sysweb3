import {
  findUtxoCoinByRegistration,
  getCoinNameVariations,
} from './coin-utils';
import { coins } from './coins';

export type OwnedUtxoRpcVerification = Readonly<{
  registration: Readonly<{ chainId: number; slip44: number }>;
  /** Expected from a trusted registration profile, before reading the endpoint. */
  backendChain: string;
  signal: AbortSignal;
  /** Synchronous guard for the same registration draft and request owner. */
  assertCurrent: () => void;
  /** Owns bounded GET/JSON reads, exact response URLs, redirects and credentials. */
  readJson: (url: string, signal: AbortSignal) => Promise<unknown>;
}>;

const INVALID = 'Invalid UTXO registration verification';
const MISMATCH = 'UTXO registration does not match the selected coin';
const CANCELLED = 'UTXO registration verification cancelled';

function field(value: unknown, name: string): unknown {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new Error(INVALID);
  const own = Object.getOwnPropertyDescriptor(value, name);
  if (!own) return undefined;
  if (!('value' in own)) throw new Error(INVALID);
  return own.value;
}

function statusName(value: unknown): string {
  if (
    typeof value !== 'string' ||
    !value.length ||
    value.length > 128 ||
    /[^ -~]/.test(value)
  )
    throw new Error(INVALID);
  return value.toLowerCase();
}

export async function verifyOwnedUtxoRpc(
  url: string,
  owner: OwnedUtxoRpcVerification
) {
  const registration = owner?.registration;
  if (
    !owner ||
    !registration ||
    typeof url !== 'string' ||
    url.length > 2048 ||
    !/^https?:\/\//i.test(url) ||
    /[\s\\#]/.test(url)
  )
    throw new Error(INVALID);
  let endpoint: URL;
  try {
    endpoint = new URL(url);
  } catch {
    throw new Error(INVALID);
  }
  if (endpoint.username || endpoint.password) throw new Error(INVALID);
  const { chainId, slip44 } = registration;
  const { assertCurrent: guard, backendChain, readJson, signal } = owner;
  const selected = findUtxoCoinByRegistration({ chainId, slip44 });
  if (
    !selected ||
    selected.hashGenesisBlock.length !== 64 ||
    !/^[0-9a-f]{64}$/.test(selected.hashGenesisBlock) ||
    !signal ||
    typeof signal.aborted !== 'boolean' ||
    typeof guard !== 'function' ||
    typeof readJson !== 'function' ||
    typeof backendChain !== 'string' ||
    !backendChain.length ||
    backendChain.length > 32 ||
    /[^a-z0-9_-]/i.test(backendChain)
  )
    throw new Error(INVALID);
  const coin = { ...selected };
  const currency = statusName(coin.coinShortcut);
  const identities = coins.map((entry) => ({
    selected: entry === selected,
    slip44: entry.slip44,
    genesis: entry.hashGenesisBlock,
    shortcuts: [entry.coinShortcut, entry.shortcut].map((name) =>
      name.toLowerCase()
    ),
    names: getCoinNameVariations(entry).map((name) => name.toLowerCase()),
  }));
  // Existing custody and descriptor paths resolve (SLIP44, currency) by alias.
  if (
    identities.filter(
      (identity) =>
        identity.slip44 === slip44 && identity.names.includes(currency)
    ).length !== 1
  )
    throw new Error(INVALID);
  const assertCurrent = () => {
    if (signal.aborted) throw new Error(CANCELLED);
    let result: unknown;
    try {
      result = guard();
    } catch {
      throw new Error(CANCELLED);
    }
    if (result !== undefined) {
      void Promise.resolve(result).catch(() => undefined);
      throw new Error(INVALID);
    }
    if (signal.aborted) throw new Error(CANCELLED);
  };
  const base = endpoint.pathname.replace(/\/$/, '');
  const read = async (path: '/api/v2/' | '/api/v2/block-index/0') => {
    assertCurrent();
    endpoint.pathname = base + path;
    let result: unknown;
    try {
      result = await readJson(endpoint.href, signal);
    } catch {
      assertCurrent();
      throw new Error('UTXO registration read failed');
    }
    assertCurrent();
    return result;
  };

  const status = await read('/api/v2/');
  const blockbook = field(status, 'blockbook');
  const backend = field(status, 'backend');
  const backendError = field(backend, 'error');
  if (
    field(status, 'error') !== undefined ||
    field(blockbook, 'error') !== undefined ||
    (backendError !== undefined && backendError !== '')
  )
    throw new Error(INVALID);
  const chain = field(backend, 'chain');
  const decimals = field(blockbook, 'decimals');
  if (
    chain !== backendChain ||
    (decimals !== undefined && decimals !== coin.decimals)
  )
    throw new Error(MISMATCH);
  const reportedNetwork = field(blockbook, 'network');
  const reportedCoin = field(blockbook, 'coin');
  const network =
    reportedNetwork === undefined ? undefined : statusName(reportedNetwork);
  const name =
    reportedCoin === undefined ? undefined : statusName(reportedCoin);
  if (network === undefined && name === undefined) throw new Error(INVALID);
  const byNetwork =
    network === undefined
      ? identities
      : identities.filter((identity) => identity.shortcuts.includes(network));
  const matches =
    name === undefined
      ? byNetwork
      : byNetwork.filter((identity) => identity.names.includes(name));
  if (
    !matches.some((identity) => identity.selected) ||
    (network !== undefined && byNetwork.length !== 1)
  )
    throw new Error(MISMATCH);

  const genesisResponse = await read('/api/v2/block-index/0');
  if (field(genesisResponse, 'error') !== undefined) throw new Error(INVALID);
  const genesis = field(genesisResponse, 'blockHash');
  if (
    genesis !== coin.hashGenesisBlock ||
    matches.filter((identity) => identity.genesis === genesis).length !== 1
  )
    throw new Error(MISMATCH);
  assertCurrent();
  return { assertCurrent, backendChain, coin, chainId, currency };
}
