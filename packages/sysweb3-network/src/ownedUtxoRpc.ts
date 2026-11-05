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

type OwnedUtxoRpcReader = Pick<
  OwnedUtxoRpcVerification,
  'signal' | 'assertCurrent' | 'readJson'
>;
type UtxoRegistration = OwnedUtxoRpcVerification['registration'];

export type OwnedUtxoRpcFirstUse = OwnedUtxoRpcReader &
  Readonly<{ registration?: UtxoRegistration; backendChain?: never }>;

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

function isBackendChainToken(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= 32 &&
    !/[^a-z0-9_-]/i.test(value)
  );
}

function captureReader(
  url: string,
  owner: OwnedUtxoRpcReader,
  firstUse: boolean
) {
  if (
    !owner ||
    typeof url !== 'string' ||
    url.length > 2048 ||
    !/^https?:\/\//i.test(url) ||
    /[\s\\?#]/.test(url)
  )
    throw new Error(INVALID);
  let endpoint: URL;
  try {
    endpoint = new URL(url);
  } catch {
    throw new Error(INVALID);
  }
  if (
    endpoint.username ||
    endpoint.password ||
    (firstUse &&
      endpoint.protocol === 'http:' &&
      endpoint.hostname !== '127.0.0.1' &&
      endpoint.hostname !== '[::1]')
  )
    throw new Error(INVALID);
  const { assertCurrent: guard, readJson, signal } = owner;
  if (
    !signal ||
    typeof signal.aborted !== 'boolean' ||
    typeof guard !== 'function' ||
    typeof readJson !== 'function'
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
  return { assertCurrent, read };
}

function captureIdentities() {
  return coins.map((coin) => ({
    coin,
    registration: {
      chainId: coin.chainId ?? coin.slip44,
      slip44: coin.slip44,
    },
    genesis: coin.hashGenesisBlock,
    decimals: coin.decimals,
    addressEncoding: [
      coin.addressType,
      coin.addressTypeP2sh,
      coin.bech32Prefix,
      coin.signedMessageHeader,
      coin.wif,
      coin.xprvMagic,
      coin.xpubMagic,
      coin.xpubMagicSegwitNative,
      coin.xpubMagicSegwitP2sh,
    ],
    shortcut: coin.coinShortcut,
    shortcuts: [coin.coinShortcut, coin.shortcut].map((name) =>
      name.toLowerCase()
    ),
    names: getCoinNameVariations(coin).map((name) => name.toLowerCase()),
  }));
}

type Identities = ReturnType<typeof captureIdentities>;
type Identity = Identities[number];

function canonicalCurrency(identity: Identity, identities: Identities) {
  const currency = statusName(identity.shortcut);
  // Existing custody and descriptor paths resolve (SLIP44, currency) by alias.
  if (
    identity.genesis.length !== 64 ||
    !/^[0-9a-f]{64}$/.test(identity.genesis) ||
    identities.filter(
      (entry) =>
        entry.registration.slip44 === identity.registration.slip44 &&
        entry.names.includes(currency)
    ).length !== 1
  )
    throw new Error(INVALID);
  return currency;
}

function selectIdentity(
  registration: UtxoRegistration,
  identities: Identities
) {
  const { chainId, slip44 } = registration;
  const coin = findUtxoCoinByRegistration({ chainId, slip44 });
  const selected = identities.find((identity) => identity.coin === coin);
  if (!selected) throw new Error(INVALID);
  return selected;
}

function matchStatus(
  identities: Identities,
  selected: Identity | undefined,
  network: string | undefined,
  name: string | undefined
) {
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
    !matches.length ||
    (selected && !matches.includes(selected)) ||
    (network !== undefined && byNetwork.length !== 1)
  )
    throw new Error(MISMATCH);
  return matches;
}

function matchGenesis(
  matches: Identities,
  selected: Identity | undefined,
  genesis: unknown,
  decimals: unknown
) {
  const genesisMatches = matches.filter(
    (candidate) => candidate.genesis === genesis
  );
  const identity = genesisMatches[0];
  if (
    !identity ||
    genesisMatches.length !== 1 ||
    (selected && identity !== selected) ||
    (decimals !== undefined && decimals !== identity.decimals)
  )
    throw new Error(MISMATCH);
  return identity;
}

async function readIdentity(
  read: ReturnType<typeof captureReader>['read'],
  identities: Identities,
  selected?: Identity,
  expectedBackendChain?: string
) {
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
    (expectedBackendChain !== undefined && chain !== expectedBackendChain) ||
    (selected && decimals !== undefined && decimals !== selected.decimals)
  )
    throw new Error(MISMATCH);
  if (!isBackendChainToken(chain)) throw new Error(INVALID);
  const reportedNetwork = field(blockbook, 'network');
  const reportedCoin = field(blockbook, 'coin');
  const network =
    reportedNetwork === undefined ? undefined : statusName(reportedNetwork);
  const name =
    reportedCoin === undefined ? undefined : statusName(reportedCoin);
  const matches = matchStatus(identities, selected, network, name);

  const genesisResponse = await read('/api/v2/block-index/0');
  if (field(genesisResponse, 'error') !== undefined) throw new Error(INVALID);
  const genesis = field(genesisResponse, 'blockHash');
  const identity = matchGenesis(matches, selected, genesis, decimals);
  return {
    identity,
    observedBackendChain: chain,
    network,
    name,
    genesis,
    decimals,
  };
}

function guardObservedIdentity(
  observed: Awaited<ReturnType<typeof readIdentity>>,
  currency: string,
  guard: () => void
) {
  const { identity, network, name, genesis, decimals } = observed;
  return () => {
    guard();
    // Registration and custody must still resolve to the same coin after the
    // asynchronous reads, including the wallet's legacy ticker lookup.
    const identities = captureIdentities();
    const live = selectIdentity(identity.registration, identities);
    const matches = matchStatus(identities, live, network, name);
    matchGenesis(matches, live, genesis, decimals);
    if (
      live.coin !== identity.coin ||
      live.decimals !== identity.decimals ||
      live.addressEncoding.some(
        (value, index) => value !== identity.addressEncoding[index]
      ) ||
      canonicalCurrency(live, identities) !== currency
    )
      throw new Error(INVALID);
  };
}

export async function verifyOwnedUtxoRpc(
  url: string,
  owner: OwnedUtxoRpcVerification
) {
  const registration = owner?.registration;
  const backendChain = owner?.backendChain;
  if (!registration || !isBackendChainToken(backendChain))
    throw new Error(INVALID);
  const { assertCurrent: guard, read } = captureReader(url, owner, false);
  const identities = captureIdentities();
  const selected = selectIdentity(registration, identities);
  const currency = canonicalCurrency(selected, identities);
  const { chainId } = selected.registration;
  const observed = await readIdentity(read, identities, selected, backendChain);
  const assertCurrent = guardObservedIdentity(observed, currency, guard);
  assertCurrent();
  const coin = { ...selected.coin };
  return { assertCurrent, backendChain, coin, chainId, currency };
}

/**
 * Read the canonical coin identity and the backend token reported on first use.
 * Plain HTTP is limited to a literal local loopback endpoint.
 * The token is an observation from the selected HTTPS endpoint, not an
 * independently expected value. The caller owns any approval or pin.
 */
export async function observeFirstUseUtxoRpc(
  url: string,
  owner: OwnedUtxoRpcFirstUse
) {
  if (!owner || typeof owner !== 'object' || 'backendChain' in owner)
    throw new Error(INVALID);
  const registration = owner.registration;
  if (registration !== undefined && !registration) throw new Error(INVALID);
  const { assertCurrent: guard, read } = captureReader(url, owner, true);
  const identities = captureIdentities();
  const selected =
    registration === undefined
      ? undefined
      : selectIdentity(registration, identities);
  const selectedCurrency = selected && canonicalCurrency(selected, identities);
  const observed = await readIdentity(read, identities, selected);
  const { identity, observedBackendChain } = observed;
  const currency = selectedCurrency ?? canonicalCurrency(identity, identities);
  const assertCurrent = guardObservedIdentity(observed, currency, guard);
  assertCurrent();
  return Object.freeze({
    registration: Object.freeze(identity.registration),
    coin: Object.freeze({ ...identity.coin }),
    currency,
    observedBackendChain,
    assertCurrent,
  });
}
