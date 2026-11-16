import { Chain, chains } from 'eth-chains';
import { toBeHex } from 'ethers/utils';

// import fetch from "node-fetch";
import {
  getNetworkConfigFromCoin,
  toDecimalFromHex,
  INetwork,
  INetworkType,
} from './networks';
import { observeFirstUseUtxoRpc, verifyOwnedUtxoRpc } from './ownedUtxoRpc';
import { retryableFetch } from './retryUtils';
import {
  JsonRpcReadClient,
  RpcReadError,
  type RpcReadRequest,
} from './rpc-read-client';

import type {
  OwnedUtxoRpcFirstUse,
  OwnedUtxoRpcVerification,
} from './ownedUtxoRpc';
import type { Coin } from './types';

export type {
  OwnedUtxoRpcFirstUse,
  OwnedUtxoRpcVerification,
} from './ownedUtxoRpc';

const hexRegEx = /^0x[0-9a-f]+$/iu;

const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

// Cache for eth_chainId calls
const ethChainIdCache = new Map<
  string,
  {
    chainId: number;
    timestamp: number;
  }
>();

// Function to clear RPC caches
export const clearRpcCaches = () => {
  ethChainIdCache.clear();
  console.log('[RPC] Cleared all RPC caches');
};

/**
 * Get chain details by chain ID
 * @param chainId - The chain ID to look up
 * @returns Chain details object or undefined if not found
 */
export const getChainById = (chainId: number): Chain | undefined => {
  try {
    return chains.getById(chainId);
  } catch (error) {
    return undefined;
  }
};

export const validateChainId = (
  chainId: number | string
): { hexChainId: string; valid: boolean } => {
  const hexChainId = toBeHex(chainId);

  const isHexChainIdValid =
    typeof hexChainId === 'string' && hexRegEx.test(hexChainId);

  return {
    valid: isHexChainIdValid,
    hexChainId,
  };
};

const getEthChainId = async (
  url: string,
  isInCooldown: boolean
): Promise<{ chainId: number }> => {
  if (isInCooldown) {
    throw new Error('Cant make request, rpc cooldown is active');
  }

  // Check cache first
  const cached = ethChainIdCache.get(url);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
    console.log('[getEthChainId] Returning cached chainId for', url);
    return { chainId: cached.chainId };
  }

  // Create AbortController for timeout
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 second timeout

  try {
    const response = await retryableFetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        method: 'eth_chainId',
        params: [],
        id: 1,
      }),
      signal: controller.signal,
    });

    // Check for authentication errors
    if (response.status === 401 || response.status === 403) {
      throw new Error(
        `Authentication required (HTTP ${response.status}). This RPC endpoint requires an API key.`
      );
    }

    // Check the status code of the HTTP response
    if (!response.ok) {
      switch (response.status) {
        case 429:
          throw new Error(
            'Error 429: Too many requests. Please slow down your request rate.'
          );
        case 503:
          throw new Error(
            'Error 503: Service Unavailable. The server is currently unable to handle the request.'
          );
        default:
          throw new Error(
            `Error ${response.status}: An error occurred while fetching the chain ID.`
          );
      }
    }

    const data = await response.json();

    // Check for JSON-RPC level authentication errors
    if (data.error) {
      const errorMsg = data.error.message?.toLowerCase() || '';
      const authErrorPatterns = [
        'unauthorized',
        'authentication',
        'api key',
        'access denied',
        'forbidden',
        'missing key',
        'invalid key',
        'subscription',
        'upgrade',
        'plan',
      ];

      const hasAuthError = authErrorPatterns.some((pattern) =>
        errorMsg.includes(pattern)
      );

      if (hasAuthError) {
        throw new Error(
          `Authentication required: ${
            data.error.message || 'This RPC endpoint requires an API key'
          }`
        );
      }

      throw new Error(`Error getting chain ID: ${data.error.message}`);
    }

    const chainId = Number(data.result);

    // Cache the result
    ethChainIdCache.set(url, {
      chainId,
      timestamp: Date.now(),
    });

    return { chainId };
  } catch (error) {
    if (error.name === 'AbortError') {
      throw new Error(
        'RPC request timeout: The server took too long to respond'
      );
    }

    // Handle network/CORS errors
    if (
      error instanceof TypeError &&
      error.message.includes('Failed to fetch')
    ) {
      throw new Error(
        'Network error: Unable to connect to RPC endpoint. Please check the URL and ensure CORS is enabled. Authentication might be required.'
      );
    }

    // Re-throw if it's already a proper Error with a message
    if (error instanceof Error) {
      throw error;
    }

    throw new Error(`Failed to connect to RPC: ${String(error)}`);
  } finally {
    clearTimeout(timeoutId);
  }
};

/** eth rpc */
export const isValidChainIdForEthNetworks = (chainId: number | string) =>
  Number.isSafeInteger(chainId) &&
  Number(chainId) > 0 &&
  Number(chainId) <= 4503599627370476;

export const validateEthRpc = async (
  url: string,
  isInCooldown: boolean
): Promise<{
  chain: string;
  chainId: number;
  details: Chain | undefined;
  hexChainId: string;
  valid: boolean;
}> => {
  try {
    const { chainId } = await getEthChainId(url, isInCooldown);
    if (!chainId) {
      throw new Error('Invalid RPC URL. Could not get chain ID for network.');
    }

    if (!isValidChainIdForEthNetworks(Number(chainId))) {
      throw new Error('Invalid chain ID for ethereum networks.');
    }

    const { valid, hexChainId } = validateChainId(chainId);
    const details = getChainById(chainId);
    if (!valid) {
      throw new Error('RPC has an invalid chain ID');
    }

    return {
      chainId,
      details,
      chain: details && details.chain ? details.chain : 'unknown',
      hexChainId,
      valid,
    };
  } catch (error) {
    // Properly handle error objects
    if (error instanceof Error) {
      throw error;
    }
    throw new Error(String(error));
  }
};

export const getEthRpc = async (
  data: any,
  isInCooldown: boolean
): Promise<{
  formattedNetwork: INetwork;
}> => {
  const { valid, hexChainId, details } = await validateEthRpc(
    data.url,
    isInCooldown
  );

  if (!valid) throw new Error('Invalid RPC.');

  const chainIdNumber = toDecimalFromHex(hexChainId);
  let explorer = '';
  if (details && !data.explorer) {
    explorer = details.explorers ? details.explorers[0].url : explorer;
  } else if (data.explorer) {
    explorer = data.explorer;
  }
  // Preserve query and fragment bytes; only the pathname needs a trailing slash.
  const explorerString = String(explorer);
  const explorerPath = explorerString.split(/[?#]/, 1)[0];
  explorer = explorerPath.endsWith('/')
    ? explorerString
    : explorerPath + '/' + explorerString.slice(explorerPath.length);
  if (!details && !data.symbol) throw new Error('Must define a symbol');
  const formattedNetwork = {
    url: data.url,
    default: false,
    label: data.label || String(details ? details.name : ''),
    apiUrl: data.apiUrl,
    explorer: String(explorer),
    currency: data.symbol
      ? data.symbol.toLowerCase()
      : details
      ? details.nativeCurrency.symbol.toLowerCase()
      : '',
    chainId: chainIdNumber,
    slip44: 60, // All EVM networks use ETH slip44 for address compatibility
    kind: INetworkType.Ethereum,
  };

  return {
    formattedNetwork,
  };
};
/** end */

/** bitcoin-like rpc */
type SysRpcDraft = {
  url: string;
  explorer?: string;
  label?: string;
};

function snapshotSysRpcDraft({
  url,
  explorer,
  label,
}: SysRpcDraft): SysRpcDraft {
  if (
    [explorer, label].some(
      (value) => value !== undefined && typeof value !== 'string'
    )
  )
    throw new Error('Invalid UTXO registration draft');
  return { url, explorer, label };
}

function formatSysRpc(
  data: SysRpcDraft,
  coin: Coin,
  chainId: number,
  network: string,
  chain: string,
  currency: string
) {
  const networkConfig = getNetworkConfigFromCoin(coin);
  // The public explorer can differ from the RPC. It is never probed here.
  const explorer = data.explorer || data.url.replace(/\/api\/v[12]/, '');
  const formattedNetwork = {
    url: data.url,
    explorer,
    currency,
    label: data.label || network,
    default: false,
    chainId,
    slip44: coin.slip44,
    kind: INetworkType.Syscoin,
    utxoBackendChain: chain,
  };
  return { rpc: { formattedNetwork, networkConfig }, network, chain };
}

export const getSysRpc = async (
  input: SysRpcDraft,
  owner: OwnedUtxoRpcVerification
) => {
  const draft = snapshotSysRpcDraft(input);
  const { assertCurrent, coin, chainId, backendChain, currency } =
    await verifyOwnedUtxoRpc(draft.url, owner);
  assertCurrent();
  return formatSysRpc(
    draft,
    coin,
    chainId,
    coin.coinShortcut,
    backendChain,
    currency
  );
};

/** Preview an unpinned HTTPS or local loopback endpoint for registration. */
export const observeSysRpc = async (
  input: SysRpcDraft,
  owner: OwnedUtxoRpcFirstUse
) => {
  const draft = snapshotSysRpcDraft(input);
  const { assertCurrent, coin, currency, observedBackendChain, registration } =
    await observeFirstUseUtxoRpc(draft.url, owner);
  assertCurrent();
  const result = formatSysRpc(
    draft,
    coin,
    registration.chainId,
    coin.coinShortcut,
    observedBackendChain,
    currency
  );
  assertCurrent();
  return result;
};
/** end */

export type EvmRpcQualityOwner = Readonly<{
  signal?: AbortSignal;
  assertCurrent?: () => void;
  readMany?: (
    requests: readonly RpcReadRequest[],
    signal: AbortSignal
  ) => Promise<PromiseSettledResult<unknown>[]>;
}>;

/** Three independent fresh samples, timed through bounded response consumption. */
export const validateEvmRpcBatch = async (
  url: string,
  expectedChainId?: number,
  timeout = 5000,
  minLatency = 500,
  owner: EvmRpcQualityOwner = {}
): Promise<{
  success: boolean;
  chainId?: number;
  error?: string;
  latency?: number;
  requiresAuth?: boolean;
}> => {
  const client = owner.readMany
    ? undefined
    : new JsonRpcReadClient(url, {
        signal: owner.signal,
        timeoutMs: timeout,
        maxBatchItems: 2,
        maxResponseBytes: 16 * 1024,
        requestInit: { cache: 'no-cache' },
      });
  const latencies: number[] = [];
  let chainId: number | undefined;
  const check = () => {
    if (owner.signal?.aborted)
      throw Object.assign(new Error('RPC check cancelled'), {
        name: 'AbortError',
      });
    owner.assertCurrent?.();
  };
  try {
    for (let sample = 0; sample < 3; sample++) {
      check();
      const controller = new AbortController();
      const abort = () => controller.abort(owner.signal?.reason);
      owner.signal?.addEventListener('abort', abort, { once: true });
      const timer = setTimeout(
        () => controller.abort(new Error('Request timeout')),
        timeout
      );
      const started = Date.now();
      try {
        const requests = [
          { method: 'eth_chainId', params: [] },
          { method: 'eth_blockNumber', params: [] },
        ];
        const results = await (owner.readMany
          ? owner.readMany(requests, controller.signal)
          : client!.readMany(requests, {
              signal: controller.signal,
              timeoutMs: timeout,
            }));
        check();
        if (controller.signal.aborted) throw controller.signal.reason;
        if (results.length !== 2) throw new Error('Invalid RPC response');
        const values = results.map((result) => {
          if (result.status === 'rejected') throw result.reason;
          if (
            typeof result.value !== 'string' ||
            !/^0x(?:0|[1-9a-f][0-9a-f]*)$/i.test(result.value)
          )
            throw new Error('Invalid RPC quantity');
          return BigInt(result.value);
        });
        if (values[0] <= 0n || values[0] > BigInt(Number.MAX_SAFE_INTEGER))
          throw new Error('Invalid chain ID');
        const current = Number(values[0]);
        if (
          (expectedChainId !== undefined && current !== expectedChainId) ||
          (chainId !== undefined && current !== chainId)
        )
          throw new Error('Chain ID mismatch');
        chainId = current;
        latencies.push(Date.now() - started);
      } finally {
        clearTimeout(timer);
        owner.signal?.removeEventListener('abort', abort);
      }
      if (sample < 2)
        await new Promise<void>((resolve, reject) => {
          const abortDelay = () => {
            clearTimeout(timer);
            reject(new Error('RPC check cancelled'));
          };
          const timer = setTimeout(() => {
            owner.signal?.removeEventListener('abort', abortDelay);
            resolve();
          }, 1000);
          owner.signal?.addEventListener('abort', abortDelay, { once: true });
          if (owner.signal?.aborted) abortDelay();
        });
    }
    check();
    const latency = (latencies[1] + latencies[2]) / 2;
    return latency > minLatency
      ? {
          success: false,
          chainId,
          latency,
          error: `RPC response too slow (${Math.round(
            latency
          )}ms avg). Maximum ${minLatency}ms required for quality assurance.`,
        }
      : { success: true, chainId, latency };
  } catch (error: any) {
    const status = error?.status ?? error?.response?.status;
    const requiresAuth =
      status === 401 ||
      status === 403 ||
      (status === undefined &&
        error instanceof RpcReadError &&
        /unauthorized|authentication|api key|access denied|forbidden|missing key|invalid key|subscription|upgrade|plan/i.test(
          error.message
        ));
    return {
      success: false,
      chainId,
      error: requiresAuth
        ? `Authentication required${
            status === undefined ? '' : ` (HTTP ${status})`
          }. This RPC endpoint requires an API key.`
        : error?.message || 'Connection failed',
      ...(requiresAuth ? { requiresAuth: true } : {}),
    };
  } finally {
    client?.destroy();
  }
};
