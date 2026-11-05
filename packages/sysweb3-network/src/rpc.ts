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

/** Preview a previously unpinned HTTPS endpoint for explicit registration. */
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

/**
 * Validate an EVM RPC endpoint with latency sampling
 * Performs multiple requests to get accurate latency (excluding cold start)
 *
 * @param url - The RPC endpoint URL
 * @param expectedChainId - Optional expected chainId to validate against
 * @param timeout - Request timeout in milliseconds
 * @param minLatency - Minimum latency in milliseconds to ensure quality
 * @returns Success status, chainId if successful, error message if failed, and latency info
 */
export const validateEvmRpcBatch = async (
  url: string,
  expectedChainId?: number,
  timeout = 5000,
  minLatency = 500
): Promise<{
  success: boolean;
  chainId?: number;
  error?: string;
  latency?: number;
  requiresAuth?: boolean;
}> => {
  // Helper function to perform a single request
  const performSingleRequest = async (): Promise<{
    success: boolean;
    chainId?: number;
    error?: string;
    latency: number;
    requiresAuth?: boolean;
    response?: any;
  }> => {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);
    const startTime = Date.now();

    try {
      const response = await retryableFetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify([
          {
            jsonrpc: '2.0',
            method: 'eth_chainId',
            params: [],
            id: 1,
          },
          {
            jsonrpc: '2.0',
            method: 'eth_blockNumber',
            params: [],
            id: 2,
          },
        ]),
        signal: controller.signal,
        cache: 'no-cache', // Force fresh request for testing
      });

      clearTimeout(timeoutId);
      const latency = Date.now() - startTime;

      // Check for authentication errors
      if (response.status === 401 || response.status === 403) {
        return {
          success: false,
          error: `Authentication required (HTTP ${response.status}). This RPC endpoint requires an API key.`,
          requiresAuth: true,
          latency,
        };
      }

      if (!response.ok) {
        // Check for rate limiting
        if (response.status === 429) {
          return {
            success: false,
            error:
              'Rate limited. Please try again later or use a different RPC endpoint.',
            latency,
          };
        }

        // Check for server errors
        if (response.status >= 500) {
          return {
            success: false,
            error: `Server error (HTTP ${response.status}). The RPC endpoint is currently unavailable.`,
            latency,
          };
        }

        return {
          success: false,
          error: `RPC returned ${response.status}`,
          latency,
        };
      }

      const data = await response.json();
      return {
        success: true,
        latency,
        response: data,
      };
    } catch (error) {
      clearTimeout(timeoutId);
      const latency = Date.now() - startTime;

      if (error.name === 'AbortError') {
        return {
          success: false,
          error: 'Request timeout',
          latency,
        };
      }

      // Check for network errors that might indicate authentication issues
      if (
        error instanceof TypeError &&
        error.message.includes('Failed to fetch')
      ) {
        return {
          success: false,
          error:
            'Network error: Unable to connect. This might be due to CORS restrictions or authentication requirements.',
          latency,
        };
      }

      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        latency,
      };
    }
  };

  // Perform multiple requests to get accurate latency measurement
  const requests: Array<{
    success: boolean;
    chainId?: number;
    error?: string;
    latency: number;
    requiresAuth?: boolean;
    response?: any;
  }> = [];
  const maxRequests = 3;

  for (let i = 0; i < maxRequests; i++) {
    try {
      const result = await performSingleRequest();
      requests.push(result);

      // If first request fails, don't continue
      if (!result.success) {
        return {
          success: false,
          chainId: result.chainId,
          error: result.error,
          latency: result.latency,
          requiresAuth: result.requiresAuth,
        };
      }

      // Delay between requests to avoid rate limiting (503 errors)
      if (i < maxRequests - 1) {
        await new Promise((resolve) => setTimeout(resolve, 1000));
      }
    } catch (error) {
      // If any request fails, return the error
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        latency: 0,
      };
    }
  }

  // Calculate average latency excluding the first request (cold start)
  const warmRequests = requests.slice(1); // Skip first request
  const averageLatency =
    warmRequests.reduce((sum, req) => sum + req.latency, 0) /
    warmRequests.length;

  // Use the response from the first successful request for validation
  const firstSuccessfulRequest = requests.find((req) => req.success);
  if (!firstSuccessfulRequest) {
    return {
      success: false,
      error: 'All requests failed',
      latency: averageLatency,
    };
  }

  const data = firstSuccessfulRequest.response;

  if (!Array.isArray(data) || data.length !== 2) {
    // Check for single error response indicating auth issues
    if (data?.error?.message) {
      const errorMsg = data.error.message.toLowerCase();
      if (
        errorMsg.includes('unauthorized') ||
        errorMsg.includes('authentication') ||
        errorMsg.includes('api key') ||
        errorMsg.includes('access denied') ||
        errorMsg.includes('forbidden')
      ) {
        return {
          success: false,
          error:
            'Authentication required. This RPC endpoint requires an API key.',
          requiresAuth: true,
          latency: averageLatency,
        };
      }
    }

    return {
      success: false,
      error: 'Invalid batch response format',
      latency: averageLatency,
    };
  }

  const chainIdResult = data.find((r) => r.id === 1);
  const blockNumberResult = data.find((r) => r.id === 2);

  // Check for JSON-RPC level authentication errors
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

  if (chainIdResult?.error) {
    const errorMsg = chainIdResult.error.message?.toLowerCase() || '';
    const hasAuthError = authErrorPatterns.some((pattern) =>
      errorMsg.includes(pattern)
    );

    if (hasAuthError) {
      return {
        success: false,
        error: chainIdResult.error.message || 'Authentication required',
        requiresAuth: true,
        latency: averageLatency,
      };
    }

    return {
      success: false,
      error: chainIdResult.error.message || 'Failed to get chainId',
      latency: averageLatency,
    };
  }

  if (blockNumberResult?.error) {
    const errorMsg = blockNumberResult.error.message?.toLowerCase() || '';
    const hasAuthError = authErrorPatterns.some((pattern) =>
      errorMsg.includes(pattern)
    );

    if (hasAuthError) {
      return {
        success: false,
        error: blockNumberResult.error.message || 'Authentication required',
        requiresAuth: true,
        latency: averageLatency,
      };
    }

    return {
      success: false,
      error: blockNumberResult.error.message || 'Failed to get block number',
      latency: averageLatency,
    };
  }

  if (!chainIdResult?.result || !blockNumberResult?.result) {
    return {
      success: false,
      error: 'Invalid response: missing required data',
      latency: averageLatency,
    };
  }

  const chainId = parseInt(chainIdResult.result, 16);

  // If expectedChainId is provided, validate it matches
  if (expectedChainId !== undefined && chainId !== expectedChainId) {
    return {
      success: false,
      chainId,
      error: `Chain ID mismatch: expected ${expectedChainId}, got ${chainId}`,
      latency: averageLatency,
    };
  }

  // Check minimum latency requirement using the average warm latency
  if (averageLatency > minLatency) {
    return {
      success: false,
      chainId,
      error: `RPC response too slow (${Math.round(
        averageLatency
      )}ms avg). Maximum ${minLatency}ms required for quality assurance.`,
      latency: averageLatency,
    };
  }

  return {
    success: true,
    chainId,
    latency: averageLatency,
  };
};
