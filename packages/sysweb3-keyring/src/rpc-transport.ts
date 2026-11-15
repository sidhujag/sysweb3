export type RpcReadRequest = Readonly<{
  method: string;
  params: readonly unknown[] | Record<string, unknown>;
}>;
export type RpcTransportRequest = Readonly<{
  method: string;
  params: readonly unknown[] | Record<string, unknown>;
}>;
type RpcWireRequest = {
  jsonrpc: '2.0';
  method: string;
  params: readonly unknown[] | Record<string, unknown>;
  id: number;
};
export type RpcResponse = {
  jsonrpc: '2.0';
  id: number;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
};
export type RpcJsonTransport = (
  url: string,
  body: string,
  signal: AbortSignal
) => Promise<unknown>;

// A stale response must never be interpreted as the result of another RPC.
// Keep the sentinel in the message for callers that serialize errors as text.
export class RpcResponseIntegrityError extends Error {
  readonly code = 'SYSWEB3_RPC_RESPONSE_INVALID';

  constructor(
    message = 'JSON-RPC response does not match its request',
    readonly retryable = true
  ) {
    super(`[SYSWEB3_RPC_RESPONSE_INVALID] ${message}`);
    this.name = 'RpcResponseIntegrityError';
  }
}

// Only these standard, side-effect-free reads may recover from a stale cache
// entry. Never infer retry eligibility from an RPC method prefix.
const RECOVERABLE_READ_METHODS = new Set([
  'eth_chainId',
  'net_version',
  'web3_clientVersion',
  'eth_blockNumber',
  'eth_syncing',
  'eth_getBalance',
  'eth_getTransactionCount',
  'eth_getCode',
  'eth_getStorageAt',
  'eth_getProof',
  'eth_call',
  'eth_estimateGas',
  'eth_createAccessList',
  'eth_gasPrice',
  'eth_maxPriorityFeePerGas',
  'eth_feeHistory',
  'eth_getBlockByNumber',
  'eth_getBlockByHash',
  'eth_getBlockTransactionCountByNumber',
  'eth_getBlockTransactionCountByHash',
  'eth_getTransactionByHash',
  'eth_getTransactionByBlockNumberAndIndex',
  'eth_getTransactionByBlockHashAndIndex',
  'eth_getTransactionReceipt',
  'eth_getLogs',
]);

export const isReadOnlyRpcMethod = (method: string): boolean =>
  RECOVERABLE_READ_METHODS.has(method);

let rpcRecoveryNonce = 0;
// Shared across provider instances and seeded anew on process restart. These
// numeric correlation IDs are not authorization tokens.
let nextRpcWireId = Math.floor(Math.random() * 2 ** 51);
const reserveRpcWireId = (): number => {
  const id = ++nextRpcWireId;
  if (!Number.isSafeInteger(id)) {
    throw new RpcResponseIntegrityError(
      'RPC request ID range exhausted',
      false
    );
  }
  return id;
};

const recoveryUrl = (original: string): string => {
  const url = new URL(original);
  const token = `${Date.now()}-${++rpcRecoveryNonce}-${Math.random()
    .toString(36)
    .slice(2)}`;
  // Append without reserializing existing query values (including auth data).
  url.search += `${url.search ? '&' : '?'}sysweb3_rpc_request=${token}`;
  return url.toString();
};

function validateRpcResponses(
  json: any,
  requests: RpcWireRequest[],
  batch: boolean
): any[] {
  if (batch ? !Array.isArray(json) : Array.isArray(json)) {
    throw new RpcResponseIntegrityError();
  }
  const responses = batch ? json : [json];
  if (responses.length !== requests.length) {
    throw new RpcResponseIntegrityError();
  }
  const expectedIds = new Set(requests.map((request) => request.id));
  const byId = new Map<number, any>();
  for (const response of responses) {
    if (
      !response ||
      typeof response !== 'object' ||
      Array.isArray(response) ||
      typeof response.id !== 'number' ||
      !expectedIds.has(response.id) ||
      byId.has(response.id)
    ) {
      throw new RpcResponseIntegrityError();
    }
    const hasResult = Object.prototype.hasOwnProperty.call(response, 'result');
    const hasError = Object.prototype.hasOwnProperty.call(response, 'error');
    if (
      response.jsonrpc !== '2.0' ||
      hasResult === hasError ||
      (hasError &&
        (!response.error ||
          typeof response.error.message !== 'string' ||
          !Number.isSafeInteger(response.error.code)))
    ) {
      throw new RpcResponseIntegrityError(
        'Invalid JSON-RPC response envelope',
        false
      );
    }
    byId.set(response.id, response);
  }
  return requests.map((request) => byId.get(request.id));
}

/** Correlate exact wire responses and recover one stale read response. */
export async function requestJsonRpc(
  url: string,
  inputs: readonly RpcTransportRequest[],
  batch: boolean,
  signal: AbortSignal,
  transport: RpcJsonTransport,
  recoverResponse = true
): Promise<RpcResponse[]> {
  const canRecover =
    recoverResponse &&
    inputs.every(({ method }) => RECOVERABLE_READ_METHODS.has(method));
  const serialized = JSON.stringify(inputs);
  for (let attempt = 0; attempt < 2; attempt++) {
    if (signal.aborted) throw signal.reason || new Error('RPC request aborted');
    const source = JSON.parse(serialized) as RpcTransportRequest[];
    const requests: RpcWireRequest[] = source.map(({ method, params }) => ({
      jsonrpc: '2.0',
      method,
      params,
      id: reserveRpcWireId(),
    }));
    const json = await transport(
      attempt === 0 ? url : recoveryUrl(url),
      JSON.stringify(batch ? requests : requests[0]),
      signal
    ).catch((error) => {
      if (
        attempt === 0 ||
        error instanceof RpcResponseIntegrityError ||
        signal.aborted ||
        error?.name === 'AbortError'
      )
        throw error;
      throw new RpcResponseIntegrityError(
        'JSON-RPC response recovery failed',
        false
      );
    });
    try {
      return validateRpcResponses(json, requests, batch);
    } catch (error) {
      if (
        !(error instanceof RpcResponseIntegrityError) ||
        !error.retryable ||
        attempt !== 0 ||
        !canRecover
      )
        throw error;
    }
  }
  throw new RpcResponseIntegrityError();
}
