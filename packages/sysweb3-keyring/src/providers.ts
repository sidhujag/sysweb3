import { FeeData } from 'ethers/providers';
import { FetchRequest, getBigInt } from 'ethers/utils';

import { handleStatusCodeError } from './errorUtils';
import {
  BigNumber,
  JsonRpcProvider,
  normalizeTransactionRequest,
  type Networkish,
} from './ethers-v6';

import type { JsonRpcPayload } from 'ethers/providers';

const TRANSACTION_RESPONSE_BIG_NUMBER_FIELDS = new Set([
  'gasLimit',
  'gasPrice',
  'maxFeePerGas',
  'maxPriorityFeePerGas',
  'value',
]);

const TRANSACTION_RESPONSE_NUMBER_FIELDS = new Set(['chainId']);

const TRANSACTION_RECEIPT_BIG_NUMBER_FIELDS = new Set([
  'blobGasPrice',
  'blobGasUsed',
  'cumulativeGasUsed',
  'effectiveGasPrice',
  'gasPrice',
  'gasUsed',
]);

const FEE_DATA_CACHE_TTL_MS = 5000;

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

const getChainIdFromNetworkish = (network?: Networkish): number | undefined => {
  if (network == null) return undefined;
  if (typeof network === 'number') return network;
  if (typeof network === 'bigint') return Number(network);
  const chainId = (network as { chainId?: bigint | number | string }).chainId;
  if (chainId == null) return undefined;
  return typeof chainId === 'bigint' ? Number(chainId) : Number(chainId);
};

const parseChainId = (chainId: bigint | number | string): number => {
  if (typeof chainId === 'number') return chainId;
  if (typeof chainId === 'bigint') return Number(chainId);
  return Number(BigInt(chainId));
};

const defineValue = (target: any, field: string, value: any) => {
  Object.defineProperty(target, field, {
    value,
    configurable: true,
    enumerable: true,
    writable: true,
  });
};

const wrapBigNumberFields = (
  source: any,
  fields: Set<string>,
  omittedFields: Set<string> = fields
) => {
  if (!source) return source;
  const wrapped = Object.create(Object.getPrototypeOf(source));
  const descriptors = Object.getOwnPropertyDescriptors(source);
  for (const field of omittedFields) {
    delete descriptors[field];
  }
  Object.defineProperties(wrapped, descriptors);

  for (const field of fields) {
    if (source[field] != null) {
      defineValue(wrapped, field, BigNumber.from(source[field]));
    }
  }

  return wrapped;
};

export const wrapTransactionReceipt = (receipt: any) => {
  const wrapped = wrapBigNumberFields(
    receipt,
    TRANSACTION_RECEIPT_BIG_NUMBER_FIELDS
  );
  if (!wrapped) return wrapped;

  return new Proxy(wrapped, {
    get(target, property, receiver) {
      const value = Reflect.get(target, property, receiver);
      return typeof value === 'function' ? value.bind(receipt) : value;
    },
  });
};

export const wrapTransactionResponse = (transaction: any) => {
  if (!transaction) return transaction;
  const omittedFields = new Set([
    ...TRANSACTION_RESPONSE_BIG_NUMBER_FIELDS,
    ...TRANSACTION_RESPONSE_NUMBER_FIELDS,
    'wait',
  ]);
  const wrapped = wrapBigNumberFields(
    transaction,
    TRANSACTION_RESPONSE_BIG_NUMBER_FIELDS,
    omittedFields
  );

  for (const field of TRANSACTION_RESPONSE_NUMBER_FIELDS) {
    if (transaction[field] != null) {
      defineValue(wrapped, field, Number(transaction[field]));
    }
  }

  if (typeof transaction.wait === 'function') {
    defineValue(wrapped, 'wait', async (...args: any[]) =>
      wrapTransactionReceipt(await transaction.wait(...args))
    );
  }

  return new Proxy(wrapped, {
    get(target, property, receiver) {
      const value = Reflect.get(target, property, receiver);
      return typeof value === 'function' ? value.bind(transaction) : value;
    },
  });
};

// Preserve JSON-RPC error details (code, revert data) on thrown errors so
// consumers can decode custom contract errors instead of only seeing
// "execution reverted".
const makeRpcError = (rpcError: {
  code?: number;
  data?: unknown;
  message: string;
}): Error => {
  const error = new Error(rpcError.message) as Error & {
    code?: number;
    data?: unknown;
  };
  if (rpcError.code !== undefined) {
    error.code = rpcError.code;
  }
  if (rpcError.data !== undefined) {
    error.data = rpcError.data;
  }
  return error;
};

class BaseProvider extends JsonRpcProvider {
  private isPossibleGetChainId = true;
  private cooldownTime = 120 * 1000;
  private rateLimit = 30;
  private requestCount = 0;
  private lastRequestTime = 0;
  private currentChainId = '';
  private feeDataCache: { expiresAt: number; value: any } | null = null;
  private feeDataPromise: Promise<any> | null = null;
  private readonly configuredChainId?: number;
  private chainIdVerificationPromise: Promise<void> | null = null;
  public isInCooldown = false;
  public errorMessage: any = '';
  public serverHasAnError = false;
  signal: AbortSignal;
  _pendingBatchAggregator: NodeJS.Timer | null;
  _pendingBatch: Array<{
    reject: (error: Error) => void;
    request: { id: number; jsonrpc: '2.0'; method: string; params: Array<any> };
    resolve: (result: any) => void;
  }> | null;

  constructor(
    signal: AbortSignal,
    url?: string | { url: string },
    network?: Networkish
  ) {
    super(
      typeof url === 'string' ? url : url?.url,
      network,
      network == null ? undefined : { staticNetwork: true }
    );
    this.configuredChainId = getChainIdFromNetworkish(network);
    this.signal = signal;
    this._pendingBatchAggregator = null;
    this._pendingBatch = null;

    this.bindMethods();
  }

  private bindMethods() {
    const proto = Object.getPrototypeOf(this);
    for (const key of Object.getOwnPropertyNames(proto)) {
      if (typeof this[key] === 'function' && key !== 'constructor') {
        this[key] = this[key].bind(this);
      }
    }
  }

  private throttledRequest = <T>(requestFn: () => Promise<T>): Promise<T> => {
    if (!this.canMakeRequest()) {
      return this.cooldown();
    }
    // Execute request immediately without timeout delay
    return requestFn().catch((error) => {
      if (error.name === 'AbortError') {
        console.log('Aborted request', error);
        return Promise.reject(error);
      }
      throw error;
    });
  };
  private canMakeRequest = () => {
    const now = Date.now();
    let elapsedTime = 0;
    if (this.lastRequestTime > 0) {
      elapsedTime = now - this.lastRequestTime;
    }
    if (elapsedTime <= this.cooldownTime && this.serverHasAnError) {
      this.isInCooldown = true;
      return false;
    }

    if (elapsedTime >= this.cooldownTime && this.serverHasAnError) {
      this.requestCount = 0;
      this.serverHasAnError = false;
      this.isInCooldown = true;
      return false; //One last blocked request before cooldown ends
    }

    if (this.requestCount < this.rateLimit || !this.serverHasAnError) {
      this.requestCount++;
      if (elapsedTime > 1000) {
        //Uncomment the console.log to see the request per second
        // console.log(
        //   `Request/sec to Provider(${this.connection.url}): ${this.requestCount}`
        // );
        this.requestCount = 1;
        this.lastRequestTime = now;
      } else if (this.lastRequestTime === 0) {
        this.lastRequestTime = now;
      }
      this.isInCooldown = false;
      return true;
    }
  };

  async verifyConfiguredChainId(): Promise<void> {
    if (this.configuredChainId == null) return;
    if (!this.chainIdVerificationPromise) {
      this.chainIdVerificationPromise =
        this.fetchAndVerifyConfiguredChainId().finally(() => {
          this.chainIdVerificationPromise = null;
        });
    }
    return this.chainIdVerificationPromise;
  }

  private async fetchAndVerifyConfiguredChainId(): Promise<void> {
    this.isPossibleGetChainId = true;
    const actualChainId = parseChainId(await this.send('eth_chainId', []));
    if (actualChainId !== this.configuredChainId) {
      throw new Error(
        `Configured EVM chainId ${this.configuredChainId} does not match RPC eth_chainId ${actualChainId}`
      );
    }
  }

  private cooldown = async () => {
    const now = Date.now();
    const elapsedTime = now - this.lastRequestTime;
    console.error(
      'Cant make request, rpc cooldown is active for the next: ',
      (this.cooldownTime - elapsedTime) / 1000,
      ' seconds'
    );
    throw {
      message: `Cant make request, rpc cooldown is active for the next: ${
        (this.cooldownTime - elapsedTime) / 1000
      } seconds`,
    };
  };

  private validateRpcResponses(
    json: any,
    requests: JsonRpcPayload[],
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
      const hasResult = Object.prototype.hasOwnProperty.call(
        response,
        'result'
      );
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

  private async requestRpc(
    inputs: Array<Pick<JsonRpcPayload, 'method' | 'params'>>,
    batch: boolean
  ): Promise<any[]> {
    const canRecover = inputs.every(({ method }) =>
      RECOVERABLE_READ_METHODS.has(method)
    );
    const originalUrl = this._getConnection().url;
    let originalBody = '';
    for (let attempt = 0; attempt < 2; attempt++) {
      if (this.signal.aborted) {
        throw this.signal.reason || new Error('RPC request aborted');
      }
      // Reserve the whole request range before any dispatch or await.
      // A recovery must repeat the serialized read, even if its caller mutates
      // an input object while the first response is delayed.
      const source =
        attempt === 0
          ? inputs
          : batch
          ? JSON.parse(originalBody)
          : [JSON.parse(originalBody)];
      const requests: JsonRpcPayload[] = source.map(({ method, params }) => ({
        jsonrpc: '2.0',
        method,
        params,
        id: reserveRpcWireId(),
      }));
      const options: RequestInit = {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(batch ? requests : requests[0]),
        signal: this.signal,
      };
      if (attempt === 0) originalBody = options.body as string;
      const json = await this.throttledRequest(async () => {
        const response = await fetch(
          attempt === 0 ? originalUrl : recoveryUrl(originalUrl),
          options
        );
        if (!response.ok) {
          let errorBody = { error: undefined, message: undefined };
          try {
            errorBody = await response.json();
          } catch {
            console.warn('No body in request');
          }
          this.errorMessage =
            errorBody.error || errorBody.message || 'No message from Provider';
          handleStatusCodeError(response.status, this.errorMessage);
        }
        if (response.status !== 200) {
          throw new Error(`Unexpected HTTP status code: ${response.status}`);
        }
        try {
          return await response.json();
        } catch (error) {
          if (this.signal.aborted || error?.name === 'AbortError') throw error;
          throw new RpcResponseIntegrityError(
            'Invalid JSON-RPC JSON response',
            false
          );
        }
      }).catch((error) => {
        if (
          attempt === 0 ||
          error instanceof RpcResponseIntegrityError ||
          this.signal.aborted ||
          error?.name === 'AbortError'
        ) {
          throw error;
        }
        throw new RpcResponseIntegrityError(
          'JSON-RPC response recovery failed',
          false
        );
      });
      try {
        const responses = this.validateRpcResponses(json, requests, batch);
        this.serverHasAnError = false;
        return responses;
      } catch (error) {
        if (
          !(error instanceof RpcResponseIntegrityError) ||
          !error.retryable ||
          attempt !== 0 ||
          !canRecover
        ) {
          throw error;
        }
      }
    }
    throw new RpcResponseIntegrityError();
  }

  // Ethers uses this primitive for network auto-detection and inherited send.
  // Share wire IDs and validation, then restore its caller IDs after correlation.
  override async _send(
    payload: JsonRpcPayload | Array<JsonRpcPayload>
  ): Promise<any[]> {
    const inputs = Array.isArray(payload) ? payload : [payload];
    if (!inputs.length) return [];
    const callerIds = inputs.map(({ id }) => id);
    const responses = await this.requestRpc(inputs, Array.isArray(payload));
    return responses.map((response, index) => ({
      ...response,
      id: callerIds[index],
    }));
  }

  override send = async (method: string, params: any[]) => {
    if (!this.isPossibleGetChainId && method === 'eth_chainId') {
      return this.currentChainId;
    }
    const [json] = await this.requestRpc([{ method, params }], false);
    if (json.error) {
      this.errorMessage = json.error.message;
      throw makeRpcError(json.error);
    }
    if (method === 'eth_chainId') {
      this.currentChainId = json.result;
      this.isPossibleGetChainId = false;
    }
    return json.result;
  };

  async sendBatch(method: string, params: Array<any[]>): Promise<any[]> {
    if (!params.length) return [];
    const responses = await this.requestRpc(
      params.map((param) => ({ method, params: param })),
      true
    );
    return responses.map((json) => {
      if (json.error) {
        this.errorMessage = json.error.message;
        throw makeRpcError(json.error);
      }
      return json.result;
    });
  }

  async getGasPrice() {
    return BigNumber.from(await this.send('eth_gasPrice', []));
  }

  async getFeeData(): Promise<any> {
    const now = Date.now();
    if (this.feeDataCache && this.feeDataCache.expiresAt > now) {
      return this.feeDataCache.value;
    }
    if (this.feeDataPromise) {
      return this.feeDataPromise;
    }

    this.feeDataPromise = this.fetchFeeData();
    try {
      const value = await this.feeDataPromise;
      this.feeDataCache = {
        expiresAt: Date.now() + FEE_DATA_CACHE_TTL_MS,
        value,
      };
      return value;
    } finally {
      this.feeDataPromise = null;
    }
  }

  private async readFeeData(): Promise<FeeData> {
    const network = await this.getNetwork();
    // Ethers tolerates unavailable optional fee methods; keep that behavior,
    // but never convert a response-integrity failure into an invented quote.
    const optionalFee = async (method: 'getGasPrice' | 'getPriorityFee') => {
      try {
        return getBigInt(await this._perform({ method }), '%response');
      } catch (error) {
        if (
          error?.code === 'SYSWEB3_RPC_RESPONSE_INVALID' ||
          error?.name === 'AbortError' ||
          this.signal.aborted
        )
          throw error;
        return null;
      }
    };
    const getFeeData = async () => {
      const [block, gasPrice, priorityFee] = await Promise.all([
        super.getBlock('latest'),
        optionalFee('getGasPrice'),
        optionalFee('getPriorityFee'),
      ]);
      let maxFeePerGas: bigint | null = null;
      let maxPriorityFeePerGas: bigint | null = null;
      if (block?.baseFeePerGas != null && priorityFee != null) {
        maxPriorityFeePerGas = priorityFee;
        maxFeePerGas = block.baseFeePerGas * 2n + maxPriorityFeePerGas;
      }
      return new FeeData(gasPrice, maxFeePerGas, maxPriorityFeePerGas);
    };
    // Preserve network-specific fee plugins, including Polygon's fee reader.
    const plugin = network.getPlugin(
      'org.ethers.plugins.network.FetchUrlFeeDataPlugin'
    ) as any;
    if (plugin) {
      // Polygon wraps reader failures in SERVER_ERROR. Preserve this
      // invocation's integrity/cancellation failure through that wrapper.
      let readerFailure: any;
      const pluginReader = async () => {
        try {
          return await getFeeData();
        } catch (error) {
          if (
            error?.code === 'SYSWEB3_RPC_RESPONSE_INVALID' ||
            error?.name === 'AbortError' ||
            this.signal.aborted
          ) {
            readerFailure = error;
          }
          throw error;
        }
      };
      let result;
      try {
        result = await plugin.processFunc(
          pluginReader,
          this,
          new FetchRequest(plugin.url)
        );
      } catch (error) {
        throw readerFailure ?? error;
      }
      if (readerFailure) throw readerFailure;
      return new FeeData(
        result.gasPrice,
        result.maxFeePerGas,
        result.maxPriorityFeePerGas
      );
    }
    return getFeeData();
  }

  private async fetchFeeData(): Promise<any> {
    const feeData = await this.readFeeData();
    const maxFeePerGas =
      feeData.maxFeePerGas == null
        ? null
        : BigNumber.from(feeData.maxFeePerGas);
    const maxPriorityFeePerGas =
      feeData.maxPriorityFeePerGas == null
        ? null
        : BigNumber.from(feeData.maxPriorityFeePerGas);

    if (maxFeePerGas == null || maxPriorityFeePerGas == null) {
      const block = await super.getBlock('latest');
      if (!block) throw new Error('Block not found');
      if (block?.baseFeePerGas != null) {
        throw new Error('EIP-1559 fee data unavailable');
      }
    }

    if (
      (maxFeePerGas != null && maxFeePerGas.isNegative()) ||
      (maxPriorityFeePerGas != null && maxPriorityFeePerGas.isNegative()) ||
      (maxFeePerGas != null &&
        maxPriorityFeePerGas != null &&
        maxPriorityFeePerGas.gt(maxFeePerGas))
    )
      throw new Error('Invalid EIP-1559 fee data');

    const gasPrice =
      feeData.gasPrice == null ? null : BigNumber.from(feeData.gasPrice);
    if (gasPrice?.isNegative()) throw new Error('Invalid gas price');
    return {
      gasPrice,
      maxFeePerGas,
      maxPriorityFeePerGas,
    };
  }

  async getBalance(address: string, blockTag?: any): Promise<any> {
    return BigNumber.from(await super.getBalance(address, blockTag));
  }

  private async normalizeLegacyCallRequest(transaction: any) {
    const normalized = normalizeTransactionRequest(transaction);

    // Some legacy/non-EIP-1559 RPCs reject a type field on call/estimateGas.
    // Preserve the old provider behavior by stripping explicit type 0 only
    // when the network does not expose EIP-1559 fee fields.
    if (
      normalized?.type === 0 &&
      normalized.maxFeePerGas == null &&
      normalized.maxPriorityFeePerGas == null
    ) {
      const feeData = await this.readFeeData();
      if (
        feeData.maxFeePerGas == null &&
        feeData.maxPriorityFeePerGas == null
      ) {
        delete normalized.type;
      }
    }

    return normalized;
  }

  async call(transaction: any, blockTag?: any): Promise<any> {
    const normalized = await this.normalizeLegacyCallRequest(transaction);
    if (blockTag != null) {
      normalized.blockTag = blockTag;
    }

    return await super.call(normalized);
  }

  async estimateGas(transaction: any): Promise<any> {
    const normalized = await this.normalizeLegacyCallRequest(transaction);

    return BigNumber.from(await super.estimateGas(normalized));
  }

  async getBlock(blockHashOrBlockTag: any): Promise<any> {
    return await super.getBlock(blockHashOrBlockTag);
  }

  async getTransaction(hash: string): Promise<any> {
    return wrapTransactionResponse(await super.getTransaction(hash));
  }

  async sendTransaction(signedTransaction: string) {
    return wrapTransactionResponse(
      await this.broadcastTransaction(signedTransaction)
    );
  }
}

export class CustomJsonRpcProvider extends BaseProvider {
  constructor(
    signal: AbortSignal,
    url?: string | { url: string },
    network?: Networkish
  ) {
    super(signal, url, network);
  }
}
