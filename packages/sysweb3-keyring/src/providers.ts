import { FeeData } from 'ethers/providers';
import { FetchRequest, getBigInt } from 'ethers/utils';

import { handleStatusCodeError } from './errorUtils';
import {
  BigNumber,
  JsonRpcProvider,
  normalizeTransactionRequest,
  type Networkish,
} from './ethers-v6';
import {
  JsonRpcReadClient,
  RpcReadError,
  type RpcReadClientOptions,
  type RpcReadOptions,
  type RpcReadRequest,
} from './rpc-read-client';
import {
  isReadOnlyRpcMethod,
  cancelRpcResponse,
  readJsonRpcResponse,
  requestJsonRpc,
} from './rpc-transport';

import type { JsonRpcPayload } from 'ethers/providers';

export { RpcResponseIntegrityError } from './rpc-transport';
export type RpcProviderOptions = Omit<RpcReadClientOptions, 'signal'>;

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
  private cooldownTime = 120 * 1000;
  private cooldownUntil = 0;
  private readonly fetcher: NonNullable<RpcReadClientOptions['fetch']>;
  private readonly maximumResponseBytes: number;
  private readonly requestTimeoutMs: number;
  private feeDataCache: { expiresAt: number; value: any } | null = null;
  private feeDataPromise: Promise<any> | null = null;
  private readonly configuredChainId?: number;
  private chainIdVerificationPromise: Promise<void> | null = null;
  private readonly readClient: JsonRpcReadClient;
  private readonly lifetime = new AbortController();
  private releaseExternalSignal: () => void;
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
    network?: Networkish,
    options: RpcProviderOptions = {}
  ) {
    super(
      typeof url === 'string' ? url : url?.url,
      network,
      network == null ? undefined : { staticNetwork: true }
    );
    this.configuredChainId = getChainIdFromNetworkish(network);
    this.signal = this.lifetime.signal;
    const abort = () => this.lifetime.abort(signal.reason);
    this.releaseExternalSignal = () =>
      signal.removeEventListener('abort', abort);
    if (signal.aborted) abort();
    else signal.addEventListener('abort', abort, { once: true });
    this.fetcher = options.fetch ?? ((address, init) => fetch(address, init));
    this.maximumResponseBytes = options.maxResponseBytes ?? 2 * 1024 * 1024;
    this.requestTimeoutMs = options.timeoutMs ?? 12000;
    this.readClient = new JsonRpcReadClient(this._getConnection().url, {
      ...options,
      fetch: (address, init) => this.fetchRpc(address, init),
      signal: this.lifetime.signal,
    });
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

  private async fetchRpc(url: string, init: RequestInit): Promise<Response> {
    this.assertActive();
    if (this.cooldownUntil > Date.now()) {
      this.isInCooldown = true;
      throw Object.assign(new Error('RPC rate-limit cooldown is active'), {
        status: 429,
      });
    }
    this.isInCooldown = false;
    this.serverHasAnError = false;
    const response = await this.fetcher(url, init);
    if (response.status === 429) {
      this.cooldownUntil = Date.now() + this.cooldownTime;
      this.serverHasAnError = true;
      this.isInCooldown = true;
    }
    return response;
  }

  private assertActive(): void {
    if (this.lifetime.signal.aborted)
      throw this.lifetime.signal.reason instanceof Error
        ? this.lifetime.signal.reason
        : Object.assign(new Error('RPC provider aborted'), {
            name: 'AbortError',
          });
  }

  async verifyConfiguredChainId(fresh = false): Promise<void> {
    if (this.configuredChainId == null) return;
    if (fresh) return this.fetchAndVerifyConfiguredChainId();
    if (!this.chainIdVerificationPromise) {
      this.chainIdVerificationPromise =
        this.fetchAndVerifyConfiguredChainId().finally(() => {
          this.chainIdVerificationPromise = null;
        });
    }
    return this.chainIdVerificationPromise;
  }

  private async fetchAndVerifyConfiguredChainId(): Promise<void> {
    const actual = await this.readChainId(true);
    const actualChainId = parseChainId(actual);
    if (actualChainId !== this.configuredChainId) {
      throw new Error(
        `Configured EVM chainId ${this.configuredChainId} does not match RPC eth_chainId ${actualChainId}`
      );
    }
  }

  private readChainId(fresh: boolean): Promise<string> {
    return this.readClient.getChainId({ fresh });
  }

  private async requestRpc(
    inputs: Array<Pick<JsonRpcPayload, 'method' | 'params'>>,
    batch: boolean
  ): Promise<any[]> {
    this.assertActive();
    const controller = new AbortController();
    const abort = () => controller.abort(this.lifetime.signal.reason);
    this.lifetime.signal.addEventListener('abort', abort, { once: true });
    const signal = controller.signal;
    const timer = setTimeout(
      () =>
        controller.abort(
          Object.assign(new Error('RPC request deadline exceeded'), {
            name: 'AbortError',
          })
        ),
      this.requestTimeoutMs
    );
    const work = requestJsonRpc(
      this._getConnection().url,
      inputs,
      batch,
      signal,
      async (url, body, signal) => {
        const response = await this.fetchRpc(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body,
          signal,
        });
        let readingBody = false;
        try {
          if (signal.aborted) throw signal.reason;
          readingBody = true;
          const json: any = await readJsonRpcResponse(
            response,
            this.maximumResponseBytes,
            signal
          );
          if (signal.aborted) throw signal.reason;
          if (!response.ok) {
            this.errorMessage =
              json?.error || json?.message || 'No message from Provider';
            handleStatusCodeError(response.status, this.errorMessage);
          }
          if (response.status !== 200)
            throw new Error(`Unexpected HTTP status code: ${response.status}`);
          return json;
        } finally {
          if (!readingBody) await cancelRpcResponse(response);
        }
      },
      false
    );
    try {
      return await new Promise<any[]>((resolve, reject) => {
        const cancel = () => reject(signal.reason);
        signal.addEventListener('abort', cancel, { once: true });
        if (signal.aborted) cancel();
        void work
          .then(resolve, reject)
          .finally(() => signal.removeEventListener('abort', cancel));
      });
    } finally {
      clearTimeout(timer);
      this.lifetime.signal.removeEventListener('abort', abort);
    }
  }

  async readMany(inputs: readonly RpcReadRequest[], options?: RpcReadOptions) {
    const results = await this.readClient.readMany(inputs, options);
    for (const result of results) {
      if (
        result.status === 'rejected' &&
        result.reason instanceof RpcReadError
      ) {
        this.errorMessage = result.reason.message;
        break;
      }
    }
    return results;
  }

  // Ethers uses this primitive for network auto-detection and inherited send.
  // Share wire IDs and validation, then restore its caller IDs after correlation.
  override async _send(
    payload: JsonRpcPayload | Array<JsonRpcPayload>
  ): Promise<any[]> {
    const inputs = Array.isArray(payload) ? payload : [payload];
    if (!inputs.length) return [];
    const callerIds = inputs.map(({ id }) => id);
    if (inputs.every(({ method }) => isReadOnlyRpcMethod(method))) {
      const results = await this.readMany(inputs);
      return results.map((result, index) => {
        if (result.status === 'fulfilled')
          return { jsonrpc: '2.0', id: callerIds[index], result: result.value };
        if (!(result.reason instanceof RpcReadError)) throw result.reason;
        const { code, message, data } = result.reason;
        return {
          jsonrpc: '2.0',
          id: callerIds[index],
          error: { code, message, data },
        };
      });
    }
    const responses = await this.requestRpc(inputs, Array.isArray(payload));
    return responses.map((response, index) => ({
      ...response,
      id: callerIds[index],
    }));
  }

  override send = async (method: string, params: any[]) => {
    if (method === 'eth_chainId') return this.readChainId(false);
    if (isReadOnlyRpcMethod(method)) {
      const [result] = await this.readMany([{ method, params }]);
      if (result.status === 'rejected') throw result.reason;
      return result.value;
    }
    const [json] = await this.requestRpc([{ method, params }], false);
    if (json.error) {
      this.errorMessage = json.error.message;
      throw makeRpcError(json.error);
    }
    return json.result;
  };

  async sendBatch(method: string, params: Array<any[]>): Promise<any[]> {
    if (!params.length) return [];
    if (isReadOnlyRpcMethod(method)) {
      const results = await this.readMany(
        params.map((param) => ({ method, params: param }))
      );
      return results.map((result) => {
        if (result.status === 'rejected') throw result.reason;
        return result.value;
      });
    }
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

  override destroy(): void {
    this.lifetime.abort(
      Object.assign(new Error('RPC provider destroyed'), { name: 'AbortError' })
    );
    this.releaseExternalSignal();
    this.readClient.destroy();
    super.destroy();
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
    this.assertActive();
    return wrapTransactionResponse(
      await this.broadcastTransaction(signedTransaction)
    );
  }

  override async broadcastTransaction(signedTransaction: string) {
    this.assertActive();
    return super.broadcastTransaction(signedTransaction);
  }
}

export class CustomJsonRpcProvider extends BaseProvider {
  constructor(
    signal: AbortSignal,
    url?: string | { url: string },
    network?: Networkish,
    options: RpcProviderOptions = {}
  ) {
    super(signal, url, network, options);
  }
}
