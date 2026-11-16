import { FeeData, Network } from 'ethers/providers';
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
  RpcHttpExecutor,
  captureRpcRequests,
  checkRpcSignal,
  RpcResponseIntegrityError,
  requestJsonRpc,
} from './rpc-transport';

import type { JsonRpcPayload } from 'ethers/providers';

export { RpcResponseIntegrityError } from './rpc-transport';
export type RpcProviderOptions = Omit<RpcReadClientOptions, 'signal'>;
export type RpcFeeReadTransport = Readonly<{
  signal?: AbortSignal;
  getBlock(tag: 'latest'): Promise<{ baseFeePerGas?: unknown } | null>;
  send(
    method: 'eth_gasPrice' | 'eth_maxPriorityFeePerGas',
    params: unknown[]
  ): Promise<unknown>;
}>;

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
const queuedReadFailure = Symbol('queuedReadFailure');

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

export class CustomJsonRpcProvider extends JsonRpcProvider {
  private cooldownTime = 120 * 1000;
  private cooldownUntil = 0;
  private readonly fetcher: NonNullable<RpcReadClientOptions['fetch']>;
  private readonly requestInit: NonNullable<
    RpcReadClientOptions['requestInit']
  >;
  private readonly http: RpcHttpExecutor;
  private feeDataCache: { expiresAt: number; value: any } | null = null;
  private feeBlock?: {
    expiresAt: number;
    block: { baseFeePerGas?: unknown } | null;
  };
  private readonly configuredChainId?: bigint;
  private chainIdVerificationPromise: Promise<void> | null = null;
  private readonly readClient: JsonRpcReadClient;
  private readonly lifetime = new AbortController();
  private readonly ccipReads = new WeakMap<
    string[],
    { signal: AbortSignal; failure?: unknown }
  >();
  private releaseExternalSignal: () => void;
  public isInCooldown = false;
  public errorMessage: any = '';
  public serverHasAnError = false;
  signal: AbortSignal;

  constructor(
    signal: AbortSignal,
    url?: string | { url: string },
    network?: Networkish,
    options: RpcProviderOptions = {}
  ) {
    super(typeof url === 'string' ? url : url?.url, network, {
      ...(network == null ? {} : { staticNetwork: true }),
      batchStallTime: 4,
      // Ethers counts UTF-16 code units; the executor enforces UTF-8 bytes.
      batchMaxSize: Math.min(
        1024 * 1024,
        Math.floor(((options.maxRequestBytes ?? 256 * 1024) * 16) / 3)
      ),
    });
    Object.defineProperty(this, 'configuredChainId', {
      value: network == null ? undefined : Network.from(network).chainId,
    });
    this.signal = this.lifetime.signal;
    const abort = () => this.lifetime.abort(signal.reason);
    this.releaseExternalSignal = () =>
      signal.removeEventListener('abort', abort);
    if (signal.aborted) abort();
    else signal.addEventListener('abort', abort, { once: true });
    this.fetcher = options.fetch ?? ((address, init) => fetch(address, init));
    this.requestInit = {
      ...options.requestInit,
      headers: new Headers(options.requestInit?.headers),
    };
    this.http = new RpcHttpExecutor({
      ...options,
      fetch: (address, init) => this.fetchRpc(address, init),
      signal: this.lifetime.signal,
    });
    this.readClient = new JsonRpcReadClient(
      this._getConnection().url,
      {
        ...options,
        requestInit: this.requestInit,
        fetch: (address, init) => this.fetchRpc(address, init),
        signal: this.lifetime.signal,
      },
      this.http
    );
    this.send = this.send.bind(this);
    // The former base-class constructor bound an external subclass's own methods.
    if (new.target !== CustomJsonRpcProvider) this.bindMethods();
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

  private assertActive(reader?: RpcFeeReadTransport): void {
    const ended = [this.lifetime.signal, reader?.signal].find(
      (signal) => signal?.aborted
    );
    if (ended)
      throw ended.reason instanceof Error
        ? ended.reason
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
    const actualChainId = BigInt(actual);
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
    batch: boolean,
    signal?: AbortSignal
  ): Promise<any[]> {
    this.assertActive();
    const captured = captureRpcRequests(inputs as RpcReadRequest[]);
    const headers = new Headers(this.requestInit.headers);
    headers.set('Content-Type', 'application/json');
    headers.set('Accept', 'application/json');
    return this.http.run([signal], (signal) =>
      requestJsonRpc(
        this._getConnection().url,
        captured,
        batch,
        signal,
        (url, body) =>
          this.http.request(
            url,
            {
              ...this.requestInit,
              method: 'POST',
              headers,
              body,
              redirect: 'error',
            },
            signal,
            {
              process: (json, response) => {
                if (!response.ok) {
                  this.errorMessage =
                    json?.error || json?.message || 'No message from Provider';
                  handleStatusCodeError(response.status, this.errorMessage);
                }
                if (response.status !== 200)
                  throw new Error(
                    `Unexpected HTTP status code: ${response.status}`
                  );
                return json;
              },
            }
          ),
        false
      )
    );
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
      if (
        !Array.isArray(payload) &&
        results[0].status === 'rejected' &&
        !(results[0].reason instanceof RpcReadError)
      )
        throw results[0].reason;
      return results.map((result, index) => {
        if (result.status === 'fulfilled')
          return { jsonrpc: '2.0', id: callerIds[index], result: result.value };
        return {
          jsonrpc: '2.0',
          id: callerIds[index],
          error: {
            code:
              result.reason instanceof RpcReadError
                ? result.reason.code
                : -32603,
            message:
              result.reason instanceof Error
                ? result.reason.message
                : 'RPC read failed',
            data:
              result.reason instanceof RpcReadError
                ? result.reason.data
                : undefined,
            [queuedReadFailure]: result.reason,
          },
        };
      });
    }
    const responses = await this.requestRpc(inputs, Array.isArray(payload));
    return responses.map((response, index) => ({
      ...response,
      id: callerIds[index],
    }));
  }

  override getRpcError(payload: JsonRpcPayload, response: any): Error {
    if (
      response.error &&
      queuedReadFailure in response.error &&
      !(response.error[queuedReadFailure] instanceof RpcReadError)
    )
      return response.error[queuedReadFailure];
    return super.getRpcError(payload, response);
  }

  override async send(
    method: string,
    params: any[],
    options: Pick<RpcReadOptions, 'signal'> = {}
  ) {
    if (method === 'eth_chainId') return this.readClient.getChainId(options);
    if (isReadOnlyRpcMethod(method)) {
      this.assertActive();
      if (
        options.signal ||
        this.configuredChainId == null ||
        !this.readClient.supportsBatch
      ) {
        const [result] = await this.readMany([{ method, params }], options);
        if (result.status === 'rejected') {
          if (!(result.reason instanceof RpcReadError)) throw result.reason;
          throw this.getRpcError(
            { jsonrpc: '2.0', id: 1, method, params },
            { error: result.reason }
          );
        }
        return result.value;
      }
      const [{ params: snapshot }] = captureRpcRequests([{ method, params }]);
      let result;
      try {
        result = await super.send(method, snapshot);
      } catch (error) {
        this.assertActive();
        throw error;
      }
      this.assertActive();
      return result;
    }
    const [json] = await this.requestRpc(
      [{ method, params }],
      false,
      options.signal
    );
    if (json.error) {
      this.errorMessage = json.error.message;
      throw new RpcReadError(json.error);
    }
    return json.result;
  }

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
        throw new RpcReadError(json.error);
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

  override ccipReadFetch(
    transaction: Parameters<JsonRpcProvider['ccipReadFetch']>[0],
    calldata: string,
    urls: string[]
  ): Promise<string | null> {
    const capturedUrls = [...urls];
    return this.http.run([], async (signal) => {
      const owner = { signal, failure: undefined as unknown };
      this.ccipReads.set(capturedUrls, owner);
      try {
        const value = await super.ccipReadFetch(
          transaction,
          calldata,
          capturedUrls
        );
        checkRpcSignal(signal);
        if (owner.failure) throw owner.failure;
        return value;
      } catch (error) {
        checkRpcSignal(signal);
        throw owner.failure ?? error;
      } finally {
        this.ccipReads.delete(capturedUrls);
      }
    });
  }

  override emit(
    event: Parameters<JsonRpcProvider['emit']>[0],
    ...args: unknown[]
  ): Promise<boolean> {
    const value = args[0] as
      | { action?: string; request?: FetchRequest; urls?: string[] }
      | undefined;
    if (event === 'debug' && value?.action === 'sendCcipReadFetchRequest') {
      const owner = value.urls && this.ccipReads.get(value.urls);
      if (owner && value.request instanceof FetchRequest) {
        const request = value.request;
        checkRpcSignal(owner.signal);
        if (owner.failure) throw owner.failure;
        request.timeout = this.http.timeoutMs;
        request.setThrottleParams({ maxAttempts: 1 });
        request.getUrlFunc = async (wire) => {
          try {
            checkRpcSignal(owner.signal);
            if (owner.failure) throw owner.failure;
            const url = new URL(wire.url);
            if (
              wire.url.length > 4096 ||
              url.username ||
              url.password ||
              url.hash ||
              (url.protocol !== 'https:' &&
                !(
                  url.protocol === 'http:' &&
                  ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)
                )) ||
              !['GET', 'POST'].includes(wire.method)
            )
              throw new RpcResponseIntegrityError(
                'Invalid CCIP gateway request',
                false
              );
            return await this.http.request(
              wire.url,
              {
                method: wire.method,
                headers: wire.headers,
                body: wire.body ? Uint8Array.from(wire.body).buffer : undefined,
                credentials: 'omit',
                redirect: 'error',
                cache: 'no-store',
                referrerPolicy: 'no-referrer',
              },
              owner.signal,
              {
                fetch: (url, init) => fetch(url, init),
                format: 'text',
                validate: (response) => {
                  if (
                    response.redirected ||
                    (response.url && response.url !== wire.url) ||
                    (response.status >= 300 && response.status < 400)
                  )
                    throw new RpcResponseIntegrityError(
                      'CCIP gateway redirect refused',
                      false
                    );
                },
                process: (text, response) => {
                  const headers: Record<string, string> = {};
                  response.headers.forEach((value, name) => {
                    headers[name] = value;
                  });
                  return {
                    statusCode: response.status,
                    statusMessage: response.statusText,
                    headers,
                    body: new TextEncoder().encode(text),
                  };
                },
              }
            );
          } catch (error) {
            if (error instanceof RpcResponseIntegrityError)
              owner.failure = error;
            throw error;
          }
        };
      }
    }
    return super.emit(event, ...args);
  }

  async getGasPrice() {
    return BigNumber.from(await this.send('eth_gasPrice', []));
  }

  async getFeeData(reader?: RpcFeeReadTransport): Promise<any> {
    this.assertActive(reader);
    if (reader)
      return this.http.run([reader.signal], (signal) =>
        this.readFeeData(reader, signal)
      );
    if (!this.feeDataCache || this.feeDataCache.expiresAt <= Date.now()) {
      const cached = {
        expiresAt: Infinity,
        value: this.http.run([], (signal) =>
          this.readFeeData(undefined, signal)
        ),
      };
      this.feeDataCache = cached;
      void cached.value.then(
        () => {
          cached.expiresAt = Date.now() + FEE_DATA_CACHE_TTL_MS;
        },
        () => {
          if (this.feeDataCache === cached) this.feeDataCache = null;
        }
      );
    }
    return this.feeDataCache.value;
  }

  private async readFeeData(
    reader: RpcFeeReadTransport | undefined,
    signal: AbortSignal
  ): Promise<any> {
    const network = await this.getNetwork();
    checkRpcSignal(signal);
    let raw: Promise<PromiseSettledResult<unknown>[]> | undefined;
    const read = (index: number) => {
      raw ??= this.readMany(
        [
          { method: 'eth_getBlockByNumber', params: ['latest', false] },
          { method: 'eth_gasPrice', params: [] },
          { method: 'eth_maxPriorityFeePerGas', params: [] },
        ],
        { signal }
      );
      return raw.then((results) => {
        const result = results[index];
        if (result.status === 'rejected') throw result.reason;
        if (
          index === 0 &&
          result.value !== null &&
          (typeof result.value !== 'object' || Array.isArray(result.value))
        )
          throw new RpcResponseIntegrityError('Invalid fee block', false);
        if (index === 0 && result.value !== null)
          return this._wrapBlock(
            result.value as Parameters<typeof this._wrapBlock>[0],
            network
          );
        return result.value;
      });
    };
    const optionalFee = async (
      method: 'eth_gasPrice' | 'eth_maxPriorityFeePerGas'
    ) => {
      try {
        checkRpcSignal(signal);
        return getBigInt(
          reader
            ? await reader.send(method, [])
            : ((await read(method === 'eth_gasPrice' ? 1 : 2)) as any),
          '%response'
        );
      } catch (error) {
        checkRpcSignal(signal);
        if (
          error?.code === 'SYSWEB3_RPC_RESPONSE_INVALID' ||
          error?.name === 'AbortError'
        )
          throw error;
        return null;
      }
    };
    let observation:
      | Promise<{ block: { baseFeePerGas?: unknown } | null; fees: FeeData }>
      | undefined;
    const observe = () =>
      (observation ??= (async () => {
        checkRpcSignal(signal);
        const [block, gasPrice, priorityFee] = await Promise.all([
          reader
            ? reader.getBlock('latest')
            : (read(0) as Promise<{ baseFeePerGas?: unknown } | null>),
          optionalFee('eth_gasPrice'),
          optionalFee('eth_maxPriorityFeePerGas'),
        ]);
        checkRpcSignal(signal);
        const present = block?.baseFeePerGas != null && priorityFee != null;
        return {
          block,
          fees: new FeeData(
            gasPrice,
            present
              ? getBigInt(block!.baseFeePerGas as any) * 2n + priorityFee!
              : null,
            present ? priorityFee : null
          ),
        };
      })());
    const plugin = network.getPlugin(
      'org.ethers.plugins.network.FetchUrlFeeDataPlugin'
    ) as any;
    let fees: FeeData;
    if (plugin) {
      const request = new FetchRequest(plugin.url);
      request.timeout = this.http.timeoutMs;
      let failure: unknown;
      let attempts = 0;
      let redirected: FetchRequest | undefined;
      const cancel = () => {
        try {
          request.cancel();
        } catch {
          /* The plugin may not have sent its request. */
        }
      };
      signal.addEventListener('abort', cancel, { once: true });
      const browser =
        /^\[object (?:Window|DedicatedWorkerGlobalScope|SharedWorkerGlobalScope|ServiceWorkerGlobalScope)\]$/.test(
          Object.prototype.toString.call(globalThis)
        );
      request.getUrlFunc = async (initial, cancellation) => {
        let current = redirected ?? initial;
        for (;;) {
          checkRpcSignal(signal);
          cancellation?.checkSignal();
          const protocol = new URL(current.url).protocol;
          if (!['http:', 'https:'].includes(protocol))
            throw new Error('Unsupported fee request protocol');
          if (
            protocol !== 'https:' &&
            current.credentials &&
            !current.allowInsecureAuthentication
          )
            throw new Error('Insecure fee request credentials');
          const body = current.body;
          const response = await this.http.request(
            current.url,
            {
              method: current.method,
              headers: current.headers,
              body: body ? Uint8Array.from(body).buffer : undefined,
              redirect: browser ? 'follow' : 'manual',
            },
            signal,
            {
              fetch: (url, init) => fetch(url, init),
              format: 'text',
              before: () => {
                if (++attempts > 12)
                  throw new Error('Fee request attempt limit exceeded');
              },
              validate: (response) => {
                if (browser && response.url && response.url !== current.url)
                  current.redirect(response.url);
              },
              process: (text, response) => {
                if (![200, 301, 302, 307, 308, 429].includes(response.status))
                  throw Object.assign(
                    new Error(`Fee HTTP ${response.status}`),
                    { status: response.status }
                  );
                const headers: Record<string, string> = {};
                response.headers.forEach((value, key) => {
                  headers[key.toLowerCase()] = value;
                });
                if (response.status === 429 && headers['retry-after']) {
                  const retry = headers['retry-after'].trim();
                  const delay = /^\d+$/.test(retry)
                    ? Number(retry) * 1000
                    : Date.parse(retry) - Date.now();
                  if (delay > 0)
                    headers['retry-after'] = String(
                      Math.min(Math.ceil(delay), this.http.timeoutMs + 1)
                    );
                  else if (delay === 0) headers['retry-after'] = '1';
                  else delete headers['retry-after'];
                }
                return {
                  statusCode: response.status,
                  statusMessage: response.statusText,
                  headers,
                  body: new TextEncoder().encode(text),
                };
              },
              failed: (error) => {
                failure = error;
                return error;
              },
            }
          );
          if (![301, 302, 307, 308].includes(response.statusCode))
            return response;
          current = current.redirect(response.headers.location ?? '');
          redirected = current;
        }
      };
      try {
        const result = await plugin.processFunc(
          async () => {
            try {
              return (await observe()).fees;
            } catch (error) {
              failure = error;
              throw error;
            }
          },
          this,
          request
        );
        checkRpcSignal(signal);
        if (failure) throw failure;
        fees = new FeeData(
          result.gasPrice,
          result.maxFeePerGas,
          result.maxPriorityFeePerGas
        );
      } catch (error) {
        throw failure ?? error;
      } finally {
        signal.removeEventListener('abort', cancel);
        cancel();
      }
    } else fees = (await observe()).fees;
    const { block } = await observe();
    checkRpcSignal(signal);
    if (
      !block &&
      (fees.maxFeePerGas == null || fees.maxPriorityFeePerGas == null)
    )
      throw new Error('Block not found');
    if (
      block?.baseFeePerGas != null &&
      (fees.maxFeePerGas == null || fees.maxPriorityFeePerGas == null)
    )
      throw new Error('EIP-1559 fee data unavailable');
    if (
      (fees.maxFeePerGas != null && fees.maxFeePerGas < 0n) ||
      (fees.maxPriorityFeePerGas != null &&
        (fees.maxPriorityFeePerGas < 0n ||
          (fees.maxFeePerGas != null &&
            fees.maxPriorityFeePerGas > fees.maxFeePerGas)))
    )
      throw new Error('Invalid EIP-1559 fee data');
    if (fees.gasPrice != null && fees.gasPrice < 0n)
      throw new Error('Invalid gas price');
    if (!reader)
      this.feeBlock = { expiresAt: Date.now() + FEE_DATA_CACHE_TTL_MS, block };
    return {
      gasPrice: fees.gasPrice == null ? null : BigNumber.from(fees.gasPrice),
      maxFeePerGas:
        fees.maxFeePerGas == null ? null : BigNumber.from(fees.maxFeePerGas),
      maxPriorityFeePerGas:
        fees.maxPriorityFeePerGas == null
          ? null
          : BigNumber.from(fees.maxPriorityFeePerGas),
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
      const block =
        this.feeBlock && this.feeBlock.expiresAt > Date.now()
          ? this.feeBlock.block
          : await super.getBlock('latest');
      this.assertActive();
      if (block && block.baseFeePerGas == null) delete normalized.type;
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
