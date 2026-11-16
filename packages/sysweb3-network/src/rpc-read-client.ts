import {
  isReadOnlyRpcMethod,
  captureRpcRequests,
  RpcHttpExecutor,
  rpcBound as boundedInteger,
  rpcByteLength as byteLength,
  rpcAbortError as aborted,
  checkRpcSignal as check,
  requestJsonRpc,
  RpcResponseIntegrityError,
  RpcResponseSizeError,
  type RpcReadRequest,
  type RpcResponse,
} from './rpc-transport';

export type { RpcReadRequest } from './rpc-transport';
export type RpcReadOptions = {
  signal?: AbortSignal;
  timeoutMs?: number;
  maxResponseBytes?: number;
};
export type RpcReadClientOptions = {
  fetch?: (url: string, init: RequestInit) => Promise<Response>;
  capabilities?: RpcReadCapabilities;
  requestInit?: Omit<RequestInit, 'method' | 'body' | 'signal'>;
  recoverResponse?: boolean;
  signal?: AbortSignal;
  maxBatchItems?: number;
  maxRequestBytes?: number;
  maxResponseBytes?: number;
  maxConcurrency?: number;
  timeoutMs?: number;
};
type ChainRequest = {
  maxResponseBytes: number;
  promise: Promise<string>;
  controller: AbortController;
  subscribers: number;
  settled: boolean;
};

/** Endpoint capability metadata only. Responses and request lifetimes remain private to each client. */
export class RpcReadCapabilities {
  private batch?: { limit: number; expires: number };
  constructor(readonly url: string) {
    if (!['http:', 'https:'].includes(new URL(url).protocol))
      throw new Error('Invalid RPC URL');
  }

  getBatchLimit(maximum: number): number {
    boundedInteger(maximum, 128, 'batch size');
    if (this.batch && this.batch.expires > Date.now())
      return Math.min(maximum, this.batch.limit);
    this.batch = undefined;
    return maximum;
  }

  restrictBatch(limit: number): void {
    boundedInteger(limit, 128, 'batch size');
    const current = this.getBatchLimit(limit);
    this.batch = {
      limit: Math.min(current, limit),
      expires: Date.now() + 30000,
    };
  }
}

class RpcBatchRefused extends Error {}
class RpcBatchAmbiguous extends Error {}
class RpcBatchReplan extends RpcResponseIntegrityError {
  constructor() {
    super('Queued RPC batch requires a smaller size', false);
  }
}
class RpcPayloadTooLarge extends Error {
  constructor(readonly endpointLimit = false) {
    super();
  }
}
class RpcBatchLimit extends Error {}
const validParams = (value: unknown): boolean =>
  value !== null && typeof value === 'object';
export class RpcReadError extends Error {
  readonly code: number;
  readonly data?: unknown;
  constructor(value: NonNullable<RpcResponse['error']>) {
    super(value.message);
    this.name = 'RpcReadError';
    this.code = value.code;
    this.data = value.data;
  }
}
const batchFailure = (value: unknown): Error | undefined => {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    return undefined;
  const { jsonrpc, result, error, id } = value as {
    jsonrpc?: unknown;
    result?: unknown;
    error?: { code?: number; message?: string };
    id?: unknown;
  };
  if (
    jsonrpc !== '2.0' ||
    result !== undefined ||
    (id !== null && id !== undefined) ||
    !error ||
    !Number.isSafeInteger(error.code) ||
    typeof error.message !== 'string'
  )
    return undefined;
  // A temporal request limit is transient even if it mentions batches.
  // A request count explicitly scoped to one batch is a size capability.
  if (
    /rate[ -]?limit|quota|throttl|(?:per|\/)\s*(?:second|minute|hour|day|sec\b|ms\b)|\brps\b/i.test(
      error.message
    ) ||
    (/too many requests/i.test(error.message) &&
      !/(?:in|per|for) (?:a |one |single )?batch|batch (?:size|count|length)/i.test(
        error.message
      ))
  )
    return new Error('RPC rate limit exceeded');
  if (
    error.code === -32600 &&
    /^invalid request[.!]?$/i.test(error.message.trim())
  )
    return new RpcBatchAmbiguous();
  if (
    (error.code === -32600 || error.code === -32005) &&
    /batch|array/i.test(error.message)
  ) {
    if (
      /too (?:large|many)|more than\s+\d+|(?:maximum|max)\s+(?:batch|request|item|size)|(?:batch|array|request|item)[ -]?(?:size|count|length)|batch[ -]?limit/i.test(
        error.message
      )
    )
      return new RpcBatchLimit();
    if (
      /unsupported|not support|not allowed|invalid (?:request|batch|array)/i.test(
        error.message
      )
    )
      return new RpcBatchRefused();
  }
  return undefined;
};

/** Bounded, read-only JSON-RPC transport. Each instance belongs to one endpoint generation. */
export class JsonRpcReadClient {
  private readonly endpoint: string;
  private readonly options;
  private readonly lifetime = new AbortController();
  readonly capabilities: RpcReadCapabilities;
  private chainGeneration = 0;
  private chainCache?: { value: string; expires: number };
  private chainRequest?: ChainRequest;
  readonly http: RpcHttpExecutor;

  constructor(
    url: string,
    options: RpcReadClientOptions = {},
    http?: RpcHttpExecutor
  ) {
    this.endpoint = url;
    const endpoint = new URL(url);
    if (!['https:', 'http:'].includes(endpoint.protocol))
      throw new Error('Invalid RPC URL');
    const maxBatchItems = boundedInteger(
      options.maxBatchItems ?? 40,
      128,
      'batch size'
    );
    if (options.capabilities && options.capabilities.url !== url)
      throw new Error('RPC capabilities belong to another endpoint');
    this.http = http ?? new RpcHttpExecutor(options);
    this.options = {
      requestInit: options.requestInit ?? {},
      recoverResponse: options.recoverResponse ?? true,
      maxBatchItems,
      maxRequestBytes: this.http.maxRequestBytes,
      maxResponseBytes: this.http.maxResponseBytes,
      timeoutMs: this.http.timeoutMs,
    };
    this.capabilities = options.capabilities ?? new RpcReadCapabilities(url);
    if (options.signal?.aborted) this.destroy();
    else
      options.signal?.addEventListener('abort', () => this.destroy(), {
        once: true,
      });
  }

  private get batchLimit(): number {
    return this.capabilities.getBatchLimit(this.options.maxBatchItems);
  }

  private set batchLimit(limit: number) {
    this.capabilities.restrictBatch(limit);
  }

  get url(): string {
    return this.endpoint;
  }

  get supportsBatch(): boolean {
    return this.batchLimit > 1;
  }

  destroy(): void {
    this.chainGeneration++;
    this.chainCache = undefined;
    this.chainRequest?.controller.abort();
    this.lifetime.abort();
    this.http.destroy();
  }

  async readMany(
    inputs: readonly RpcReadRequest[],
    options: RpcReadOptions = {}
  ): Promise<PromiseSettledResult<unknown>[]> {
    if (
      !Array.isArray(inputs) ||
      inputs.length > 1024 ||
      inputs.some(
        (input) =>
          !input ||
          !isReadOnlyRpcMethod(input.method) ||
          !validParams(input.params)
      )
    )
      throw new Error('Invalid read-only RPC requests');
    // Snapshot before any await so caller mutations cannot change dispatched reads.
    const snapshot = captureRpcRequests(
      inputs,
      this.options.maxRequestBytes * 16
    );
    if (
      !Array.isArray(snapshot) ||
      snapshot.length > 1024 ||
      snapshot.some(
        (input) =>
          !input ||
          !isReadOnlyRpcMethod(input.method) ||
          !validParams(input.params)
      )
    )
      throw new Error('Invalid read-only RPC requests');
    const timeout = boundedInteger(
      options.timeoutMs ?? this.options.timeoutMs,
      30000,
      'timeout'
    );
    const maximum = boundedInteger(
      options.maxResponseBytes ?? this.options.maxResponseBytes,
      8 * 1024 * 1024,
      'response size'
    );
    return this.http.run(
      [options.signal, this.lifetime.signal],
      async (signal) => {
        let localBatchLimit = this.batchLimit;
        let attempts = 0;
        const recordBatchLimit = (error: unknown, count: number) => {
          if (count <= 1) return;
          if (
            error instanceof RpcBatchRefused ||
            error instanceof RpcPayloadTooLarge ||
            error instanceof RpcBatchLimit
          ) {
            const limit =
              error instanceof RpcBatchRefused
                ? 1
                : Math.min(this.batchLimit, Math.ceil(count / 2));
            if (error instanceof RpcPayloadTooLarge && !error.endpointLimit)
              localBatchLimit = Math.min(localBatchLimit, limit);
            else this.batchLimit = limit;
          }
        };
        const request = (
          rows: readonly RpcReadRequest[],
          batch: boolean,
          recoverResponse = this.options.recoverResponse
        ) =>
          requestJsonRpc(
            this.url,
            rows,
            batch,
            signal,
            async (url, body) => {
              if (byteLength(body) > this.options.maxRequestBytes) {
                const error = new RpcPayloadTooLarge();
                recordBatchLimit(error, rows.length);
                throw error;
              }
              const headers = new Headers(this.options.requestInit.headers);
              headers.set('Content-Type', 'application/json');
              headers.set('Accept', 'application/json');
              return this.http.request(
                url,
                {
                  ...this.options.requestInit,
                  method: 'POST',
                  headers,
                  body,
                  redirect: 'error',
                },
                signal,
                {
                  maxResponseBytes: maximum,
                  format: batch ? 'text' : 'json',
                  before: () => {
                    if (rows.length > this.batchLimit)
                      throw new RpcBatchReplan();
                    if (++attempts > 2048)
                      throw new Error('RPC attempt limit exceeded');
                  },
                  validate: (response) => {
                    if (response.status === 413)
                      throw new RpcPayloadTooLarge(true);
                    if (
                      response.status !== 200 &&
                      !(batch && response.status === 400)
                    )
                      throw Object.assign(
                        new Error(`RPC HTTP ${response.status}`),
                        { status: response.status }
                      );
                  },
                  process: (json, response) => {
                    if (batch && typeof json === 'string') {
                      try {
                        json = JSON.parse(json);
                      } catch {
                        if (response.status === 400)
                          throw new RpcBatchAmbiguous();
                        throw new RpcResponseIntegrityError(
                          'Invalid JSON-RPC JSON response',
                          false
                        );
                      }
                    }
                    const failure = batch ? batchFailure(json) : undefined;
                    if (failure) throw failure;
                    if (response.status !== 200)
                      throw Object.assign(new Error('RPC HTTP 400'), {
                        status: 400,
                      });
                    return json;
                  },
                  failed: (error, response) => {
                    if (
                      response &&
                      response.status !== 200 &&
                      error instanceof RpcResponseSizeError
                    )
                      error = new RpcResponseIntegrityError(
                        'RPC error response exceeded size limit',
                        false
                      );
                    recordBatchLimit(error, rows.length);
                    return error;
                  },
                }
              );
            },
            recoverResponse
          );
        const executeChunks = async (
          rows: readonly RpcReadRequest[],
          recoverResponse = this.options.recoverResponse
        ): Promise<PromiseSettledResult<unknown>[]> => {
          const chunks: Array<Promise<PromiseSettledResult<unknown>[]>> = [];
          const limit = Math.min(this.batchLimit, localBatchLimit);
          for (let offset = 0; offset < rows.length; offset += limit)
            chunks.push(
              execute(rows.slice(offset, offset + limit), recoverResponse)
            );
          return (await Promise.all(chunks)).flat();
        };
        const execute = async (
          rows: readonly RpcReadRequest[],
          recoverResponse = this.options.recoverResponse
        ): Promise<PromiseSettledResult<unknown>[]> => {
          check(signal);
          try {
            const responses = await request(
              rows,
              rows.length > 1,
              recoverResponse
            );
            return responses.map((response) => {
              if (response.error)
                return {
                  status: 'rejected',
                  reason: new RpcReadError(response.error),
                };
              return { status: 'fulfilled', value: response.result };
            });
          } catch (error) {
            check(signal);
            if (rows.length > 1 && error instanceof RpcResponseSizeError) {
              // The byte limit applies to this response, not the endpoint's batch
              // capability. Children retain this operation's deadline and queue.
              const middle = Math.ceil(rows.length / 2);
              const children = await Promise.all([
                execute(rows.slice(0, middle), recoverResponse),
                execute(rows.slice(middle), recoverResponse),
              ]);
              return children.flat();
            }
            if (error instanceof RpcBatchReplan)
              return executeChunks(rows, recoverResponse);
            if (rows.length > 1 && error instanceof RpcBatchAmbiguous) {
              // A generic envelope error alone is insufficient evidence. Probe one
              // proper single request and retain its result without sending it again.
              const [probe] = await execute(rows.slice(0, 1), false);
              if (
                probe.status === 'fulfilled' ||
                probe.reason instanceof RpcReadError
              ) {
                this.batchLimit = 1;
                return [probe, ...(await executeChunks(rows.slice(1)))];
              }
              return rows.map(() => ({ status: 'rejected', reason: error }));
            }
            if (
              rows.length > 1 &&
              (error instanceof RpcBatchRefused ||
                error instanceof RpcPayloadTooLarge ||
                error instanceof RpcBatchLimit)
            ) {
              return executeChunks(rows);
            }
            return rows.map(() => ({ status: 'rejected', reason: error }));
          }
        };
        check(signal);
        return executeChunks(snapshot);
      },
      timeout
    );
  }

  async read(
    method: string,
    params: readonly unknown[],
    options?: RpcReadOptions
  ): Promise<unknown> {
    const [result] = await this.readMany([{ method, params }], options);
    if (result.status === 'rejected') throw result.reason;
    return result.value;
  }

  getChainId(
    options: RpcReadOptions & { fresh?: boolean } = {}
  ): Promise<string> {
    const timeout = boundedInteger(
      options.timeoutMs ?? this.options.timeoutMs,
      30000,
      'timeout'
    );
    const maxResponseBytes = boundedInteger(
      options.maxResponseBytes ?? this.options.maxResponseBytes,
      8 * 1024 * 1024,
      'response size'
    );
    if (options.signal?.aborted) return Promise.reject(aborted(options.signal));
    if (this.lifetime.signal.aborted)
      return Promise.reject(aborted(this.lifetime.signal));
    if (
      !options.fresh &&
      this.chainCache &&
      this.chainCache.expires > Date.now()
    )
      return Promise.resolve(this.chainCache.value);
    if (options.fresh) {
      this.chainRequest = undefined;
      this.chainCache = undefined;
    }
    let request =
      !options.fresh && this.chainRequest?.maxResponseBytes === maxResponseBytes
        ? this.chainRequest
        : undefined;
    if (!request) {
      const controller = new AbortController();
      const generation = ++this.chainGeneration;
      // Each subscriber owns its deadline. A short first subscriber must not
      // impose that deadline on later subscribers sharing the wire response.
      const promise = this.read('eth_chainId', [], {
        signal: controller.signal,
        timeoutMs: 30000,
        maxResponseBytes,
      }).then((value) => {
        if (
          typeof value !== 'string' ||
          !/^0x(?:0|[1-9a-f][0-9a-f]*)$/i.test(value)
        )
          throw new RpcResponseIntegrityError('Invalid chain ID', false);
        if (generation === this.chainGeneration && !controller.signal.aborted)
          this.chainCache = { value, expires: Date.now() + 30000 };
        return value;
      });
      request = {
        promise,
        controller,
        maxResponseBytes,
        subscribers: 0,
        settled: false,
      };
      const captured = request;
      void promise
        .finally(() => {
          captured.settled = true;
          if (this.chainRequest === captured) this.chainRequest = undefined;
        })
        .catch(() => undefined);
      if (!options.fresh) this.chainRequest = request;
    }
    const subscribed = request;
    subscribed.subscribers++;
    return new Promise((resolve, reject) => {
      let finished = false;
      const finish = (error?: unknown, value?: string) => {
        if (finished) return;
        finished = true;
        clearTimeout(timer);
        options.signal?.removeEventListener('abort', cancel);
        subscribed.subscribers--;
        if (!subscribed.subscribers && !subscribed.settled) {
          if (this.chainRequest === subscribed) this.chainRequest = undefined;
          subscribed.controller.abort();
        }
        if (error !== undefined) reject(error);
        else resolve(value!);
      };
      const cancel = () => finish(aborted(options.signal!));
      options.signal?.addEventListener('abort', cancel, { once: true });
      const timer = setTimeout(
        () =>
          finish(
            Object.assign(new Error('RPC read deadline exceeded'), {
              name: 'AbortError',
            })
          ),
        timeout
      );
      subscribed.promise.then(
        (value) => finish(undefined, value),
        (error) => finish(error)
      );
    });
  }
}
