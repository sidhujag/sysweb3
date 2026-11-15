import {
  isReadOnlyRpcMethod,
  cancelRpcResponse,
  readJsonRpcResponse,
  requestJsonRpc,
  RpcResponseIntegrityError,
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
type Waiter = { run(): void; cancel(): void };
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
const aborted = (signal: AbortSignal): Error => {
  if (signal.reason instanceof Error) return signal.reason;
  return Object.assign(new Error('RPC read aborted'), { name: 'AbortError' });
};
const check = (signal: AbortSignal) => {
  if (signal.aborted) throw aborted(signal);
};
const byteLength = (value: string) =>
  new TextEncoder().encode(value).byteLength;
const boundedInteger = (value: number, maximum: number, name: string) => {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum)
    throw new Error(`Invalid RPC ${name}`);
  return value;
};
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
  private readonly fetcher;
  private readonly endpoint: string;
  private readonly options;
  private readonly lifetime = new AbortController();
  private readonly queue: Waiter[] = [];
  private active = 0;
  private readonly capabilities: RpcReadCapabilities;
  private localBatchLimit: number;
  private chainGeneration = 0;
  private chainCache?: { value: string; expires: number };
  private chainRequest?: ChainRequest;

  constructor(url: string, options: RpcReadClientOptions = {}) {
    this.endpoint = url;
    const endpoint = new URL(url);
    if (!['https:', 'http:'].includes(endpoint.protocol))
      throw new Error('Invalid RPC URL');
    this.fetcher =
      options.fetch ??
      ((address: string, init: RequestInit) => fetch(address, init));
    this.options = {
      requestInit: options.requestInit ?? {},
      recoverResponse: options.recoverResponse ?? true,
      maxBatchItems: boundedInteger(
        options.maxBatchItems ?? 40,
        128,
        'batch size'
      ),
      maxRequestBytes: boundedInteger(
        options.maxRequestBytes ?? 256 * 1024,
        2 * 1024 * 1024,
        'request size'
      ),
      maxResponseBytes: boundedInteger(
        options.maxResponseBytes ?? 2 * 1024 * 1024,
        8 * 1024 * 1024,
        'response size'
      ),
      maxConcurrency: boundedInteger(
        options.maxConcurrency ?? 4,
        16,
        'concurrency'
      ),
      timeoutMs: boundedInteger(options.timeoutMs ?? 12000, 30000, 'timeout'),
    };
    if (options.capabilities && options.capabilities.url !== url)
      throw new Error('RPC capabilities belong to another endpoint');
    this.capabilities = options.capabilities ?? new RpcReadCapabilities(url);
    this.localBatchLimit = this.options.maxBatchItems;
    if (options.signal?.aborted) this.destroy();
    else
      options.signal?.addEventListener('abort', () => this.destroy(), {
        once: true,
      });
  }

  private get batchLimit(): number {
    return Math.min(
      this.localBatchLimit,
      this.capabilities.getBatchLimit(this.options.maxBatchItems)
    );
  }

  private set batchLimit(limit: number) {
    this.capabilities.restrictBatch(limit);
  }

  get url(): string {
    return this.endpoint;
  }

  destroy(): void {
    this.chainGeneration++;
    this.chainCache = undefined;
    this.chainRequest?.controller.abort();
    this.lifetime.abort();
  }

  private async slot<T>(
    signal: AbortSignal,
    work: () => Promise<T>
  ): Promise<T> {
    check(signal);
    await new Promise<void>((resolve, reject) => {
      const waiter: Waiter = {
        run: () => {
          signal.removeEventListener('abort', waiter.cancel);
          this.active++;
          resolve();
        },
        cancel: () => {
          const i = this.queue.indexOf(waiter);
          if (i >= 0) this.queue.splice(i, 1);
          reject(aborted(signal));
        },
      };
      if (this.active < this.options.maxConcurrency) waiter.run();
      else {
        this.queue.push(waiter);
        signal.addEventListener('abort', waiter.cancel, { once: true });
      }
    });
    try {
      check(signal);
      return await work();
    } finally {
      this.active--;
      this.queue.shift()?.run();
    }
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
    const serialized = JSON.stringify(inputs);
    if (byteLength(serialized) > this.options.maxRequestBytes * 16)
      throw new Error('RPC read work exceeded request budget');
    const snapshot = JSON.parse(serialized) as RpcReadRequest[];
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
    const controller = new AbortController();
    const abort = () =>
      controller.abort(options.signal?.reason ?? this.lifetime.signal.reason);
    const sources = [options.signal, this.lifetime.signal].filter(
      (value): value is AbortSignal => !!value
    );
    sources.forEach((source) =>
      source.addEventListener('abort', abort, { once: true })
    );
    if (sources.some((source) => source.aborted)) abort();
    const timer = setTimeout(
      () =>
        controller.abort(
          Object.assign(new Error('RPC read deadline exceeded'), {
            name: 'AbortError',
          })
        ),
      timeout
    );
    const signal = controller.signal;
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
          this.localBatchLimit = limit;
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
          return this.slot(signal, async () => {
            // A preceding request can learn a smaller limit while this chunk
            // waits for physical capacity. Repartition before sending it.
            if (rows.length > this.batchLimit) throw new RpcBatchReplan();
            if (++attempts > 2048)
              throw new Error('RPC attempt limit exceeded');
            const headers = new Headers(this.options.requestInit.headers);
            headers.set('Content-Type', 'application/json');
            headers.set('Accept', 'application/json');
            const response = await this.fetcher(url, {
              ...this.options.requestInit,
              method: 'POST',
              headers,
              body,
              signal,
            });
            let readingBody = false;
            try {
              check(signal);
              if (response.status === 413) throw new RpcPayloadTooLarge(true);
              // Inspect HTTP 400 for a protocol-level batch refusal.
              // Transient HTTP failures never establish a batch capability.
              const batchBadRequest = batch && response.status === 400;
              if ((!response.ok || response.status !== 200) && !batchBadRequest)
                throw Object.assign(new Error(`RPC HTTP ${response.status}`), {
                  status: response.status,
                });
              readingBody = true;
              const json = await readJsonRpcResponse(response, maximum, signal);
              const batchError = batch ? batchFailure(json) : undefined;
              if (batchError) throw batchError;
              if (batchBadRequest)
                throw Object.assign(new Error('RPC HTTP 400'), { status: 400 });
              return json;
            } catch (error) {
              // Publish endpoint feedback before releasing this physical slot.
              recordBatchLimit(error, rows.length);
              throw error;
            } finally {
              if (!readingBody) await cancelRpcResponse(response);
            }
          });
        },
        recoverResponse
      );
    const executeChunks = async (
      rows: readonly RpcReadRequest[],
      recoverResponse = this.options.recoverResponse
    ): Promise<PromiseSettledResult<unknown>[]> => {
      const chunks: Array<Promise<PromiseSettledResult<unknown>[]>> = [];
      const limit = this.batchLimit;
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
        const responses = await request(rows, rows.length > 1, recoverResponse);
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
    try {
      check(signal);
      const work = executeChunks(snapshot);
      return await new Promise((resolve, reject) => {
        const cancelled = () => reject(aborted(signal));
        signal.addEventListener('abort', cancelled, { once: true });
        work
          .then(resolve, reject)
          .finally(() => signal.removeEventListener('abort', cancelled));
      });
    } finally {
      clearTimeout(timer);
      sources.forEach((source) => source.removeEventListener('abort', abort));
    }
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
