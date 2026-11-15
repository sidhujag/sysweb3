import {
  isReadOnlyRpcMethod,
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
  promise: Promise<string>;
  controller: AbortController;
  subscribers: number;
  settled: boolean;
};

class RpcBatchRefused extends Error {}
class RpcPayloadTooLarge extends Error {}
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
  if (
    (error.code === -32600 || error.code === -32005) &&
    /batch|array/i.test(error.message)
  ) {
    if (
      /too (?:large|many)|more than|limit|maximum|max(?:imum)? size/i.test(
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

async function responseText(
  response: Response,
  maximum: number,
  signal: AbortSignal
): Promise<string> {
  const declared = response.headers.get('content-length');
  if (
    declared !== null &&
    (!/^\d+$/.test(declared) || Number(declared) > maximum)
  ) {
    void response.body?.cancel().catch(() => undefined);
    throw new RpcResponseIntegrityError(
      'RPC response exceeded size limit',
      false
    );
  }
  if (!response.body?.getReader) {
    const text = await response.text();
    check(signal);
    if (byteLength(text) > maximum)
      throw new RpcResponseIntegrityError(
        'RPC response exceeded size limit',
        false
      );
    return text;
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder('utf-8', { fatal: true });
  let size = 0;
  let text = '';
  try {
    let complete = false;
    while (!complete) {
      check(signal);
      const part = await reader.read();
      if (part.done) {
        complete = true;
        continue;
      }
      size += part.value.byteLength;
      if (size > maximum)
        throw new RpcResponseIntegrityError(
          'RPC response exceeded size limit',
          false
        );
      text += decoder.decode(part.value, { stream: true });
    }
    return text + decoder.decode();
  } finally {
    void reader.cancel().catch(() => undefined);
  }
}

/** Bounded, read-only JSON-RPC transport. Each instance belongs to one endpoint generation. */
export class JsonRpcReadClient {
  private readonly fetcher;
  private readonly endpoint: string;
  private readonly options;
  private readonly lifetime = new AbortController();
  private readonly queue: Waiter[] = [];
  private active = 0;
  private batchLimit: number;
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
    this.batchLimit = this.options.maxBatchItems;
    if (options.signal?.aborted) this.destroy();
    else
      options.signal?.addEventListener('abort', () => this.destroy(), {
        once: true,
      });
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
          !Array.isArray(input.params)
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
          !Array.isArray(input.params)
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
    const request = (rows: readonly RpcReadRequest[], batch: boolean) =>
      requestJsonRpc(
        this.url,
        rows,
        batch,
        signal,
        async (url, body) => {
          if (++attempts > 2048) throw new Error('RPC attempt limit exceeded');
          if (byteLength(body) > this.options.maxRequestBytes)
            throw new RpcPayloadTooLarge();
          return this.slot(signal, async () => {
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
            check(signal);
            if (response.status === 413) {
              void response.body?.cancel().catch(() => undefined);
              throw new RpcPayloadTooLarge();
            }
            const contentType = response.headers.get('content-type');
            if (
              contentType &&
              !/^(application\/json|application\/[a-z0-9!#$&^_.+-]+\+json)(?:\s*;|$)/i.test(
                contentType
              )
            ) {
              void response.body?.cancel().catch(() => undefined);
              throw new RpcResponseIntegrityError(
                'Invalid JSON-RPC content type',
                false
              );
            }
            const text = await responseText(response, maximum, signal);
            let json: unknown;
            try {
              json = JSON.parse(text);
            } catch {
              throw new RpcResponseIntegrityError(
                'Invalid JSON-RPC JSON response',
                false
              );
            }
            const batchError = batch ? batchFailure(json) : undefined;
            if (batchError) throw batchError;
            if (!response.ok || response.status !== 200)
              throw Object.assign(new Error(`RPC HTTP ${response.status}`), {
                status: response.status,
              });
            return json;
          });
        },
        this.options.recoverResponse
      );
    const execute = async (
      rows: readonly RpcReadRequest[]
    ): Promise<PromiseSettledResult<unknown>[]> => {
      check(signal);
      try {
        const responses = await request(rows, rows.length > 1);
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
        if (
          rows.length > 1 &&
          (error instanceof RpcBatchRefused ||
            error instanceof RpcPayloadTooLarge ||
            error instanceof RpcBatchLimit)
        ) {
          this.batchLimit =
            error instanceof RpcBatchRefused
              ? 1
              : Math.min(this.batchLimit, Math.ceil(rows.length / 2));
          const results: PromiseSettledResult<unknown>[] = [];
          let offset = 0;
          while (offset < rows.length) {
            const next = Math.min(rows.length, offset + this.batchLimit);
            const chunk = rows.slice(offset, next);
            offset = next;
            results.push(...(await execute(chunk)));
          }
          return results;
        }
        return rows.map(() => ({ status: 'rejected', reason: error }));
      }
    };
    try {
      check(signal);
      const batches: RpcReadRequest[][] = [];
      for (let i = 0; i < snapshot.length; i += this.batchLimit)
        batches.push(snapshot.slice(i, i + this.batchLimit));
      let next = 0;
      const results: PromiseSettledResult<unknown>[][] = new Array(
        batches.length
      );
      const workers = Array.from(
        { length: Math.min(batches.length, this.options.maxConcurrency) },
        async () => {
          while (next < batches.length) {
            const index = next++;
            results[index] = await execute(batches[index]);
          }
        }
      );
      const work = Promise.all(workers).then(() => results.flat());
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
    if (options.timeoutMs !== undefined)
      boundedInteger(options.timeoutMs, 30000, 'timeout');
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
    let request = options.fresh ? undefined : this.chainRequest;
    if (!request) {
      const controller = new AbortController();
      const generation = ++this.chainGeneration;
      const promise = this.read('eth_chainId', [], {
        signal: controller.signal,
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
      request = { promise, controller, subscribers: 0, settled: false };
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
      let timer: ReturnType<typeof setTimeout> | undefined;
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
      if (options.timeoutMs !== undefined) {
        const timeout = boundedInteger(options.timeoutMs, 30000, 'timeout');
        timer = setTimeout(
          () =>
            finish(
              Object.assign(new Error('RPC read deadline exceeded'), {
                name: 'AbortError',
              })
            ),
          timeout
        );
      }
      subscribed.promise.then(
        (value) => finish(undefined, value),
        (error) => finish(error)
      );
    });
  }
}
