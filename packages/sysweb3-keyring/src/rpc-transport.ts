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

const ownedParams = new WeakMap<object, number>();
const freezeRpcValue = (value: unknown): void => {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return;
  Object.values(value).forEach(freezeRpcValue);
  Object.freeze(value);
};
export function captureRpcRequests<T extends RpcTransportRequest>(
  inputs: readonly T[],
  maximumBytes = Infinity
): T[] {
  let size = 2;
  return inputs.map((input) => {
    if (
      input.params &&
      typeof input.params === 'object' &&
      ownedParams.has(input.params)
    ) {
      size += ownedParams.get(input.params)! + input.method.length + 27;
      if (size > maximumBytes)
        throw new Error('RPC read work exceeded request budget');
      return Object.freeze({ method: input.method, params: input.params }) as T;
    }
    const serialized = JSON.stringify(input);
    size += rpcByteLength(serialized) + 1;
    if (size > maximumBytes)
      throw new Error('RPC read work exceeded request budget');
    const captured = JSON.parse(serialized) as T;
    if (
      !captured ||
      typeof captured.method !== 'string' ||
      !captured.params ||
      typeof captured.params !== 'object'
    )
      throw new Error('Invalid RPC request');
    ownedParams.set(
      captured.params,
      rpcByteLength(JSON.stringify(captured.params))
    );
    freezeRpcValue(captured);
    return captured;
  });
}

export const rpcAbortError = (signal: AbortSignal): Error =>
  signal.reason instanceof Error
    ? signal.reason
    : Object.assign(new Error('RPC request aborted'), { name: 'AbortError' });
export const checkRpcSignal = (signal: AbortSignal): void => {
  if (signal.aborted) throw rpcAbortError(signal);
};
export const rpcByteLength = (value: string): number =>
  new TextEncoder().encode(value).byteLength;
export const rpcBound = (
  value: number,
  maximum: number,
  name: string
): number => {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum)
    throw new Error(`Invalid RPC ${name}`);
  return value;
};

type RpcHttpOptions = {
  fetch?: (url: string, init: RequestInit) => Promise<Response>;
  signal?: AbortSignal;
  maxRequestBytes?: number;
  maxResponseBytes?: number;
  maxConcurrency?: number;
  timeoutMs?: number;
};
type RpcHttpPolicy<T> = {
  format?: 'json' | 'text';
  fetch?: RpcHttpOptions['fetch'];
  maxResponseBytes?: number;
  before?: () => void;
  validate?: (response: Response) => void;
  process: (body: any, response: Response) => T;
  failed?: (error: unknown, response?: Response) => unknown;
};

/** One physical pool and complete-body lifetime for each endpoint owner. */
export class RpcHttpExecutor {
  readonly lifetime = new AbortController();
  readonly maxRequestBytes: number;
  readonly maxResponseBytes: number;
  readonly timeoutMs: number;
  private readonly maximum: number;
  private readonly fetcher: NonNullable<RpcHttpOptions['fetch']>;
  private active = 0;
  private releaseSignal: () => void;
  private queue: Array<{ run(): void; cancel(): void }> = [];
  constructor(options: RpcHttpOptions = {}) {
    this.maxRequestBytes = rpcBound(
      options.maxRequestBytes ?? 256 * 1024,
      2 * 1024 * 1024,
      'request size'
    );
    this.maxResponseBytes = rpcBound(
      options.maxResponseBytes ?? 2 * 1024 * 1024,
      8 * 1024 * 1024,
      'response size'
    );
    this.timeoutMs = rpcBound(options.timeoutMs ?? 12000, 30000, 'timeout');
    this.maximum = rpcBound(options.maxConcurrency ?? 4, 16, 'concurrency');
    this.fetcher = options.fetch ?? ((url, init) => fetch(url, init));
    const abort = () => this.lifetime.abort(options.signal?.reason);
    this.releaseSignal = () =>
      options.signal?.removeEventListener('abort', abort);
    if (options.signal?.aborted) abort();
    else options.signal?.addEventListener('abort', abort, { once: true });
  }
  destroy(reason?: unknown): void {
    this.releaseSignal();
    this.lifetime.abort(reason);
  }
  async run<T>(
    signals: readonly (AbortSignal | undefined)[],
    work: (signal: AbortSignal) => Promise<T>,
    timeoutMs = this.timeoutMs
  ): Promise<T> {
    rpcBound(timeoutMs, 30000, 'timeout');
    const controller = new AbortController();
    const sources = [this.lifetime.signal, ...signals].filter(
      (signal): signal is AbortSignal => !!signal
    );
    const abort = () =>
      controller.abort(sources.find((signal) => signal.aborted)?.reason);
    sources.forEach((signal) =>
      signal.addEventListener('abort', abort, { once: true })
    );
    if (sources.some((signal) => signal.aborted)) abort();
    const timer = setTimeout(
      () =>
        controller.abort(
          Object.assign(new Error('RPC request deadline exceeded'), {
            name: 'AbortError',
          })
        ),
      timeoutMs
    );
    const signal = controller.signal;
    let cancel = () => {};
    try {
      checkRpcSignal(signal);
      return await new Promise<T>((resolve, reject) => {
        cancel = () => reject(rpcAbortError(signal));
        signal.addEventListener('abort', cancel, { once: true });
        void work(signal).then(resolve, reject);
      });
    } finally {
      clearTimeout(timer);
      signal.removeEventListener('abort', cancel);
      sources.forEach((source) => source.removeEventListener('abort', abort));
      if (!signal.aborted) controller.abort();
    }
  }
  async request<T>(
    url: string,
    init: RequestInit,
    signal: AbortSignal,
    policy: RpcHttpPolicy<T>
  ): Promise<T> {
    let response: Response | undefined;
    let admitted = false;
    let reading = false;
    try {
      checkRpcSignal(signal);
      const bodySize =
        typeof init.body === 'string'
          ? rpcByteLength(init.body)
          : init.body instanceof ArrayBuffer || ArrayBuffer.isView(init.body)
          ? init.body.byteLength
          : 0;
      if (bodySize > this.maxRequestBytes)
        throw new Error('RPC request exceeded size limit');
      await new Promise<void>((resolve, reject) => {
        const entry = {
          run: () => {
            signal.removeEventListener('abort', entry.cancel);
            this.active++;
            resolve();
          },
          cancel: () => {
            const index = this.queue.indexOf(entry);
            if (index >= 0) this.queue.splice(index, 1);
            reject(rpcAbortError(signal));
          },
        };
        if (this.active < this.maximum) entry.run();
        else {
          this.queue.push(entry);
          signal.addEventListener('abort', entry.cancel, { once: true });
        }
      });
      admitted = true;
      checkRpcSignal(signal);
      policy.before?.();
      response = await (policy.fetch ?? this.fetcher)(url, { ...init, signal });
      checkRpcSignal(signal);
      policy.validate?.(response);
      reading = true;
      const body = await readJsonRpcResponse(
        response,
        policy.maxResponseBytes ?? this.maxResponseBytes,
        signal,
        policy.format === 'text'
      );
      checkRpcSignal(signal);
      return policy.process(body, response);
    } catch (error) {
      throw policy.failed ? policy.failed(error, response) : error;
    } finally {
      if (response && !reading) await cancelRpcResponse(response);
      if (admitted) {
        this.active--;
        this.queue.shift()?.run();
      }
    }
  }
}

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

// Only a local byte limit can be recovered by dividing a read-only batch.
export class RpcResponseSizeError extends RpcResponseIntegrityError {
  constructor() {
    super('RPC response exceeded size limit', false);
    this.name = 'RpcResponseSizeError';
  }
}

export async function cancelRpcResponse(response: Response): Promise<void> {
  try {
    await response.body?.cancel();
  } catch {
    // Cancellation may reject after the underlying stream has already closed.
  }
}

export async function readRpcResponseText(
  response: Response,
  maximum: number,
  signal: AbortSignal
): Promise<string> {
  const declared = response.headers.get('content-length');
  if (declared !== null && !/^\d+$/.test(declared)) {
    await cancelRpcResponse(response);
    throw new RpcResponseIntegrityError('Invalid RPC content length', false);
  }
  if (declared !== null && Number(declared) > maximum) {
    await cancelRpcResponse(response);
    throw new RpcResponseSizeError();
  }
  if (!response.body?.getReader) {
    try {
      const text = await response.text();
      checkRpcSignal(signal);
      if (new TextEncoder().encode(text).byteLength > maximum)
        throw new RpcResponseSizeError();
      return text;
    } finally {
      await cancelRpcResponse(response);
    }
  }
  let reader: ReadableStreamDefaultReader<Uint8Array>;
  try {
    reader = response.body.getReader();
  } catch (error) {
    await cancelRpcResponse(response);
    throw error;
  }
  const decoder = new TextDecoder('utf-8', { fatal: true });
  const decode = (chunk?: Uint8Array, stream = false) => {
    try {
      return decoder.decode(chunk, { stream });
    } catch {
      throw new RpcResponseIntegrityError(
        'Invalid JSON-RPC UTF-8 response',
        false
      );
    }
  };
  let size = 0;
  let text = '';
  let cancellation: Promise<void> | undefined;
  const cancel = () => {
    cancellation ??= (async () => {
      try {
        await reader.cancel();
      } catch {
        // Keep cleanup owned until cancellation settles, including rejection.
      }
    })();
    return cancellation;
  };
  signal.addEventListener('abort', cancel, { once: true });
  try {
    let complete = false;
    while (!complete) {
      checkRpcSignal(signal);
      const part = await reader.read();
      checkRpcSignal(signal);
      if (part.done) {
        complete = true;
        continue;
      }
      size += part.value.byteLength;
      if (size > maximum) throw new RpcResponseSizeError();
      text += decode(part.value, true);
    }
    return text + decode();
  } finally {
    signal.removeEventListener('abort', cancel);
    await cancel();
    reader.releaseLock();
  }
}

/** Read one bounded JSON response. The caller owns HTTP policy and correlation. */
export async function readJsonRpcResponse(
  response: Response,
  maximum: number,
  signal: AbortSignal,
  retainText = false
): Promise<unknown> {
  let readingBody = false;
  try {
    checkRpcSignal(signal);
    const contentType = response.headers.get('content-type');
    if (
      (!retainText || response.status === 200) &&
      contentType &&
      !/^(application\/json|application\/[a-z0-9!#$&^_.+-]+\+json)(?:\s*;|$)/i.test(
        contentType
      )
    )
      throw new RpcResponseIntegrityError(
        'Invalid JSON-RPC content type',
        false
      );
    readingBody = true;
    const text = await readRpcResponseText(response, maximum, signal);
    checkRpcSignal(signal);
    if (retainText && response.status !== 200) return text;
    try {
      const json = JSON.parse(text);
      return retainText ? text : json;
    } catch {
      throw new RpcResponseIntegrityError(
        'Invalid JSON-RPC JSON response',
        false
      );
    }
  } finally {
    if (!readingBody) await cancelRpcResponse(response);
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
  const source = captureRpcRequests(inputs);
  const canRecover =
    recoverResponse &&
    source.every(({ method }) => RECOVERABLE_READ_METHODS.has(method));
  for (let attempt = 0; attempt < 2; attempt++) {
    checkRpcSignal(signal);
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
