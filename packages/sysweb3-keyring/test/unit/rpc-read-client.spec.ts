import { JsonRpcReadClient, RpcReadError } from '../../src/rpc-read-client';
import { RpcResponseIntegrityError } from '../../src/rpc-transport';

const URL = 'https://rpc.example/read?token=a%2Fb';
const input = (method = 'eth_getBalance', value = '0x1') => ({
  method,
  params: [value, 'latest'],
});
const response = (body: unknown, status = 200) =>
  ({
    ok: status === 200,
    status,
    headers: new Headers(),
    text: async () => JSON.stringify(body),
  } as Response);
const reply = (request: any, value: unknown = request.method) => ({
  jsonrpc: '2.0',
  id: request.id,
  result: value,
});
const deferred = <T>() => {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => (resolve = done));
  return { promise, resolve };
};
const tick = async () => {
  for (let i = 0; i < 8; i++) await Promise.resolve();
};

describe('bounded JSON-RPC read client', () => {
  it('batches heterogeneous reads, correlates reversed IDs and retains partial RPC errors', async () => {
    const fetcher = jest.fn(async (_url, init) => {
      const requests = JSON.parse(init.body);
      return response([
        reply(requests[2]),
        {
          jsonrpc: '2.0',
          id: requests[1].id,
          error: { code: 3, message: 'reverted', data: '0x1234' },
        },
        reply(requests[0]),
      ]);
    });
    const client = new JsonRpcReadClient(URL, { fetch: fetcher });
    const result = await client.readMany([
      input(),
      input('eth_call'),
      input('eth_getCode'),
    ]);
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(result[0]).toEqual({ status: 'fulfilled', value: 'eth_getBalance' });
    expect(result[2]).toEqual({ status: 'fulfilled', value: 'eth_getCode' });
    expect(result[1]).toMatchObject({
      status: 'rejected',
      reason: { code: 3, data: '0x1234' },
    });
    expect((result[1] as PromiseRejectedResult).reason).toBeInstanceOf(
      RpcReadError
    );
  });

  it.each([
    'eth_sendRawTransaction',
    'wallet_sendCalls',
    'eth_getFilterChanges',
    'eth_newFilter',
    'personal_sign',
  ])('rejects %s before sending any member', async (method) => {
    const fetcher = jest.fn();
    const client = new JsonRpcReadClient(URL, { fetch: fetcher });
    await expect(client.readMany([input(), input(method)])).rejects.toThrow(
      'read-only'
    );
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('falls back to proper single objects after an explicit batch refusal and remembers the endpoint', async () => {
    const fetcher = jest.fn(async (_url, init) => {
      const request = JSON.parse(init.body);
      return response(
        Array.isArray(request)
          ? {
              jsonrpc: '2.0',
              id: null,
              error: { code: -32600, message: 'Batch unsupported' },
            }
          : reply(request)
      );
    });
    const client = new JsonRpcReadClient(URL, { fetch: fetcher });
    expect(
      (await client.readMany([input(), input('eth_getCode')])).every(
        (row) => row.status === 'fulfilled'
      )
    ).toBe(true);
    await client.readMany([input(), input('eth_getCode')]);
    const payloads = fetcher.mock.calls.map(([, init]) =>
      JSON.parse(init.body)
    );
    expect(payloads.filter(Array.isArray)).toHaveLength(1);
    expect(payloads.slice(1).every((value) => !Array.isArray(value))).toBe(
      true
    );
  });

  it('reduces oversized batches and executes every member once after refusal', async () => {
    const fulfilled: string[] = [];
    const fetcher = jest.fn(async (_url, init) => {
      const request = JSON.parse(init.body);
      if (Array.isArray(request) && request.length > 2)
        return response({}, 413);
      const rows = Array.isArray(request) ? request : [request];
      fulfilled.push(...rows.map((row) => row.params[0]));
      return response(
        Array.isArray(request)
          ? rows.map((row) => reply(row, row.params[0]))
          : reply(request, request.params[0])
      );
    });
    const client = new JsonRpcReadClient(URL, {
      fetch: fetcher,
      maxBatchItems: 8,
    });
    const result = await client.readMany(
      Array.from({ length: 7 }, (_, i) => input('eth_call', String(i)))
    );
    expect(result).toEqual(
      Array.from({ length: 7 }, (_, i) => ({
        status: 'fulfilled',
        value: String(i),
      }))
    );
    expect(fulfilled).toEqual(['0', '1', '2', '3', '4', '5', '6']);
  });

  it('does not poison batch capability after HTTP429', async () => {
    let refused = true;
    const fetcher = jest.fn(async (_url, init) => {
      const requests = JSON.parse(init.body);
      if (refused) return response({}, 429);
      return response(requests.map(reply));
    });
    const client = new JsonRpcReadClient(URL, { fetch: fetcher });
    expect(
      (await client.readMany([input(), input()])).every(
        (row) => row.status === 'rejected'
      )
    ).toBe(true);
    refused = false;
    expect(
      (await client.readMany([input(), input()])).every(
        (row) => row.status === 'fulfilled'
      )
    ).toBe(true);
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(
      fetcher.mock.calls.every(([, init]) =>
        Array.isArray(JSON.parse(init.body))
      )
    ).toBe(true);
  });

  it.each(['duplicate', 'missing', 'unexpected'])(
    'rejects %s wire IDs after one bounded recovery',
    async (kind) => {
      const fetcher = jest.fn(async (_url, init) => {
        const rows = JSON.parse(init.body);
        const values = rows.map(reply);
        if (kind === 'duplicate') values[1].id = values[0].id;
        if (kind === 'missing') values.pop();
        if (kind === 'unexpected') values[1].id += 100;
        return response(values);
      });
      const client = new JsonRpcReadClient(URL, { fetch: fetcher });
      const result = await client.readMany([input(), input()]);
      expect(
        result.every(
          (row) =>
            row.status === 'rejected' &&
            row.reason instanceof RpcResponseIntegrityError
        )
      ).toBe(true);
      expect(fetcher).toHaveBeenCalledTimes(2);
    }
  );

  it('bounds response bytes and request bytes', async () => {
    const fetcher = jest.fn(async (_url, init) =>
      response(reply(JSON.parse(init.body), 'x'.repeat(300)))
    );
    const client = new JsonRpcReadClient(URL, { fetch: fetcher });
    expect(
      (await client.readMany([input()], { maxResponseBytes: 100 }))[0].status
    ).toBe('rejected');
    const small = new JsonRpcReadClient(URL, {
      fetch: fetcher,
      maxRequestBytes: 20,
    });
    expect((await small.readMany([input()]))[0].status).toBe('rejected');
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it('shares fifty cold ordinary identity reads and separates an explicitly fresh probe', async () => {
    const old = deferred<Response>();
    const fresh = deferred<Response>();
    const fetcher = jest
      .fn()
      .mockReturnValueOnce(old.promise)
      .mockReturnValueOnce(fresh.promise);
    const client = new JsonRpcReadClient(URL, { fetch: fetcher });
    const ordinary = Array.from({ length: 50 }, () => client.getChainId());
    await tick();
    expect(fetcher).toHaveBeenCalledTimes(1);
    const current = client.getChainId({ fresh: true });
    await tick();
    expect(fetcher).toHaveBeenCalledTimes(2);
    fresh.resolve(
      response(reply(JSON.parse(fetcher.mock.calls[1][1].body), '0x2'))
    );
    await expect(current).resolves.toBe('0x2');
    old.resolve(
      response(reply(JSON.parse(fetcher.mock.calls[0][1].body), '0x1'))
    );
    await Promise.all(ordinary);
    await expect(client.getChainId()).resolves.toBe('0x2');
  });

  it('cancels one identity subscriber without aborting another', async () => {
    const held = deferred<Response>();
    const fetcher = jest.fn().mockReturnValue(held.promise);
    const client = new JsonRpcReadClient(URL, { fetch: fetcher });
    const first = new AbortController();
    const a = client.getChainId({ signal: first.signal });
    const b = client.getChainId();
    await tick();
    first.abort();
    await expect(a).rejects.toThrow();
    expect(fetcher.mock.calls[0][1].signal.aborted).toBe(false);
    held.resolve(
      response(reply(JSON.parse(fetcher.mock.calls[0][1].body), '0x1'))
    );
    await expect(b).resolves.toBe('0x1');
  });

  it('retains physical capacity while an aborted fetch drains', async () => {
    const held = deferred<Response>();
    const fetcher = jest
      .fn()
      .mockReturnValueOnce(held.promise)
      .mockImplementation(async (_url, init) =>
        response(reply(JSON.parse(init.body)))
      );
    const client = new JsonRpcReadClient(URL, {
      fetch: fetcher,
      maxConcurrency: 1,
    });
    const abort = new AbortController();
    const first = client.read('eth_chainId', [], { signal: abort.signal });
    await tick();
    abort.abort();
    await expect(first).rejects.toThrow();
    const second = client.read('eth_chainId', []);
    await tick();
    expect(fetcher).toHaveBeenCalledTimes(1);
    held.resolve(response(reply(JSON.parse(fetcher.mock.calls[0][1].body))));
    await expect(second).resolves.toBe('eth_chainId');
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it('captures immutable input before dispatch', async () => {
    const held = deferred<Response>();
    const fetcher = jest
      .fn()
      .mockReturnValueOnce(held.promise)
      .mockImplementation(async (_url, init) =>
        response(reply(JSON.parse(init.body)))
      );
    const client = new JsonRpcReadClient(URL, {
      fetch: fetcher,
      maxConcurrency: 1,
    });
    const blocking = client.read('eth_chainId', []);
    await tick();
    const params = ['before'];
    const next = client.read('eth_call', params);
    params[0] = 'after';
    held.resolve(response(reply(JSON.parse(fetcher.mock.calls[0][1].body))));
    await blocking;
    await next;
    expect(JSON.parse(fetcher.mock.calls[1][1].body).params).toEqual([
      'before',
    ]);
  });
});

it('times out a hanging call without releasing physical capacity prematurely', async () => {
  jest.useFakeTimers();
  const held = deferred<Response>();
  const fetcher = jest
    .fn()
    .mockReturnValueOnce(held.promise)
    .mockImplementation(async (_url, init) =>
      response(reply(JSON.parse(init.body)))
    );
  const client = new JsonRpcReadClient(URL, {
    fetch: fetcher,
    maxConcurrency: 1,
  });
  const first = client.read('eth_chainId', [], { timeoutMs: 10 });
  const rejected = expect(first).rejects.toMatchObject({ name: 'AbortError' });
  await jest.advanceTimersByTimeAsync(10);
  await rejected;
  const second = client.read('eth_chainId', []);
  await tick();
  expect(fetcher).toHaveBeenCalledTimes(1);
  held.resolve(response(reply(JSON.parse(fetcher.mock.calls[0][1].body))));
  await expect(second).resolves.toBe('eth_chainId');
  jest.useRealTimers();
});

it('uses independent deadlines for subscribers to the same chain read', async () => {
  jest.useFakeTimers();
  const held = deferred<Response>();
  const fetcher = jest.fn().mockReturnValue(held.promise);
  const client = new JsonRpcReadClient(URL, { fetch: fetcher });
  const first = client.getChainId({ timeoutMs: 10 });
  const second = client.getChainId({ timeoutMs: 1000 });
  const rejected = expect(first).rejects.toMatchObject({ name: 'AbortError' });
  await jest.advanceTimersByTimeAsync(10);
  await rejected;
  expect(fetcher.mock.calls[0][1].signal.aborted).toBe(false);
  held.resolve(
    response(reply(JSON.parse(fetcher.mock.calls[0][1].body), '0x1'))
  );
  await expect(second).resolves.toBe('0x1');
  jest.useRealTimers();
});

it('starts a new ordinary chain read after every previous subscriber cancels', async () => {
  const held = deferred<Response>();
  const fetcher = jest
    .fn()
    .mockReturnValueOnce(held.promise)
    .mockImplementation(async (_url, init) =>
      response(reply(JSON.parse(init.body), '0x2'))
    );
  const client = new JsonRpcReadClient(URL, { fetch: fetcher });
  const controller = new AbortController();
  const first = client.getChainId({ signal: controller.signal });
  await tick();
  controller.abort();
  await expect(first).rejects.toThrow();
  await expect(client.getChainId()).resolves.toBe('0x2');
  held.resolve(
    response(reply(JSON.parse(fetcher.mock.calls[0][1].body), '0x1'))
  );
  await tick();
  await expect(client.getChainId()).resolves.toBe('0x2');
});

it('does not classify forged transport error fields as a verified RPC error', async () => {
  const forged = Object.assign(new Error('network failed'), {
    code: 3,
    data: '0x1234',
  });
  const client = new JsonRpcReadClient(URL, {
    fetch: async () => {
      throw forged;
    },
  });
  const [item] = await client.readMany([input('eth_call')]);
  expect(item.status).toBe('rejected');
  expect((item as PromiseRejectedResult).reason).toBe(forged);
  expect((item as PromiseRejectedResult).reason).not.toBeInstanceOf(
    RpcReadError
  );
});

it('preserves exact-endpoint one-attempt behavior when recovery is disabled', async () => {
  const fetcher = jest.fn(async (_url, init) =>
    response({ ...reply(JSON.parse(init.body)), id: -1 })
  );
  const client = new JsonRpcReadClient(URL, {
    fetch: fetcher,
    recoverResponse: false,
  });
  const [item] = await client.readMany([input()]);
  expect(item.status).toBe('rejected');
  expect(fetcher).toHaveBeenCalledTimes(1);
  expect(fetcher.mock.calls[0][0]).toBe(URL);
});

it('ignores request-object mutation during one stale-response recovery', async () => {
  const params = ['original'];
  let first = true;
  const fetcher = jest.fn(async (_url, init) => {
    const request = JSON.parse(init.body);
    if (first) {
      first = false;
      params[0] = 'mutated';
      return response({ ...reply(request), id: -1 });
    }
    return response(reply(request, request.params[0]));
  });
  const client = new JsonRpcReadClient(URL, { fetch: fetcher });
  await expect(client.read('eth_call', params)).resolves.toBe('original');
  expect(
    new globalThis.URL(fetcher.mock.calls[1][0]).searchParams.has(
      'sysweb3_rpc_request'
    )
  ).toBe(true);
});

it('rejects a serialized mutation method before dispatch', async () => {
  const fetcher = jest.fn();
  const client = new JsonRpcReadClient(URL, { fetch: fetcher });
  const value = {
    method: 'eth_call',
    params: [],
    toJSON: () => ({ method: 'eth_sendRawTransaction', params: ['0x1234'] }),
  };
  await expect(client.readMany([value])).rejects.toThrow('read-only');
  expect(fetcher).not.toHaveBeenCalled();
});

it('reduces an explicitly limited batch while preserving every successful member', async () => {
  const fetcher = jest.fn(async (_url, init) => {
    const request = JSON.parse(init.body);
    if (Array.isArray(request) && request.length > 2)
      return response({
        jsonrpc: '2.0',
        id: null,
        error: {
          code: -32005,
          message: 'Batch of more than 2 requests not allowed',
        },
      });
    return response(
      Array.isArray(request) ? request.map(reply) : reply(request)
    );
  });
  const client = new JsonRpcReadClient(URL, {
    fetch: fetcher,
    maxBatchItems: 8,
  });
  expect(
    (await client.readMany(Array.from({ length: 7 }, () => input()))).every(
      (item) => item.status === 'fulfilled'
    )
  ).toBe(true);
  const payloads = fetcher.mock.calls.map(([, init]) => JSON.parse(init.body));
  expect(
    payloads.slice(1).some((item) => Array.isArray(item) && item.length === 2)
  ).toBe(true);
});

it('keeps other calls within the shared concurrency bound', async () => {
  let active = 0;
  let maximum = 0;
  const held: Array<() => void> = [];
  const fetcher = jest.fn(
    (_url, init) =>
      new Promise<Response>((resolve) => {
        active++;
        maximum = Math.max(maximum, active);
        held.push(() => {
          active--;
          resolve(response(reply(JSON.parse(init.body))));
        });
      })
  );
  const client = new JsonRpcReadClient(URL, {
    fetch: fetcher,
    maxConcurrency: 2,
    maxBatchItems: 1,
  });
  const first = client.readMany([input(), input(), input()]);
  const second = client.readMany([input(), input(), input()]);
  await tick();
  expect(fetcher).toHaveBeenCalledTimes(2);
  for (let index = 0; index < 6; index++) {
    held[index]();
    await tick();
  }
  await Promise.all([first, second]);
  expect(maximum).toBe(2);
});

it('refuses further reads after endpoint client destruction', async () => {
  const fetcher = jest.fn(async (_url, init) =>
    response(reply(JSON.parse(init.body), '0x1'))
  );
  const client = new JsonRpcReadClient(URL, { fetch: fetcher });
  await client.getChainId();
  client.destroy();
  await expect(client.getChainId()).rejects.toThrow();
  await expect(client.read('eth_chainId', [])).rejects.toThrow();
  expect(fetcher).toHaveBeenCalledTimes(1);
});

it.each([false, true])(
  'honors a chain subscriber deadline longer than the client default, fresh=%s',
  async (fresh) => {
    jest.useFakeTimers();
    try {
      const held = deferred<Response>();
      const fetcher = jest.fn().mockReturnValue(held.promise);
      const client = new JsonRpcReadClient(URL, {
        fetch: fetcher,
        timeoutMs: 10,
      });
      const result = client.getChainId({ fresh, timeoutMs: 1000 });
      await jest.advanceTimersByTimeAsync(50);
      expect(fetcher.mock.calls[0][1].signal.aborted).toBe(false);
      held.resolve(
        response(reply(JSON.parse(fetcher.mock.calls[0][1].body), '0x1'))
      );
      await expect(result).resolves.toBe('0x1');
    } finally {
      jest.useRealTimers();
    }
  }
);

it.each([false, true])(
  'enforces the per-call chain response cap, fresh=%s',
  async (fresh) => {
    const client = new JsonRpcReadClient(URL, {
      fetch: async (_url, init) =>
        response({
          ...reply(JSON.parse(String(init.body)), '0x1'),
          padding: 'x'.repeat(1024),
        }),
    });
    await expect(
      client.getChainId({ fresh, maxResponseBytes: 100 })
    ).rejects.toThrow('size limit');
  }
);

it('separates concurrent chain reads with different response caps', async () => {
  const held = deferred<Response>();
  const fetcher = jest.fn().mockImplementation(async (_url, init) => {
    await held.promise;
    return response({
      ...reply(JSON.parse(init.body), '0x1'),
      padding: 'x'.repeat(1024),
    });
  });
  const client = new JsonRpcReadClient(URL, { fetch: fetcher });
  const small = expect(
    client.getChainId({ maxResponseBytes: 100 })
  ).rejects.toThrow('size limit');
  const large = client.getChainId({ maxResponseBytes: 2048 });
  await tick();
  expect(fetcher).toHaveBeenCalledTimes(2);
  held.resolve(response(null));
  await small;
  await expect(large).resolves.toBe('0x1');
});

it.each([429, 503])(
  'does not split or change capabilities for HTTP %s with batch rate-limit JSON',
  async (status) => {
    let limited = true;
    const fetcher = jest.fn(async (_url, init) => {
      const request = JSON.parse(init.body);
      return limited
        ? response(
            {
              jsonrpc: '2.0',
              id: null,
              error: { code: -32005, message: 'Batch rate limit exceeded' },
            },
            status
          )
        : response(request.map(reply));
    });
    const client = new JsonRpcReadClient(URL, { fetch: fetcher });
    const inputs = Array.from({ length: 4 }, () => input());
    expect(
      (await client.readMany(inputs)).every(
        (item) => item.status === 'rejected'
      )
    ).toBe(true);
    expect(fetcher).toHaveBeenCalledTimes(1);
    limited = false;
    expect(
      (await client.readMany(inputs)).every(
        (item) => item.status === 'fulfilled'
      )
    ).toBe(true);
    expect(
      fetcher.mock.calls.map(([, init]) => JSON.parse(init.body).length)
    ).toEqual([4, 4]);
  }
);

it('does not classify a successful HTTP rate-limit envelope as a batch size limit', async () => {
  const fetcher = jest.fn(async () =>
    response({
      jsonrpc: '2.0',
      id: null,
      error: { code: -32005, message: 'Batch rate limit exceeded' },
    })
  );
  const client = new JsonRpcReadClient(URL, { fetch: fetcher });
  expect(
    (await client.readMany([input(), input()])).every(
      (item) => item.status === 'rejected'
    )
  ).toBe(true);
  expect(fetcher).toHaveBeenCalledTimes(2);
  expect(
    fetcher.mock.calls.every(([, init]) => Array.isArray(JSON.parse(init.body)))
  ).toBe(true);
});

it('confirms generic Invalid Request batch refusal with one successful scalar probe', async () => {
  const fetcher = jest.fn(async (_url, init) => {
    const request = JSON.parse(init.body);
    return response(
      Array.isArray(request)
        ? {
            jsonrpc: '2.0',
            id: null,
            error: { code: -32600, message: 'Invalid Request' },
          }
        : reply(request, request.params[0])
    );
  });
  const client = new JsonRpcReadClient(URL, { fetch: fetcher });
  const inputs = [input('eth_call', 'first'), input('eth_call', 'second')];
  expect(await client.readMany(inputs)).toEqual([
    { status: 'fulfilled', value: 'first' },
    { status: 'fulfilled', value: 'second' },
  ]);
  await client.readMany(inputs);
  const payloads = fetcher.mock.calls.map(([, init]) => JSON.parse(init.body));
  expect(payloads.filter(Array.isArray)).toHaveLength(1);
  expect(payloads.slice(1).every((value) => !Array.isArray(value))).toBe(true);
  expect(payloads.slice(1).map((value) => value.params[0])).toEqual([
    'first',
    'second',
    'first',
    'second',
  ]);
});

it('keeps batch capability when the generic-refusal scalar probe fails', async () => {
  let unavailable = true;
  const fetcher = jest.fn(async (_url, init) => {
    const request = JSON.parse(init.body);
    if (unavailable)
      return response({
        jsonrpc: '2.0',
        id: null,
        error: { code: -32600, message: 'Invalid Request' },
      });
    return response(request.map(reply));
  });
  const client = new JsonRpcReadClient(URL, {
    fetch: fetcher,
    recoverResponse: false,
  });
  expect(
    (await client.readMany([input(), input()])).every(
      (item) => item.status === 'rejected'
    )
  ).toBe(true);
  expect(fetcher).toHaveBeenCalledTimes(2);
  unavailable = false;
  expect(
    (await client.readMany([input(), input()])).every(
      (item) => item.status === 'fulfilled'
    )
  ).toBe(true);
  expect(Array.isArray(JSON.parse(fetcher.mock.calls[2][1].body))).toBe(true);
});

it.each([
  'payload',
  'content-type',
  'content-length',
  'stream-size',
  'aborted-headers',
  'reader-unavailable',
])('holds physical capacity through %s body cleanup', async (failure) => {
  const cleanup = deferred<void>();
  const cancel = jest.fn(() => cleanup.promise);
  const abort = new AbortController();
  const fetcher = jest.fn(async (_url, init) => {
    const request = JSON.parse(init.body);
    if (fetcher.mock.calls.length > 1)
      return response(
        Array.isArray(request) ? request.map(reply) : reply(request)
      );
    const headers = new Headers();
    if (failure === 'content-type') headers.set('content-type', 'text/html');
    if (failure === 'content-length') headers.set('content-length', '1000000');
    if (failure === 'aborted-headers') abort.abort();
    return {
      ok: failure !== 'payload',
      status: failure === 'payload' ? 413 : 200,
      headers,
      body: {
        cancel,
        getReader: () => {
          if (failure === 'reader-unavailable')
            throw new Error('Reader unavailable');
          return {
            read: async () => ({ done: false, value: new Uint8Array(1025) }),
            cancel,
            releaseLock: jest.fn(),
          };
        },
      },
    } as unknown as Response;
  });
  const client = new JsonRpcReadClient(URL, {
    fetch: fetcher,
    maxConcurrency: 1,
    maxResponseBytes: 1024,
  });
  const first = client
    .readMany([input(), input(), input()], { signal: abort.signal })
    .catch((error) => error);
  await tick();
  expect(cancel).toHaveBeenCalledTimes(1);
  const second = client.read('eth_chainId', []);
  await tick();
  expect(fetcher).toHaveBeenCalledTimes(1);
  cleanup.resolve();
  await first;
  await expect(second).resolves.toBe('eth_chainId');
});

it('settles caller cancellation before held response cleanup releases its slot', async () => {
  const cleanup = deferred<void>();
  const cancel = jest.fn(() => cleanup.promise);
  const controller = new AbortController();
  const fetcher = jest.fn(async (_url, init) => {
    if (fetcher.mock.calls.length > 1)
      return response(reply(JSON.parse(init.body)));
    return {
      ok: false,
      status: 429,
      headers: new Headers(),
      body: { cancel },
    } as unknown as Response;
  });
  const client = new JsonRpcReadClient(URL, {
    fetch: fetcher,
    maxConcurrency: 1,
  });
  const first = client.read('eth_call', [], { signal: controller.signal });
  await tick();
  controller.abort();
  await expect(first).rejects.toMatchObject({ name: 'AbortError' });
  const second = client.read('eth_getCode', []);
  await tick();
  expect(fetcher).toHaveBeenCalledTimes(1);
  cleanup.resolve();
  await expect(second).resolves.toBe('eth_getCode');
});

it('uses a verified scalar RPC error to confirm generic batch refusal', async () => {
  const fetcher = jest.fn(async (_url, init) => {
    const request = JSON.parse(init.body);
    return response(
      Array.isArray(request)
        ? {
            jsonrpc: '2.0',
            id: null,
            error: { code: -32600, message: 'Invalid Request' },
          }
        : request.method === 'eth_call'
        ? {
            jsonrpc: '2.0',
            id: request.id,
            error: { code: 3, message: 'reverted', data: '0x1234' },
          }
        : reply(request)
    );
  });
  const client = new JsonRpcReadClient(URL, { fetch: fetcher });
  const [first, second] = await client.readMany([
    input('eth_call'),
    input('eth_getCode'),
  ]);
  expect(first.status).toBe('rejected');
  expect((first as PromiseRejectedResult).reason).toBeInstanceOf(RpcReadError);
  expect(second).toEqual({ status: 'fulfilled', value: 'eth_getCode' });
  expect(fetcher).toHaveBeenCalledTimes(3);
});

it.each([
  'Batch limit exceeded',
  'Too many requests in a batch; maximum batch size is 2',
  'Batch of more than 2 requests not allowed',
  'Maximum batch size is 2',
  'Batch size exceeded',
  'Array length exceeds maximum',
  'Too many items per batch',
])('splits an explicit per-batch count refusal: %s', async (message) => {
  const fetcher = jest.fn(async (_url, init) => {
    const request = JSON.parse(init.body);
    return response(
      Array.isArray(request) && request.length > 2
        ? { jsonrpc: '2.0', id: null, error: { code: -32005, message } }
        : request.map(reply)
    );
  });
  const client = new JsonRpcReadClient(URL, { fetch: fetcher });
  const inputs = Array.from({ length: 4 }, () => input());
  expect(
    (await client.readMany(inputs)).every((item) => item.status === 'fulfilled')
  ).toBe(true);
  expect(
    fetcher.mock.calls.map(([, init]) => JSON.parse(init.body).length)
  ).toEqual([4, 2, 2]);
});

it.each([
  'Batch rate limit exceeded',
  'Too many requests; batch endpoint busy',
  'Batch requests per second exceeded',
  'Batch quota exhausted',
  'Batch size 4 was throttled',
  'Maximum batch requests per second exceeded',
])(
  'keeps capacity unchanged for transient batch errors: %s',
  async (message) => {
    let limited = true;
    const fetcher = jest.fn(async (_url, init) => {
      const request = JSON.parse(init.body);
      return response(
        limited
          ? { jsonrpc: '2.0', id: null, error: { code: -32005, message } }
          : request.map(reply)
      );
    });
    const client = new JsonRpcReadClient(URL, { fetch: fetcher });
    const inputs = Array.from({ length: 4 }, () => input());
    expect(
      (await client.readMany(inputs)).every(
        (item) => item.status === 'rejected'
      )
    ).toBe(true);
    expect(
      fetcher.mock.calls.map(([, init]) => JSON.parse(init.body).length)
    ).toEqual([4, 4]);
    limited = false;
    expect(
      (await client.readMany(inputs)).every(
        (item) => item.status === 'fulfilled'
      )
    ).toBe(true);
    expect(JSON.parse(fetcher.mock.calls[2][1].body)).toHaveLength(4);
  }
);

it.each(
  [200, 400, 413, 429, 500, 503].flatMap((status) =>
    ['explicit', 'generic', 'rate'].map((kind) => [status, kind] as const)
  )
)(
  'handles HTTP %s %s batch responses without transient capability poisoning',
  async (status, kind) => {
    let limited = true;
    const fetcher = jest.fn(async (_url, init) => {
      const request = JSON.parse(init.body);
      const rows = Array.isArray(request) ? request : [request];
      if (limited && Array.isArray(request) && request.length > 2) {
        return response(
          {
            jsonrpc: '2.0',
            id: null,
            error: {
              code: kind === 'rate' ? -32005 : -32600,
              message:
                kind === 'explicit'
                  ? 'Batch requests are not supported'
                  : kind === 'generic'
                  ? 'Invalid Request'
                  : 'Batch rate limit exceeded',
            },
          },
          status
        );
      }
      return response(
        Array.isArray(request) ? rows.map(reply) : reply(request)
      );
    });
    const client = new JsonRpcReadClient(URL, { fetch: fetcher });
    const inputs = Array.from({ length: 4 }, () => input());
    const recovers =
      status === 413 || ([200, 400].includes(status) && kind !== 'rate');
    const result = await client.readMany(inputs);
    expect(
      result.every(
        (item) => item.status === (recovers ? 'fulfilled' : 'rejected')
      )
    ).toBe(true);
    const widths = () =>
      fetcher.mock.calls.map(([, init]) => {
        const request = JSON.parse(init.body);
        return Array.isArray(request) ? request.length : 1;
      });
    const attempts = widths();
    if (status === 413) expect(attempts).toEqual([4, 2, 2]);
    else if (recovers) expect(attempts).toEqual([4, 1, 1, 1, 1]);
    else expect(attempts).toEqual(status === 200 ? [4, 4] : [4]);
    limited = false;
    await client.readMany(inputs);
    expect(widths().slice(attempts.length)).toEqual(
      status === 413 ? [2, 2] : recovers ? [1, 1, 1, 1] : [4]
    );
  }
);
