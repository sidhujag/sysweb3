import { validateEvmRpcBatch } from '../src/rpc';

const reply = (request: any, chain = '0x1') => ({
  jsonrpc: '2.0',
  id: request.id,
  result: request.method === 'eth_chainId' ? chain : '0x2',
});
beforeEach(() => {
  jest.clearAllMocks();
});
afterEach(() => {
  jest.restoreAllMocks();
  jest.useRealTimers();
});

it.each(['not-a-url', '', 'https://', 'file:///rpc'])(
  'returns a validation failure for invalid endpoint %p without making a request',
  async (endpoint) => {
    const fetch = jest.spyOn(global, 'fetch');
    await expect(validateEvmRpcBatch(endpoint, 1)).resolves.toMatchObject({
      success: false,
      error: expect.any(String),
    });
    expect(fetch).not.toHaveBeenCalled();
  }
);

it.each(['batch', 'http400', 'rpc32600'])(
  'observes three complete samples with %s support',
  async (mode) => {
    jest.useFakeTimers();
    const posts: any[] = [];
    jest.spyOn(global, 'fetch').mockImplementation(async (_url, init) => {
      const request = JSON.parse(String(init?.body));
      posts.push(request);
      if (Array.isArray(request) && mode === 'http400')
        return new Response('unsupported', { status: 400 });
      if (Array.isArray(request) && mode === 'rpc32600')
        return Response.json({
          jsonrpc: '2.0',
          id: null,
          error: { code: -32600, message: 'Invalid Request' },
        });
      return Response.json(
        Array.isArray(request)
          ? request.map((r) => reply(r)).reverse()
          : reply(request)
      );
    });
    const result = validateEvmRpcBatch('https://rpc.example', 1);
    await jest.runAllTimersAsync();
    expect(await result).toMatchObject({ success: true, chainId: 1 });
    expect(posts.filter(Array.isArray)).toHaveLength(mode === 'batch' ? 3 : 1);
    expect(posts).toHaveLength(mode === 'batch' ? 3 : 7);
  }
);

it.each(['0x1not-hex', '0x89'])(
  'rejects a later malformed or changed chain %s',
  async (chain) => {
    jest.useFakeTimers();
    let calls = 0;
    jest.spyOn(global, 'fetch').mockImplementation(async (_url, init) => {
      const requests = JSON.parse(String(init?.body));
      calls++;
      return Response.json(
        requests.map((r: any) => reply(r, calls === 1 ? '0x1' : chain))
      );
    });
    const result = validateEvmRpcBatch('https://rpc.example', 1);
    await jest.runAllTimersAsync();
    expect(await result).toMatchObject({ success: false });
    expect(calls).toBe(2);
  }
);

it('holds the timeout through response body and cancels the stream', async () => {
  jest.useFakeTimers();
  let cancelled = false;
  let signal: AbortSignal | undefined;
  jest.spyOn(global, 'fetch').mockImplementation(async (_url, init) => {
    signal = init?.signal as AbortSignal;
    return new Response(
      new ReadableStream({
        cancel() {
          cancelled = true;
        },
      }),
      { headers: { 'content-type': 'application/json' } }
    );
  });
  const result = validateEvmRpcBatch('https://rpc.example', 1, 10);
  await jest.advanceTimersByTimeAsync(11);
  expect(await result).toMatchObject({ success: false });
  expect(signal?.aborted).toBe(true);
  expect(cancelled).toBe(true);
});

it('includes body delivery in the warm latency measurement', async () => {
  jest.useFakeTimers();
  jest.spyOn(global, 'fetch').mockImplementation(async (_url, init) => {
    const requests = JSON.parse(String(init?.body));
    const data = new TextEncoder().encode(
      JSON.stringify(requests.map((r: any) => reply(r)))
    );
    return new Response(
      new ReadableStream({
        start(controller) {
          setTimeout(() => {
            controller.enqueue(data);
            controller.close();
          }, 25);
        },
      })
    );
  });
  const result = validateEvmRpcBatch('https://rpc.example', 1, 100, 500);
  await jest.runAllTimersAsync();
  expect(await result).toMatchObject({ success: true, latency: 25 });
});

it('cancels the inter-sample delay without initiating another request', async () => {
  jest.useFakeTimers();
  const controller = new AbortController();
  const fetch = jest
    .spyOn(global, 'fetch')
    .mockImplementation(async (_url, init) =>
      Response.json(JSON.parse(String(init?.body)).map((r: any) => reply(r)))
    );
  const result = validateEvmRpcBatch('https://rpc.example', 1, 100, 500, {
    signal: controller.signal,
  });
  await jest.advanceTimersByTimeAsync(1);
  controller.abort();
  await jest.runAllTimersAsync();
  expect(await result).toMatchObject({ success: false });
  expect(fetch).toHaveBeenCalledTimes(1);
});

it('preserves authentication guidance for validated JSON-RPC errors', async () => {
  jest.spyOn(global, 'fetch').mockImplementation(async (_url, init) =>
    Response.json(
      JSON.parse(String(init?.body)).map((r: any) => ({
        jsonrpc: '2.0',
        id: r.id,
        error: { code: -32000, message: 'API key required' },
      }))
    )
  );
  expect(await validateEvmRpcBatch('https://rpc.example', 1)).toMatchObject({
    success: false,
    requiresAuth: true,
  });
});
