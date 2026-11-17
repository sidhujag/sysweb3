jest.unmock('../../src/providers');

const { CustomJsonRpcProvider } = jest.requireActual('../../src/providers');
const { RpcReadError } = jest.requireActual('../../src/rpc-read-client');
const { AbiCoder, Interface } = jest.requireActual('ethers/abi');
const { EnsPlugin, Network } = jest.requireActual('ethers/providers');

const RPC = 'https://rpc.example/ens';
const GATEWAY = 'https://gateway.example/lookup/{data}';
const REGISTRY = '0x0000000000000000000000000000000000000011';
const RESOLVER = '0x0000000000000000000000000000000000000022';
const RECIPIENT = '0x0000000000000000000000000000000000000033';
const CALL_DATA = '0x1234';
const CALLBACK = '0xabcdef01';
const abi = AbiCoder.defaultAbiCoder();
const iface = new Interface([
  'function resolver(bytes32) view returns(address)',
  'function supportsInterface(bytes4) view returns(bool)',
  'function addr(bytes32) view returns(address)',
]);
const offchain = (sender = RESOLVER, urls = [GATEWAY]) =>
  '0x556f1830' +
  abi
    .encode(
      ['address', 'string[]', 'bytes', 'bytes4', 'bytes'],
      [sender, urls, CALL_DATA, CALLBACK, '0x']
    )
    .slice(2);
const jsonResponse = (value: unknown, options: ResponseInit = {}) =>
  new Response(JSON.stringify(value), {
    status: 200,
    headers: { 'content-type': 'application/json' },
    ...options,
  });

describe('owned ethers CCIP reads', () => {
  let originalFetch: typeof fetch;
  const providers: any[] = [];
  beforeEach(() => {
    originalFetch = global.fetch;
  });
  afterEach(() => {
    providers.splice(0).forEach((provider) => provider.destroy());
    global.fetch = originalFetch;
  });

  function fixture(mode = 'direct', onchain = false, options: any = {}) {
    const calls: any[] = [];
    const configuration = { chainId: '0x1', sender: RESOLVER, urls: [GATEWAY] };
    const gateway = jest.fn(async () => jsonResponse({ data: '0x123456' }));
    global.fetch = gateway;
    const fetcher = jest.fn(async (_url, init) => {
      const payload = JSON.parse(init.body);
      const respond = (request: any) => {
        calls.push(request);
        const reply = (result: unknown) => ({
          jsonrpc: '2.0',
          id: request.id,
          result,
        });
        if (request.method === 'eth_chainId')
          return reply(configuration.chainId ?? '0x1');
        if (request.method === 'eth_blockNumber') return reply('0x1');
        if (request.method !== 'eth_call') throw Error('Unexpected RPC');
        const tx = request.params[0];
        const selector = tx.data.slice(0, 10);
        if (tx.to.toLowerCase() === REGISTRY.toLowerCase())
          return reply(iface.encodeFunctionResult('resolver', [RESOLVER]));
        if (selector === iface.getFunction('supportsInterface').selector)
          return reply(
            iface.encodeFunctionResult('supportsInterface', [false])
          );
        if (selector === CALLBACK || onchain)
          return reply(iface.encodeFunctionResult('addr', [RECIPIENT]));
        return {
          jsonrpc: '2.0',
          id: request.id,
          error: {
            code: 3,
            message: 'execution reverted',
            data: offchain(configuration.sender, configuration.urls),
          },
        };
      };
      if (Array.isArray(payload) && mode === 'scalar')
        return jsonResponse({
          jsonrpc: '2.0',
          id: null,
          error: { code: -32600, message: 'Batch unsupported' },
        });
      const result = Array.isArray(payload)
        ? payload.map(respond)
        : respond(payload);
      if (configuration.fault === 'malformed') return new Response('{');
      if (configuration.fault === 'duplicate' && Array.isArray(result))
        return jsonResponse([result[0], result[0]]);
      if (configuration.fault === 'missing' && Array.isArray(result))
        return jsonResponse(result.slice(1));
      if (configuration.fault === 'wrong-id') {
        const values = Array.isArray(result) ? result : [result];
        for (const value of values) value.id += 100;
      }
      return jsonResponse(result);
    });
    const owner = new AbortController();
    const network = new Network('ens fixture', 1);
    network.attachPlugin(new EnsPlugin(REGISTRY, 1));
    const provider = new CustomJsonRpcProvider(owner.signal, RPC, network, {
      fetch: fetcher,
      ...options,
    });
    providers.push(provider);
    if (mode === 'owned') {
      const send = provider.send.bind(provider);
      provider.send = (method: string, params: any[]) =>
        send(method, params, { signal: owner.signal });
    }
    const warm = () =>
      provider.readMany([
        { method: 'eth_blockNumber', params: [] },
        { method: 'eth_blockNumber', params: [] },
      ]);
    return { provider, owner, calls, gateway, fetcher, warm, configuration };
  }

  it.each(['direct', 'queued', 'owned', 'scalar'])(
    'resolves actual onchain and offchain ENS via %s',
    async (mode) => {
      const f = fixture(mode);
      if (mode === 'queued' || mode === 'scalar') await f.warm();
      await expect(f.provider.resolveName('alice.eth')).resolves.toBe(
        RECIPIENT
      );
      expect(f.gateway).toHaveBeenCalledTimes(1);
      expect(f.calls.filter((call) => call.method === 'eth_call')).toHaveLength(
        4
      );
      const healthy = fixture(mode, true);
      if (mode === 'queued' || mode === 'scalar') await healthy.warm();
      await expect(healthy.provider.resolveName('alice.eth')).resolves.toBe(
        RECIPIENT
      );
      expect(healthy.gateway).not.toHaveBeenCalled();
    }
  );

  it('rejects a forged OffchainLookup sender before a gateway request', async () => {
    const f = fixture();
    f.configuration.sender = REGISTRY;
    await expect(f.provider.resolveName('alice.eth')).resolves.toBeNull();
    expect(f.gateway).not.toHaveBeenCalled();
    expect(
      f.calls.some((call) => call.params[0]?.data?.startsWith(CALLBACK))
    ).toBe(false);
  });

  it.each(['owner', 'destroy', 'deadline'])(
    'retires a held gateway on %s without a callback',
    async (kind) => {
      const f = fixture('direct', false, { timeoutMs: 100 });
      let release!: (response: Response) => void;
      let entered!: () => void;
      const started = new Promise<void>((resolve) => {
        entered = resolve;
      });
      let signal!: AbortSignal;
      const cancel = jest.fn().mockResolvedValue(undefined);
      f.gateway.mockImplementationOnce(async (_url, init) => {
        signal = init.signal;
        entered();
        return new Promise<Response>((resolve) => {
          release = resolve;
        });
      });
      const pending = f.provider.resolveName('alice.eth');
      const rejected = expect(pending).rejects.toMatchObject({
        name: 'AbortError',
      });
      await started;
      if (kind === 'owner') f.owner.abort();
      if (kind === 'destroy') f.provider.destroy();
      await rejected;
      expect(signal.aborted).toBe(true);
      release({
        ok: true,
        status: 200,
        headers: new Headers(),
        body: { cancel },
        text: async () => JSON.stringify({ data: '0x1234' }),
      } as unknown as Response);
      await new Promise((resolve) => setImmediate(resolve));
      expect(cancel).toHaveBeenCalledTimes(1);
      expect(f.gateway).toHaveBeenCalledTimes(1);
      expect(
        f.calls.some((call) => call.params[0]?.data?.startsWith(CALLBACK))
      ).toBe(false);
    }
  );

  it.each(['redirect', 'content-type', 'oversized', 'malformed'])(
    'rejects a %s gateway response without a callback',
    async (kind) => {
      const f = fixture('direct', false, { maxResponseBytes: 1600 });
      f.configuration.urls = [GATEWAY, 'https://second.example/{data}'];
      const response =
        kind === 'redirect'
          ? new Response('{}', {
              status: 302,
              headers: { location: 'https://other.example' },
            })
          : kind === 'content-type'
          ? new Response('<html/>', {
              headers: { 'content-type': 'text/html' },
            })
          : kind === 'oversized'
          ? jsonResponse({ data: 'x'.repeat(1800) })
          : new Response('{', {
              headers: { 'content-type': 'application/json' },
            });
      f.gateway.mockResolvedValueOnce(response);
      await expect(f.provider.resolveName('alice.eth')).rejects.toMatchObject({
        code: 'SYSWEB3_RPC_RESPONSE_INVALID',
      });
      expect(f.gateway).toHaveBeenCalledTimes(1);
      expect(
        f.calls.some((call) => call.params[0]?.data?.startsWith(CALLBACK))
      ).toBe(false);
    }
  );

  it('keeps gateway fallback inside ethers for ordinary HTTP failure', async () => {
    const f = fixture();
    f.configuration.urls = [GATEWAY, 'https://second.example/{data}'];
    f.gateway.mockResolvedValueOnce(new Response('{}', { status: 503 }));
    await expect(f.provider.resolveName('alice.eth')).resolves.toBe(RECIPIENT);
    expect(f.gateway).toHaveBeenCalledTimes(2);
  });

  it('rejects an oversized gateway request before network dispatch', async () => {
    const f = fixture('direct', false, { maxRequestBytes: 256 });
    await expect(
      f.provider.ccipReadFetch({ to: RESOLVER }, '0x' + 'aa'.repeat(200), [
        'https://gateway.example/post',
      ])
    ).rejects.toMatchObject({ code: 'OFFCHAIN_FAULT' });
    expect(f.gateway).not.toHaveBeenCalled();
  });

  it('keeps concurrent gateway owners separate while one reaches its deadline', async () => {
    const f = fixture('direct', false, { timeoutMs: 100 });
    let release!: (response: Response) => void;
    let entered!: () => void;
    const started = new Promise<void>((resolve) => {
      entered = resolve;
    });
    let firstSignal!: AbortSignal;
    f.gateway.mockImplementationOnce(async (_url, init) => {
      firstSignal = init.signal;
      entered();
      return new Promise<Response>((resolve) => {
        release = resolve;
      });
    });
    const first = f.provider.ccipReadFetch({ to: RESOLVER }, CALL_DATA, [
      GATEWAY,
    ]);
    const rejected = expect(first).rejects.toMatchObject({
      name: 'AbortError',
    });
    await started;
    await expect(
      f.provider.ccipReadFetch({ to: RESOLVER }, CALL_DATA, [GATEWAY])
    ).resolves.toBe('0x123456');
    await rejected;
    expect(firstSignal.aborted).toBe(true);
    expect(f.owner.signal.aborted).toBe(false);
    release(jsonResponse({ data: '0x1234' }));
    await new Promise((resolve) => setImmediate(resolve));
    await expect(
      f.provider.ccipReadFetch({ to: RESOLVER }, CALL_DATA, [GATEWAY])
    ).resolves.toBe('0x123456');
    expect(f.gateway).toHaveBeenCalledTimes(3);
  });

  it('aborts an acquired gateway reader immediately and holds its physical slot through cleanup', async () => {
    const f = fixture('direct', false, { maxConcurrency: 1 });
    let releaseCleanup!: () => void;
    let releaseRead!: (value: { done: boolean }) => void;
    let readStarted!: () => void;
    const entered = new Promise<void>((resolve) => {
      readStarted = resolve;
    });
    const cancel = jest.fn(
      () =>
        new Promise<void>((resolve) => {
          releaseCleanup = resolve;
          releaseRead({ done: true });
        })
    );
    f.gateway.mockResolvedValueOnce({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-type': 'application/json' }),
      body: {
        getReader: () => ({
          read: () => {
            readStarted();
            return new Promise((resolve) => {
              releaseRead = resolve;
            });
          },
          cancel,
          releaseLock: jest.fn(),
        }),
      },
    } as unknown as Response);
    const pending = f.provider.ccipReadFetch({ to: RESOLVER }, CALL_DATA, [
      GATEWAY,
    ]);
    const rejected = expect(pending).rejects.toMatchObject({
      name: 'AbortError',
    });
    await entered;
    f.owner.abort();
    await rejected;
    expect(cancel).toHaveBeenCalledTimes(1);
    releaseCleanup();
    await new Promise((resolve) => setImmediate(resolve));
    expect(f.gateway).toHaveBeenCalledTimes(1);
  });

  it.each(['malformed', 'duplicate', 'missing', 'wrong-id'])(
    'preserves %s RPC integrity failures before any CCIP gateway',
    async (fault) => {
      const f = fixture('queued');
      await f.warm();
      f.configuration.fault = fault;
      const result = await Promise.allSettled([
        f.provider.call({ to: RESOLVER, data: '0x1234', enableCcipRead: true }),
        f.provider.call({ to: RESOLVER, data: '0x5678', enableCcipRead: true }),
      ]);
      for (const item of result)
        expect(item).toMatchObject({
          status: 'rejected',
          reason: { code: 'SYSWEB3_RPC_RESPONSE_INVALID' },
        });
      expect(f.gateway).not.toHaveBeenCalled();
    }
  );

  it('detects a changed configured chain after the offchain lookup', async () => {
    const f = fixture();
    f.gateway.mockImplementationOnce(async () => {
      f.configuration.chainId = '0x2';
      return jsonResponse({ data: '0x123456' });
    });
    await expect(f.provider.resolveName('alice.eth')).resolves.toBe(RECIPIENT);
    await expect(f.provider.verifyConfiguredChainId(true)).rejects.toThrow(
      'does not match'
    );
  });

  it('omits RPC authorization and cookies from the gateway request', async () => {
    const f = fixture('direct', false, {
      requestInit: {
        credentials: 'include',
        headers: { Authorization: 'Bearer fixture' },
      },
    });
    await expect(f.provider.resolveName('alice.eth')).resolves.toBe(RECIPIENT);
    const [url, init] = f.gateway.mock.calls[0];
    expect(url).toBe(GATEWAY.replace('{data}', CALL_DATA));
    expect(init).toMatchObject({
      method: 'GET',
      credentials: 'omit',
      redirect: 'error',
      cache: 'no-store',
    });
    expect(new Headers(init.headers).get('authorization')).toBeNull();
  });

  it('retains the decoded RPC error for explicit settled reads', async () => {
    const f = fixture();
    const [result] = await f.provider.readMany([
      {
        method: 'eth_call',
        params: [{ to: RESOLVER, data: '0x1234' }, 'latest'],
      },
    ]);
    expect(result.status).toBe('rejected');
    expect(result.reason).toBeInstanceOf(RpcReadError);
    expect(result.reason).toMatchObject({
      code: 3,
      data: offchain(),
    });
    expect(f.gateway).not.toHaveBeenCalled();
  });
});
