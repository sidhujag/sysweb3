import { BigNumber, JsonRpcProvider } from '../../src/ethers-v6';

const { Network } = jest.requireActual('ethers/providers');
const { FetchRequest } = jest.requireActual('ethers/utils');

const { CustomJsonRpcProvider, RpcResponseIntegrityError } = jest.requireActual(
  '../../src/providers'
);
const { EthereumTransactions } = jest.requireActual(
  '../../src/transactions/ethereum'
);

const SENTINEL = 'SYSWEB3_RPC_RESPONSE_INVALID';
const RPC_URL = 'https://rpc.example/v1/token?existing=a%2Fb&space=a%20b';
const FROM = '0x0000000000000000000000000000000000000001';
const RUNTIME = `0x${'60'.repeat(512)}`;
const network = { url: RPC_URL, chainId: 5700 };

const response = (json: any) => ({
  ok: true,
  status: 200,
  json: async () => json,
});
const resultFor = (request: any, result = '0x5208') => ({
  jsonrpc: '2.0',
  id: request.id,
  result,
});
const requestsFrom = (fetchMock: jest.Mock) =>
  fetchMock.mock.calls.map(([, options]) => JSON.parse(options.body));

const sdkFor = (provider: any) => {
  const sdk = new EthereumTransactions(
    () => network,
    () => {
      throw new Error('This read-only test must not sign');
    },
    () => ({ activeNetwork: network }),
    {},
    {}
  );
  Object.defineProperty(sdk, 'web3Provider', { get: () => provider });
  return sdk;
};

describe('JSON-RPC response correlation', () => {
  let fetchMock: jest.Mock;
  let originalFetch: typeof fetch;
  const providers: any[] = [];
  const providerFor = (url = RPC_URL, chainId: number | null = 5700) => {
    const provider = new CustomJsonRpcProvider(
      new AbortController().signal,
      url,
      chainId ?? undefined
    );
    providers.push(provider);
    return provider;
  };

  beforeEach(() => {
    originalFetch = global.fetch;
    fetchMock = jest.fn(async (_url, options) =>
      response(resultFor(JSON.parse(options.body)))
    );
    global.fetch = fetchMock;
  });
  afterEach(() => {
    for (const provider of providers.splice(0)) provider.destroy();
    global.fetch = originalFetch;
  });

  it('keeps a healthy read on the original URL with one request', async () => {
    await expect(
      providerFor().send('eth_getBalance', [FROM, 'latest'])
    ).resolves.toBe('0x5208');
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][0]).toBe(RPC_URL);
  });

  it('reserves distinct IDs before concurrent requests settle', async () => {
    const deferred: Array<{ request: any; resolve: (value: any) => void }> = [];
    fetchMock.mockImplementation(
      (_url, options) =>
        new Promise((resolve) => {
          deferred.push({ request: JSON.parse(options.body), resolve });
        })
    );
    const provider = providerFor();
    const first = provider.send('eth_call', [{ data: '0x01' }, 'latest']);
    const second = provider.send('eth_call', [{ data: '0x02' }, 'latest']);
    expect(deferred).toHaveLength(2);
    expect(deferred[0].request.id).not.toBe(deferred[1].request.id);
    deferred[1].resolve(response(resultFor(deferred[1].request, '0x02')));
    deferred[0].resolve(response(resultFor(deferred[0].request, '0x01')));
    await expect(Promise.all([first, second])).resolves.toEqual([
      '0x01',
      '0x02',
    ]);
  });

  it('recovers a replayed deployment call response without treating code as gas', async () => {
    let callReply: any;
    fetchMock.mockImplementation(async (_url, options) => {
      const request = JSON.parse(options.body);
      if (request.method === 'eth_call') {
        callReply = resultFor(request, RUNTIME);
        return response(callReply);
      }
      if (fetchMock.mock.calls.length === 2) return response(callReply);
      return response(resultFor(request));
    });
    const provider = providerFor();
    await expect(
      provider.send('eth_call', [{ from: FROM, data: '0x6000' }, 'latest'])
    ).resolves.toBe(RUNTIME);
    const gas = await sdkFor(provider).getTxGasLimit({
      from: FROM,
      data: '0x6000',
    });
    expect(gas.toString()).toBe('25200');
    expect(fetchMock).toHaveBeenCalledTimes(3);
    const ids = requestsFrom(fetchMock).map((request) => request.id);
    expect(new Set(ids).size).toBe(3);
    expect(ids.every(Number.isSafeInteger)).toBe(true);
    expect(ids[1]).toBe(ids[0] + 1);
    expect(ids[2]).toBe(ids[1] + 1);
    const retryUrl = new URL(fetchMock.mock.calls[2][0]);
    expect(retryUrl.origin).toBe(new URL(RPC_URL).origin);
    expect(retryUrl.pathname).toBe('/v1/token');
    expect(retryUrl.searchParams.get('existing')).toBe('a/b');
    expect(retryUrl.searchParams.get('space')).toBe('a b');
    expect(retryUrl.search).toContain('existing=a%2Fb&space=a%20b');
    expect(retryUrl.searchParams.get('sysweb3_rpc_request')).toBeTruthy();
  });

  it.each([
    { from: FROM, data: '0x6000' },
    { from: FROM, to: FROM, value: '0x0' },
  ])(
    'rejects repeated integrity failures instead of gas fallback: %p',
    async (tx) => {
      fetchMock.mockResolvedValue(
        response({ jsonrpc: '2.0', id: -1, result: RUNTIME })
      );
      await expect(
        sdkFor(providerFor()).getTxGasLimit(tx)
      ).rejects.toMatchObject({
        code: SENTINEL,
        message: expect.stringContaining(SENTINEL),
      });
      expect(fetchMock).toHaveBeenCalledTimes(2);
    }
  );

  it('does not hide an integrity failure in simple-transfer fallback', async () => {
    fetchMock.mockImplementation(async (_url, options) => {
      const request = JSON.parse(options.body);
      if (fetchMock.mock.calls.length === 1) {
        return response({
          jsonrpc: '2.0',
          id: request.id,
          error: { code: -32000, message: 'estimate failed' },
        });
      }
      return response({ jsonrpc: '2.0', id: -1, result: RUNTIME });
    });
    await expect(
      sdkFor(providerFor()).getTxGasLimit({ from: FROM, to: FROM })
    ).rejects.toMatchObject({ code: SENTINEL });
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it('preserves a matched RPC error and advances the next request ID', async () => {
    fetchMock.mockImplementationOnce(async (_url, options) => {
      const request = JSON.parse(options.body);
      return response({
        jsonrpc: '2.0',
        id: request.id,
        error: { code: 3, message: 'execution reverted', data: '0x1234' },
      });
    });
    const provider = providerFor();
    await expect(
      provider.send('eth_call', [{ data: '0x01' }, 'latest'])
    ).rejects.toMatchObject({
      code: 3,
      message: 'execution reverted',
      data: '0x1234',
    });
    await expect(
      provider.send('eth_getBalance', [FROM, 'latest'])
    ).resolves.toBe('0x5208');
    const ids = requestsFrom(fetchMock).map((request) => request.id);
    expect(ids[1]).toBe(ids[0] + 1);
    expect(fetchMock.mock.calls.every(([url]) => url === RPC_URL)).toBe(true);
  });

  it.each([
    'eth_sendRawTransaction',
    'eth_sendTransaction',
    'personal_sign',
    'eth_sign',
    'eth_signTypedData_v4',
    'wallet_sendCalls',
    'eth_newFilter',
    'eth_uninstallFilter',
    'custom_read',
  ])('does not retry an uncertain %s result', async (method) => {
    fetchMock.mockResolvedValue(
      response({ jsonrpc: '2.0', id: -1, result: '0x1234' })
    );
    await expect(providerFor().send(method, ['0x1234'])).rejects.toMatchObject({
      code: SENTINEL,
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it.each([undefined, null, '1', -1])(
    'rejects a missing or nonmatching response ID: %p',
    async (id) => {
      fetchMock.mockResolvedValue(
        response({ jsonrpc: '2.0', id, result: '0x5208' })
      );
      await expect(
        providerFor().send('eth_estimateGas', [{ from: FROM }])
      ).rejects.toMatchObject({ code: SENTINEL });
      expect(fetchMock).toHaveBeenCalledTimes(2);
    }
  );

  it('checks stale errors before accepting their RPC error classification', async () => {
    fetchMock.mockImplementationOnce(async () =>
      response({
        jsonrpc: '2.0',
        id: -1,
        error: { code: 3, message: 'execution reverted' },
      })
    );
    await expect(
      providerFor().send('eth_getBalance', [FROM, 'latest'])
    ).resolves.toBe('0x5208');
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('never caches a stale chain ID', async () => {
    fetchMock.mockImplementationOnce(async () =>
      response({ jsonrpc: '2.0', id: -1, result: '0x1' })
    );
    fetchMock.mockImplementation(async (_url, options) =>
      response(resultFor(JSON.parse(options.body), '0x1644'))
    );
    const provider = providerFor();
    await expect(provider.send('eth_chainId', [])).resolves.toBe('0x1644');
    await expect(provider.send('eth_chainId', [])).resolves.toBe('0x1644');
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('accepts reordered batches and restores request order', async () => {
    fetchMock.mockImplementation(async (_url, options) => {
      const requests = JSON.parse(options.body);
      return response(
        requests
          .map((request: any, index: number) =>
            resultFor(request, `0x${index + 1}`)
          )
          .reverse()
      );
    });
    await expect(
      providerFor().sendBatch('eth_getBalance', [
        [FROM, 'latest'],
        [FROM, 'pending'],
      ])
    ).resolves.toEqual(['0x1', '0x2']);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it.each(['missing', 'duplicate', 'foreign', 'string', 'object'])(
    'rejects a %s batch correlation',
    async (failure) => {
      fetchMock.mockImplementation(async (_url, options) => {
        const requests = JSON.parse(options.body);
        const replies = requests.map((request: any) => resultFor(request));
        if (failure === 'missing') replies.pop();
        if (failure === 'duplicate') replies[1].id = replies[0].id;
        if (failure === 'foreign') replies[1].id = -1;
        if (failure === 'string') replies[1].id = String(replies[1].id);
        return response(failure === 'object' ? replies[0] : replies);
      });
      await expect(
        providerFor().sendBatch('eth_getBalance', [
          [FROM, 'latest'],
          [FROM, 'pending'],
        ])
      ).rejects.toMatchObject({ code: SENTINEL });
      expect(fetchMock).toHaveBeenCalledTimes(2);
    }
  );

  it('does not retry a write batch', async () => {
    fetchMock.mockResolvedValue(response([]));
    await expect(
      providerFor().sendBatch('eth_sendRawTransaction', [['0x01'], ['0x02']])
    ).rejects.toMatchObject({ code: SENTINEL });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('covers inherited ethers send through the same transport', async () => {
    const provider = providerFor();
    fetchMock.mockImplementationOnce(async () =>
      response({ jsonrpc: '2.0', id: -1, result: '0x1' })
    );
    await expect(
      JsonRpcProvider.prototype.send.call(provider, 'eth_blockNumber', [])
    ).resolves.toBe('0x5208');
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('preserves inherited caller IDs while rejecting mixed-batch retries', async () => {
    const provider = providerFor();
    fetchMock.mockImplementation(async (_url, options) => {
      const requests = JSON.parse(options.body);
      return response(
        requests.map((request: any) => resultFor(request)).reverse()
      );
    });
    await expect(
      provider._send([
        {
          jsonrpc: '2.0',
          id: 101,
          method: 'eth_getBalance',
          params: [FROM, 'latest'],
        },
        {
          jsonrpc: '2.0',
          id: 102,
          method: 'eth_getCode',
          params: [FROM, 'latest'],
        },
      ])
    ).resolves.toEqual([
      { jsonrpc: '2.0', id: 101, result: '0x5208' },
      { jsonrpc: '2.0', id: 102, result: '0x5208' },
    ]);
    fetchMock.mockResolvedValue(response([]));
    await expect(
      provider._send([
        {
          jsonrpc: '2.0',
          id: 201,
          method: 'eth_getBalance',
          params: [FROM, 'latest'],
        },
        {
          jsonrpc: '2.0',
          id: 202,
          method: 'eth_sendRawTransaction',
          params: ['0x01'],
        },
      ])
    ).rejects.toMatchObject({ code: SENTINEL });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('validates the initial ethers network auto-detection reply', async () => {
    fetchMock.mockResolvedValue(
      response({ jsonrpc: '2.0', id: -1, result: '0x1' })
    );
    await expect(providerFor(RPC_URL, null).getNetwork()).rejects.toThrow(
      SENTINEL
    );
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("does not reuse another provider instance's wire IDs", async () => {
    let oldReply: any;
    fetchMock.mockImplementation(async (_url, options) => {
      const request = JSON.parse(options.body);
      if (fetchMock.mock.calls.length === 1) {
        oldReply = resultFor(request, RUNTIME);
        return response(oldReply);
      }
      if (fetchMock.mock.calls.length === 2) return response(oldReply);
      return response(resultFor(request));
    });
    await providerFor().send('eth_call', [{ data: '0x6000' }, 'latest']);
    const gas = await sdkFor(providerFor()).getTxGasLimit({ data: '0x6000' });
    expect(gas.toString()).toBe('25200');
    const ids = requestsFrom(fetchMock).map((request) => request.id);
    expect(new Set(ids).size).toBe(3);
    expect(ids.every(Number.isSafeInteger)).toBe(true);
  });

  it('recovers a read batch once using fresh IDs and restores request order', async () => {
    fetchMock.mockImplementation(async (_url, options) => {
      const requests = JSON.parse(options.body);
      if (fetchMock.mock.calls.length === 1) return response([]);
      return response(
        requests
          .map((request: any, index: number) =>
            resultFor(request, `0x${index + 1}`)
          )
          .reverse()
      );
    });
    await expect(
      providerFor().sendBatch('eth_getBalance', [
        [FROM, 'latest'],
        [FROM, 'pending'],
      ])
    ).resolves.toEqual(['0x1', '0x2']);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const [original, retry] = requestsFrom(fetchMock);
    expect(
      new Set([...original, ...retry].map((request) => request.id)).size
    ).toBe(4);
  });

  it('repeats the original serialized read if its caller mutates a payload', async () => {
    let release: (value: any) => void;
    fetchMock.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          release = resolve;
        })
    );
    const payload = {
      jsonrpc: '2.0',
      id: 71,
      method: 'eth_call',
      params: [{ data: '0x6000' }, 'latest'],
    };
    const pending = providerFor()._send(payload);
    payload.method = 'eth_sendRawTransaction';
    payload.id = 72;
    (payload.params[0] as { data: string }).data = '0x01';
    release!(response({ jsonrpc: '2.0', id: -1, result: RUNTIME }));
    await expect(pending).resolves.toEqual([
      { jsonrpc: '2.0', id: 71, result: '0x5208' },
    ]);
    const retry = requestsFrom(fetchMock)[1];
    expect(retry.method).toBe('eth_call');
    expect(retry.params).toEqual([{ data: '0x6000' }, 'latest']);
  });

  it('preserves path, authentication, fragment and existing query bytes on recovery', async () => {
    const url =
      'https://name:password@rpc.example/path/key?token=a%2Fb&space=a%20b#anchor';
    fetchMock.mockImplementationOnce(async () =>
      response({ jsonrpc: '2.0', id: -1, result: '0x0' })
    );
    await providerFor(url).send('eth_getBalance', [FROM, 'latest']);
    const retry = new URL(fetchMock.mock.calls[1][0]);
    expect(retry.origin).toBe('https://rpc.example');
    expect(retry.pathname).toBe('/path/key');
    expect(retry.username).toBe('name');
    expect(retry.password).toBe('password');
    expect(retry.hash).toBe('#anchor');
    expect(retry.search).toContain('?token=a%2Fb&space=a%20b&');
  });

  it('stops recovery if the original AbortSignal is cancelled', async () => {
    const controller = new AbortController();
    const provider = new CustomJsonRpcProvider(
      controller.signal,
      RPC_URL,
      5700
    );
    providers.push(provider);
    fetchMock.mockImplementationOnce(async () => {
      controller.abort();
      return response({ jsonrpc: '2.0', id: -1, result: '0x0' });
    });
    await expect(
      provider.send('eth_getBalance', [FROM, 'latest'])
    ).rejects.toMatchObject({ name: 'AbortError' });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('rejects malformed HTTP-200 JSON instead of inventing gas', async () => {
    fetchMock.mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => {
        throw new SyntaxError('Unexpected end of JSON input');
      },
    });
    await expect(
      sdkFor(providerFor()).getTxGasLimit({ data: '0x6000' })
    ).rejects.toMatchObject({ code: SENTINEL });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('preserves an aborted response-body read', async () => {
    fetchMock.mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => {
        throw new DOMException('Body read aborted', 'AbortError');
      },
    });
    await expect(
      providerFor().send('eth_call', [{ data: '0x6000' }, 'latest'])
    ).rejects.toMatchObject({ name: 'AbortError' });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('keeps an aborted gas quote as cancellation', async () => {
    fetchMock.mockRejectedValueOnce(
      new DOMException('Estimate aborted', 'AbortError')
    );
    await expect(
      sdkFor(providerFor()).getTxGasLimit({ data: '0x6000' })
    ).rejects.toMatchObject({ name: 'AbortError' });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('keeps cancellation during simple-transfer gas fallback', async () => {
    fetchMock.mockImplementationOnce(async (_url, options) => {
      const request = JSON.parse(options.body);
      return response({
        jsonrpc: '2.0',
        id: request.id,
        error: { code: -32000, message: 'estimate failed' },
      });
    });
    fetchMock.mockRejectedValueOnce(
      new DOMException('Fallback aborted', 'AbortError')
    );
    await expect(
      sdkFor(providerFor()).getTxGasLimit({ from: FROM, to: FROM })
    ).rejects.toMatchObject({ name: 'AbortError' });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('keeps an aborted optional fee quote as cancellation', async () => {
    const parentGetBlock = jest
      .spyOn(JsonRpcProvider.prototype, 'getBlock')
      .mockResolvedValue({ baseFeePerGas: 7n });
    fetchMock.mockImplementation(async (_url, options) => {
      const request = JSON.parse(options.body);
      if (request.method === 'eth_maxPriorityFeePerGas')
        throw new DOMException('Priority fee aborted', 'AbortError');
      return response(resultFor(request, '0x7'));
    });
    try {
      await expect(providerFor().getFeeData()).rejects.toMatchObject({
        name: 'AbortError',
      });
    } finally {
      parentGetBlock.mockRestore();
    }
  });

  it('does not invent gas when the allowed recovery request cannot complete', async () => {
    fetchMock.mockImplementationOnce(async () =>
      response({ jsonrpc: '2.0', id: -1, result: RUNTIME })
    );
    fetchMock.mockRejectedValueOnce(new TypeError('Network request failed'));
    await expect(
      sdkFor(providerFor()).getTxGasLimit({ data: '0x6000' })
    ).rejects.toMatchObject({ code: SENTINEL });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it.each([1.5, Infinity, NaN])(
    'rejects an invalid error code without recovery: %p',
    async (code) => {
      fetchMock.mockImplementation(async (_url, options) => {
        const request = JSON.parse(options.body);
        return response({
          jsonrpc: '2.0',
          id: request.id,
          error: { code, message: 'invalid error' },
        });
      });
      await expect(
        providerFor().send('eth_call', [{ data: '0x01' }, 'latest'])
      ).rejects.toMatchObject({ code: SENTINEL });
      expect(fetchMock).toHaveBeenCalledTimes(1);
    }
  );

  it.each(['baseline', 'block', 'priority', 'history'])(
    'preserves integrity failure in dynamic fee %s discovery',
    async (stage) => {
      const integrity = new RpcResponseIntegrityError();
      const provider = {
        getGasPrice: jest.fn().mockResolvedValue(BigNumber.from(7)),
        getBlock: jest.fn().mockResolvedValue({ baseFeePerGas: 7n }),
        send: jest.fn().mockResolvedValue('0x2'),
      };
      if (stage === 'baseline')
        provider.getGasPrice.mockRejectedValueOnce(integrity);
      if (stage === 'block') provider.getBlock.mockRejectedValueOnce(integrity);
      if (stage === 'priority') provider.send.mockRejectedValueOnce(integrity);
      if (stage === 'history') {
        provider.send.mockRejectedValueOnce(
          Object.assign(new Error('priority method unavailable'), {
            code: -32601,
          })
        );
        provider.send.mockRejectedValueOnce(integrity);
      }
      await expect(
        sdkFor(provider).getFeeDataWithDynamicMaxPriorityFeePerGas()
      ).rejects.toBe(integrity);
    }
  );

  it.each([
    ['direct', 'Method not found', -32601, '0x0', '0'],
    ['UNKNOWN_ERROR', 'Method not found', -32601, '0x0', '0'],
    [
      'UNSUPPORTED_OPERATION',
      'the method eth_maxPriorityFeePerGas does not exist',
      -32601,
      '0x2',
      '3',
    ],
    ['UNKNOWN_ERROR', 'Method not found', 4200, '0x0', '0'],
  ])(
    'uses real correlated history after %s unsupported priority normalization',
    async (normalization, message, code, reward, expectedTip) => {
      const provider = providerFor();
      const sdk = sdkFor(provider);
      jest.spyOn(provider, 'getBlock').mockResolvedValue({ baseFeePerGas: 7n });
      if (normalization !== 'direct') {
        provider.send = JsonRpcProvider.prototype.send.bind(provider);
        const normalize = jest.spyOn(provider, 'getRpcError');
        normalize.mockImplementation((payload: any, error: any) => {
          const result = JsonRpcProvider.prototype.getRpcError.call(
            provider,
            payload,
            error
          );
          expect(result.code).toBe(normalization);
          expect(result.error?.code ?? result.info?.error?.code).toBe(code);
          return result;
        });
      }
      fetchMock.mockImplementation(async (_url, options) => {
        const request = JSON.parse(options.body);
        if (request.method === 'eth_maxPriorityFeePerGas') {
          return response({
            jsonrpc: '2.0',
            id: request.id,
            error: { code, message },
          });
        }
        return response(
          resultFor(
            request,
            request.method === 'eth_feeHistory'
              ? { reward: [[reward, reward, reward]] }
              : '0x7'
          )
        );
      });
      const fee = await sdk.getFeeDataWithDynamicMaxPriorityFeePerGas();
      expect(fee.maxPriorityFeePerGas.toString()).toBe(expectedTip);
      expect(fee.gasPrice.toString()).toBe('7');
      expect(requestsFrom(fetchMock).map((request) => request.method)).toEqual([
        'eth_gasPrice',
        'eth_maxPriorityFeePerGas',
        'eth_feeHistory',
      ]);
      expect(
        new Set(requestsFrom(fetchMock).map((request) => request.id)).size
      ).toBe(3);
    }
  );

  it.each([
    'integrity',
    'abort',
    'network',
    'http',
    'rpc-error',
    'generic-unsupported',
  ])(
    'does not use history to hide a real inherited-send %s failure',
    async (failure) => {
      const provider = providerFor();
      provider.send = JsonRpcProvider.prototype.send.bind(provider);
      jest.spyOn(provider, 'getBlock').mockResolvedValue({ baseFeePerGas: 7n });
      const networkError = new TypeError('Network request failed');
      fetchMock.mockImplementation(async (_url, options) => {
        const request = JSON.parse(options.body);
        if (request.method !== 'eth_maxPriorityFeePerGas')
          return response(resultFor(request, '0x7'));
        if (failure === 'abort')
          throw new DOMException('Priority read aborted', 'AbortError');
        if (failure === 'network') throw networkError;
        const rpcError = {
          jsonrpc: '2.0',
          id: failure === 'integrity' ? -1 : request.id,
          error: {
            code: ['rpc-error', 'generic-unsupported'].includes(failure)
              ? -32000
              : -32601,
            message:
              failure === 'generic-unsupported'
                ? 'the method eth_maxPriorityFeePerGas does not exist'
                : 'Method not found',
          },
        };
        return failure === 'http'
          ? { ...response(rpcError), ok: false, status: 503 }
          : response(rpcError);
      });
      const quote =
        sdkFor(provider).getFeeDataWithDynamicMaxPriorityFeePerGas();
      if (failure === 'integrity')
        await expect(quote).rejects.toMatchObject({ code: SENTINEL });
      else if (failure === 'abort')
        await expect(quote).rejects.toMatchObject({ name: 'AbortError' });
      else if (failure === 'network')
        await expect(quote).rejects.toBe(networkError);
      else await expect(quote).rejects.toThrow();
      expect(
        requestsFrom(fetchMock).some(
          (request) => request.method === 'eth_feeHistory'
        )
      ).toBe(false);
    }
  );

  it.each([
    {
      code: 'UNKNOWN_ERROR',
      error: { code: -32601 },
      payload: { method: 'eth_getBalance', params: [] },
    },
    { code: 'UNKNOWN_ERROR', error: { code: -32601 } },
    { code: 'UNSUPPORTED_OPERATION', operation: 'eth_maxPriorityFeePerGas' },
    {
      code: 'NETWORK_ERROR',
      error: { code: -32601 },
      payload: { method: 'eth_maxPriorityFeePerGas', params: [] },
    },
    {
      code: 'UNKNOWN_ERROR',
      error: { code: -32601 },
      payload: { method: 'eth_maxPriorityFeePerGas', params: ['unexpected'] },
    },
    {
      code: 'UNSUPPORTED_OPERATION',
      operation: 'eth_getBalance',
      info: {
        error: { code: -32601 },
        payload: { method: 'eth_maxPriorityFeePerGas', params: [] },
      },
    },
    {
      code: 'UNKNOWN_ERROR',
      error: { name: 'AbortError', code: -32601 },
      payload: { method: 'eth_maxPriorityFeePerGas', params: [] },
    },
  ])(
    'rejects an unsupported-looking wrapper without the matching priority RPC evidence: %p',
    async (error) => {
      const provider = {
        getGasPrice: jest.fn().mockResolvedValue(BigNumber.from(7)),
        getBlock: jest.fn().mockResolvedValue({ baseFeePerGas: 7n }),
        send: jest.fn().mockRejectedValue(error),
      };
      await expect(
        sdkFor(provider).getFeeDataWithDynamicMaxPriorityFeePerGas()
      ).rejects.toBe(error);
      expect(provider.send).toHaveBeenCalledTimes(1);
    }
  );

  it('does not replace an integrity error with legacy fees', async () => {
    const provider = {
      getGasPrice: jest.fn().mockResolvedValue(BigNumber.from(7)),
    };
    const sdk = sdkFor(provider);
    const integrity = new RpcResponseIntegrityError();
    jest
      .spyOn(sdk, 'getFeeDataWithDynamicMaxPriorityFeePerGas')
      .mockRejectedValueOnce(integrity);
    await expect(sdk.getSafeFeeData()).rejects.toBe(integrity);
    expect(provider.getGasPrice).not.toHaveBeenCalled();
  });

  it.each(['eth_gasPrice', 'eth_maxPriorityFeePerGas'])(
    'preserves an inherited optional %s integrity failure',
    async (method) => {
      const parentGetBlock = jest
        .spyOn(JsonRpcProvider.prototype, 'getBlock')
        .mockResolvedValue({ baseFeePerGas: 7n });
      fetchMock.mockImplementation(async (_url, options) => {
        const request = JSON.parse(options.body);
        return response(
          resultFor({ id: request.method === method ? -1 : request.id }, '0x2')
        );
      });
      try {
        await expect(providerFor().getFeeData()).rejects.toMatchObject({
          code: SENTINEL,
        });
      } finally {
        parentGetBlock.mockRestore();
      }
    }
  );

  it('does not fabricate a one-gwei priority fee when the method is unsupported', async () => {
    const parentGetBlock = jest
      .spyOn(JsonRpcProvider.prototype, 'getBlock')
      .mockResolvedValue({ baseFeePerGas: 7n });
    fetchMock.mockImplementation(async (_url, options) => {
      const request = JSON.parse(options.body);
      return response(
        request.method === 'eth_maxPriorityFeePerGas'
          ? {
              jsonrpc: '2.0',
              id: request.id,
              error: { code: -32601, message: 'unsupported method' },
            }
          : resultFor(request, '0x7')
      );
    });
    try {
      await expect(providerFor().getFeeData()).rejects.toThrow(
        'fee data unavailable'
      );
      expect(fetchMock).toHaveBeenCalledTimes(2);
    } finally {
      parentGetBlock.mockRestore();
    }
  });

  it('preserves network fee plugin discovery and its provider/request arguments', async () => {
    const parentGetBlock = jest
      .spyOn(JsonRpcProvider.prototype, 'getBlock')
      .mockResolvedValue({ baseFeePerGas: 7n });
    const provider = providerFor();
    const plugin = {
      url: 'https://fees.example/quote',
      processFunc: jest.fn(async (reader, observedProvider, request) => {
        expect(observedProvider).toBe(provider);
        expect(request.url).toBe('https://fees.example/quote');
        const standard = await reader();
        return { ...standard, maxFeePerGas: 99n, maxPriorityFeePerGas: 11n };
      }),
    };
    jest
      .spyOn(provider, 'getNetwork')
      .mockResolvedValue({ getPlugin: () => plugin });
    try {
      await expect(provider.getFeeData()).resolves.toEqual({
        gasPrice: BigNumber.from(21000),
        maxFeePerGas: BigNumber.from(99),
        maxPriorityFeePerGas: BigNumber.from(11),
      });
      expect(plugin.processFunc).toHaveBeenCalledTimes(1);
    } finally {
      parentGetBlock.mockRestore();
    }
  });

  it.each(['', true, false, Number.MAX_SAFE_INTEGER + 1, null])(
    'keeps ethers fallback for malformed optional gas price: %p',
    async (value) => {
      const parentGetBlock = jest
        .spyOn(JsonRpcProvider.prototype, 'getBlock')
        .mockResolvedValue({ baseFeePerGas: 7n });
      fetchMock.mockImplementation(async (_url, options) => {
        const request = JSON.parse(options.body);
        return response(
          resultFor(request, request.method === 'eth_gasPrice' ? value : '0x2')
        );
      });
      try {
        await expect(providerFor().getFeeData()).resolves.toEqual({
          gasPrice: null,
          maxFeePerGas: BigNumber.from(16),
          maxPriorityFeePerGas: BigNumber.from(2),
        });
      } finally {
        parentGetBlock.mockRestore();
      }
    }
  );

  it.each(['', true, false, Number.MAX_SAFE_INTEGER + 1, null])(
    'does not invent a quote for malformed optional priority fee: %p',
    async (value) => {
      const parentGetBlock = jest
        .spyOn(JsonRpcProvider.prototype, 'getBlock')
        .mockResolvedValue({ baseFeePerGas: 7n });
      fetchMock.mockImplementation(async (_url, options) => {
        const request = JSON.parse(options.body);
        return response(
          resultFor(
            request,
            request.method === 'eth_maxPriorityFeePerGas' ? value : '0x7'
          )
        );
      });
      try {
        await expect(providerFor().getFeeData()).rejects.toThrow(
          'fee data unavailable'
        );
      } finally {
        parentGetBlock.mockRestore();
      }
    }
  );

  it.each([0n, 7n])(
    'retains an RPC zero tip on an EIP-1559 header with base fee %p',
    async (baseFeePerGas) => {
      const parentGetBlock = jest
        .spyOn(JsonRpcProvider.prototype, 'getBlock')
        .mockResolvedValue({ baseFeePerGas });
      fetchMock.mockImplementation(async (_url, options) => {
        const request = JSON.parse(options.body);
        return response(
          resultFor(
            request,
            request.method === 'eth_maxPriorityFeePerGas' ? '0x0' : '0x7'
          )
        );
      });
      try {
        await expect(providerFor().getFeeData()).resolves.toEqual({
          gasPrice: BigNumber.from(7),
          maxFeePerGas: BigNumber.from(baseFeePerGas * 2n),
          maxPriorityFeePerGas: BigNumber.from(0),
        });
        expect(fetchMock).toHaveBeenCalledTimes(2);
      } finally {
        parentGetBlock.mockRestore();
      }
    }
  );

  it.each(['integrity', 'abort'])(
    'preserves %s through the real Polygon fee-plugin wrapper',
    async (failure) => {
      const parentGetBlock = jest
        .spyOn(JsonRpcProvider.prototype, 'getBlock')
        .mockResolvedValue({ baseFeePerGas: 7n });
      const gasStation = jest
        .spyOn(FetchRequest.prototype, 'send')
        .mockResolvedValue({
          bodyJson: { standard: { maxFee: 3, maxPriorityFee: 1 } },
        });
      const provider = providerFor();
      jest.spyOn(provider, 'getNetwork').mockResolvedValue(Network.from(137));
      fetchMock.mockImplementation(async (_url, options) => {
        const request = JSON.parse(options.body);
        if (request.method === 'eth_maxPriorityFeePerGas') {
          if (failure === 'abort')
            throw new DOMException('Fee read cancelled', 'AbortError');
          return response(resultFor({ id: -1 }, '0x2'));
        }
        return response(resultFor(request, '0x7'));
      });
      try {
        await expect(
          sdkFor(provider).getTxGasLimit({
            from: FROM,
            data: '0x6000',
            type: 0,
          })
        ).rejects.toMatchObject(
          failure === 'integrity' ? { code: SENTINEL } : { name: 'AbortError' }
        );
        expect(gasStation).toHaveBeenCalledTimes(1);
      } finally {
        gasStation.mockRestore();
        parentGetBlock.mockRestore();
      }
    }
  );

  it('retains the real Polygon gas-station fee values on a healthy read', async () => {
    const parentGetBlock = jest
      .spyOn(JsonRpcProvider.prototype, 'getBlock')
      .mockResolvedValue({ baseFeePerGas: 7n });
    const gasStation = jest
      .spyOn(FetchRequest.prototype, 'send')
      .mockResolvedValue({
        bodyJson: { standard: { maxFee: 3, maxPriorityFee: 1 } },
      });
    const provider = providerFor();
    jest.spyOn(provider, 'getNetwork').mockResolvedValue(Network.from(137));
    try {
      await expect(provider.getFeeData()).resolves.toEqual({
        gasPrice: BigNumber.from(21000),
        maxFeePerGas: BigNumber.from('3000000000'),
        maxPriorityFeePerGas: BigNumber.from('1000000000'),
      });
      expect(gasStation).toHaveBeenCalledTimes(1);
    } finally {
      gasStation.mockRestore();
      parentGetBlock.mockRestore();
    }
  });
});
