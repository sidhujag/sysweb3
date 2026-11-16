import { withEvmSendIdentity } from '../helpers/evm-send-identity';
jest.unmock('../../src/providers');
jest.resetModules();
(global as any).window.location = { href: 'http://localhost/' };

import { BigNumber, JsonRpcProvider } from '../../src/ethers-v6';
import { LedgerKeyring } from '../../src/ledger';
import { KeyringAccountType } from '../../src/types';
import { admitTestSignedDispatch } from '../helpers/evm-submission';

import type { LedgerHost } from '../../src/ledger/host-types';
import type { EvmSignedSubmission } from '../../src/transactions/evm-submission';

const { Network } = jest.requireActual('ethers/providers');
const { Transaction } = jest.requireActual('ethers/transaction');
const { FetchRequest } = jest.requireActual('ethers/utils');
const { Wallet } = jest.requireActual('ethers/wallet');

const {
  CustomJsonRpcProvider,
  RpcResponseIntegrityError,
  wrapTransactionResponse,
} = jest.requireActual('../../src/providers');
const { RpcReadCapabilities } = jest.requireActual('../../src/rpc-read-client');
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
  headers: new Headers(),
  text: async () =>
    JSON.stringify(json, (_key, value) =>
      typeof value === 'bigint' ? `0x${value.toString(16)}` : value
    ),
  json: async () => json,
});
const feeResponse = async (body: string, evaluate: (request: any) => any) => {
  const request = JSON.parse(body);
  const evaluateFee = async (row: any) => {
    if (
      row.method === 'eth_getBlockByNumber' &&
      row.params[0] === 'latest' &&
      row.params[1] === false
    ) {
      const block = (
        JsonRpcProvider.prototype.getBlock as any
      ).getMockImplementation?.();
      if (block) {
        return resultFor(row, await block());
      }
    }
    return evaluate(row);
  };
  return response(
    Array.isArray(request)
      ? await Promise.all(request.map(evaluateFee))
      : await evaluateFee(request)
  );
};
const enableBatch = async (provider: any, fetchMock: jest.Mock) => {
  fetchMock.mockImplementationOnce(async (_url, init) =>
    response(JSON.parse(init.body).map((request) => resultFor(request, '0x2')))
  );
  await provider.readMany([
    { method: 'eth_gasPrice', params: [] },
    { method: 'eth_maxPriorityFeePerGas', params: [] },
  ]);
  fetchMock.mockClear();
};
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
    {},
    () => () => undefined,
    null
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
      feeResponse(options.body, (request) => resultFor(request))
    );
    global.fetch = fetchMock;
  });
  afterEach(() => {
    for (const provider of providers.splice(0)) provider.destroy();
    global.fetch = originalFetch;
  });

  it.each(['send', 'sendBatch', '_send'] as const)(
    'refuses stateful %s after provider destruction without HTTP',
    async (entry) => {
      const provider = providerFor();
      provider.destroy();
      const pending =
        entry === 'send'
          ? provider.send('eth_sendRawTransaction', ['0x01'])
          : entry === 'sendBatch'
          ? provider.sendBatch('eth_sendRawTransaction', [['0x01']])
          : provider._send({
              jsonrpc: '2.0',
              id: 1,
              method: 'eth_newFilter',
              params: [{}],
            });
      await expect(pending).rejects.toMatchObject({ name: 'AbortError' });
      expect(fetchMock).not.toHaveBeenCalled();
    }
  );

  it.each(['owner', 'destroy'] as const)(
    'cancels stateful HTTP when its %s lifetime ends during body consumption',
    async (end) => {
      const owner = new AbortController();
      const provider = new CustomJsonRpcProvider(owner.signal, RPC_URL, 5700);
      providers.push(provider);
      let release!: () => void;
      let bodyStarted!: () => void;
      const started = new Promise<void>((resolve) => {
        bodyStarted = resolve;
      });
      const cancel = jest.fn().mockResolvedValue(undefined);
      let wireSignal: AbortSignal;
      fetchMock.mockImplementation(async (_url, init) => {
        wireSignal = init.signal;
        return {
          ...response({}),
          body: { cancel },
          text: () =>
            new Promise((resolve) => {
              bodyStarted();
              release = () =>
                resolve(
                  JSON.stringify(resultFor(JSON.parse(init.body), '0xhash'))
                );
            }),
        };
      });
      const pending = provider.send('eth_sendRawTransaction', ['0x01']);
      const rejected = expect(pending).rejects.toMatchObject({
        name: 'AbortError',
      });
      await started;
      if (end === 'owner') owner.abort();
      else provider.destroy();
      expect(wireSignal!.aborted).toBe(true);
      release();
      await rejected;
      expect(fetchMock).toHaveBeenCalledTimes(1);
      expect(cancel).toHaveBeenCalledTimes(1);
    }
  );

  it('cancels a late stateful response after destroy instead of accepting it', async () => {
    const provider = providerFor();
    let release!: () => void;
    const cancel = jest.fn().mockResolvedValue(undefined);
    fetchMock.mockImplementation(
      (_url, init) =>
        new Promise((resolve) => {
          release = () =>
            resolve({
              ...response(resultFor(JSON.parse(init.body))),
              body: { cancel },
            });
        })
    );
    const pending = provider.send('eth_sendRawTransaction', ['0x01']);
    const rejected = expect(pending).rejects.toMatchObject({
      name: 'AbortError',
    });
    await new Promise((resolve) => setImmediate(resolve));
    provider.destroy();
    release();
    await rejected;
    expect(cancel).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it.each(['sendTransaction', 'broadcastTransaction'] as const)(
    'refuses public %s before any transport after destruction',
    async (method) => {
      const raw = await new Wallet(`0x${'11'.repeat(32)}`).signTransaction({
        chainId: 5700,
        to: FROM,
        nonce: 0,
        value: 1,
        gasLimit: 21000,
        gasPrice: 1,
      });
      const provider = providerFor();
      provider.destroy();
      await expect(provider[method](raw)).rejects.toMatchObject({
        name: 'AbortError',
      });
      expect(fetchMock).not.toHaveBeenCalled();
    }
  );

  it.each([200, 400, 429])(
    'bounds stateful HTTP %s bodies before JSON parsing',
    async (status) => {
      const provider = providerFor();
      const cancel = jest.fn().mockResolvedValue(undefined);
      fetchMock.mockResolvedValue({
        ok: status === 200,
        status,
        headers: new Headers({
          'content-type': 'application/json',
          'content-length': String(2 * 1024 * 1024 + 1),
        }),
        body: { cancel },
        text: jest.fn(),
        json: jest.fn(),
      });
      await expect(
        provider.send('eth_sendRawTransaction', ['0x01'])
      ).rejects.toMatchObject({ code: SENTINEL });
      expect(fetchMock).toHaveBeenCalledTimes(1);
      expect(cancel).toHaveBeenCalledTimes(1);
      expect(fetchMock.mock.results[0].value).toBeDefined();
    }
  );

  it('rejects stateful HTML and an undeclared oversized stream without retry', async () => {
    const provider = providerFor();
    const htmlCancel = jest.fn().mockResolvedValue(undefined);
    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-type': 'text/html' }),
      body: { cancel: htmlCancel },
    });
    await expect(provider.send('eth_newFilter', [{}])).rejects.toMatchObject({
      code: SENTINEL,
    });
    expect(htmlCancel).toHaveBeenCalledTimes(1);
    let streamCancelled = 0;
    fetchMock.mockResolvedValueOnce(
      new Response(
        new ReadableStream({
          start(controller) {
            controller.enqueue(new Uint8Array(2 * 1024 * 1024 + 1));
          },
          cancel() {
            streamCancelled++;
          },
        }),
        { headers: { 'content-type': 'application/json' } }
      )
    );
    await expect(
      provider.send('eth_sendRawTransaction', ['0x01'])
    ).rejects.toMatchObject({ code: SENTINEL });
    expect(streamCancelled).toBe(1);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it.each(['headers', 'body'] as const)(
    'settles stateful cancellation while noncooperative %s cleanup is pending',
    async (stage) => {
      const provider = providerFor();
      let release!: () => void;
      let started!: () => void;
      const reading = new Promise<void>((resolve) => {
        started = resolve;
      });
      const cancel = jest.fn().mockResolvedValue(undefined);
      fetchMock.mockImplementation((_url, init) => {
        const value = {
          ...response(resultFor(JSON.parse(init.body))),
          body: { cancel },
        };
        if (stage === 'headers')
          return new Promise((resolve) => {
            release = () => resolve(value);
            started();
          });
        return Promise.resolve({
          ...value,
          text: () =>
            new Promise((resolve) => {
              release = () =>
                resolve(JSON.stringify(resultFor(JSON.parse(init.body))));
              started();
            }),
        });
      });
      const pending = provider.send('eth_sendRawTransaction', ['0x01']);
      const rejected = expect(pending).rejects.toMatchObject({
        name: 'AbortError',
      });
      await reading;
      provider.destroy();
      await rejected;
      expect(cancel).not.toHaveBeenCalled();
      release();
      await new Promise((resolve) => setImmediate(resolve));
      expect(cancel).toHaveBeenCalledTimes(1);
      expect(fetchMock).toHaveBeenCalledTimes(1);
    }
  );

  it('uses the configured deadline for a noncooperative stateful fetch', async () => {
    jest.useFakeTimers();
    const provider = new CustomJsonRpcProvider(
      new AbortController().signal,
      RPC_URL,
      5700,
      { timeoutMs: 10 }
    );
    providers.push(provider);
    let release!: () => void;
    const cancel = jest.fn().mockResolvedValue(undefined);
    fetchMock.mockImplementation(
      (_url, init) =>
        new Promise((resolve) => {
          release = () =>
            resolve({
              ...response(resultFor(JSON.parse(init.body))),
              body: { cancel },
            });
        })
    );
    try {
      const pending = provider.send('eth_sendRawTransaction', ['0x01']);
      const rejected = expect(pending).rejects.toMatchObject({
        name: 'AbortError',
      });
      await jest.advanceTimersByTimeAsync(10);
      await rejected;
      release();
      await jest.advanceTimersByTimeAsync(0);
      expect(cancel).toHaveBeenCalledTimes(1);
      expect(fetchMock).toHaveBeenCalledTimes(1);
    } finally {
      jest.useRealTimers();
    }
  });

  it('shares only supplied endpoint capability across new providers', async () => {
    const capabilities = new RpcReadCapabilities(RPC_URL);
    fetchMock.mockImplementation(async (_url, init) => {
      const request = JSON.parse(init.body);
      return response(
        Array.isArray(request)
          ? {
              jsonrpc: '2.0',
              id: null,
              error: { code: -32600, message: 'Batch unsupported' },
            }
          : resultFor(request)
      );
    });
    for (let i = 0; i < 2; i++) {
      const provider = new CustomJsonRpcProvider(
        new AbortController().signal,
        RPC_URL,
        5700,
        { capabilities }
      );
      providers.push(provider);
      await expect(
        provider.sendBatch('eth_getBalance', [
          [FROM, 'latest'],
          [FROM, 'pending'],
        ])
      ).resolves.toEqual(['0x5208', '0x5208']);
    }
    expect(requestsFrom(fetchMock).filter(Array.isArray)).toHaveLength(1);
    expect(
      () =>
        new CustomJsonRpcProvider(
          new AbortController().signal,
          RPC_URL + '&other=1',
          5700,
          { capabilities }
        )
    ).toThrow('another endpoint');
  });

  it('bounds sixty-four ordinary provider reads to four active bodies', async () => {
    let active = 0;
    let peak = 0;
    fetchMock.mockImplementation(async (_url, init) => {
      const request = JSON.parse(init.body);
      const rows = Array.isArray(request) ? request : [request];
      active++;
      peak = Math.max(peak, active);
      return {
        ...response(
          Array.isArray(request)
            ? rows.map((row) => resultFor(row))
            : resultFor(request)
        ),
        text: async () => {
          await new Promise((resolve) => setTimeout(resolve, 1));
          active--;
          return JSON.stringify(
            Array.isArray(request)
              ? rows.map((row) => resultFor(row))
              : resultFor(request)
          );
        },
      };
    });
    const provider = providerFor();
    await enableBatch(provider, fetchMock);
    const results = await Promise.all(
      Array.from({ length: 64 }, () =>
        provider.send('eth_getBalance', [FROM, 'latest'])
      )
    );
    expect(peak).toBeLessThanOrEqual(4);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(results).toEqual(Array(64).fill('0x5208'));
  });

  it.each(['send', 'sendBatch', '_send'] as const)(
    'applies bounded response validation through %s',
    async (entry) => {
      const provider = providerFor();
      const run = () =>
        entry === 'send'
          ? provider.send('eth_call', [{ data: '0x' }, 'latest'])
          : entry === 'sendBatch'
          ? provider.sendBatch('eth_call', [[{ data: '0x' }, 'latest']])
          : provider._send({
              jsonrpc: '2.0',
              id: 7,
              method: 'eth_call',
              params: [{ data: '0x' }, 'latest'],
            });
      fetchMock.mockImplementation(async (_url, init) => ({
        ...response(resultFor(JSON.parse(init.body))),
        headers: new Headers({ 'content-type': 'text/html' }),
      }));
      await expect(run()).rejects.toMatchObject({ code: SENTINEL });
      fetchMock.mockImplementation(async (_url, init) =>
        response(resultFor(JSON.parse(init.body), 'x'.repeat(2 * 1024 * 1024)))
      );
      await expect(run()).rejects.toMatchObject({ code: SENTINEL });
      provider.destroy();
      const count = fetchMock.mock.calls.length;
      await expect(run()).rejects.toMatchObject({ name: 'AbortError' });
      expect(fetchMock).toHaveBeenCalledTimes(count);
    }
  );

  it('holds queued reads during HTTP429 cooldown and resumes after expiry', async () => {
    const now = jest.spyOn(Date, 'now');
    let time = 100000;
    now.mockImplementation(() => time);
    try {
      const provider = providerFor();
      const cancel = jest.fn().mockResolvedValue(undefined);
      fetchMock.mockResolvedValueOnce({
        ...response({}),
        ok: false,
        status: 429,
        body: { cancel },
      });
      await expect(
        provider.send('eth_getBalance', [FROM, 'latest'])
      ).rejects.toMatchObject({ status: 429 });
      expect(cancel).toHaveBeenCalledTimes(1);
      expect(provider.isInCooldown).toBe(true);
      await expect(
        provider.send('eth_getCode', [FROM, 'latest'])
      ).rejects.toMatchObject({ status: 429 });
      expect(fetchMock).toHaveBeenCalledTimes(1);
      time += 120001;
      await expect(
        provider.send('eth_getBalance', [FROM, 'latest'])
      ).resolves.toBe('0x5208');
      expect(fetchMock).toHaveBeenCalledTimes(2);
      expect(provider.isInCooldown).toBe(false);
      expect(provider.serverHasAnError).toBe(false);
    } finally {
      now.mockRestore();
    }
  });

  it('preserves named read parameters through inherited ethers transport', async () => {
    const provider = providerFor();
    await expect(
      provider._send({
        jsonrpc: '2.0',
        id: 11,
        method: 'eth_getBalance',
        params: { address: FROM, block: 'latest' },
      })
    ).resolves.toEqual([{ jsonrpc: '2.0', id: 11, result: '0x5208' }]);
    expect(requestsFrom(fetchMock)[0].params).toEqual({
      address: FROM,
      block: 'latest',
    });
  });

  it('coalesces concurrent cold chain reads without hiding a new fresh verification', async () => {
    const captured: Array<{ body: any; resolve: (value: any) => void }> = [];
    fetchMock.mockImplementation(
      (_url, init) =>
        new Promise((resolve) =>
          captured.push({ body: JSON.parse(init.body), resolve })
        )
    );
    const provider = providerFor();
    const cold = Array.from({ length: 50 }, () =>
      provider.send('eth_chainId', [])
    );
    await new Promise((resolve) => setImmediate(resolve));
    expect(captured).toHaveLength(1);
    const verify = provider.verifyConfiguredChainId(true);
    await new Promise((resolve) => setImmediate(resolve));
    expect(captured).toHaveLength(2);
    captured[1].resolve(response(resultFor(captured[1].body, '0x1644')));
    await verify;
    captured[0].resolve(response(resultFor(captured[0].body, '0x1')));
    await Promise.all(cold);
    await expect(provider.send('eth_chainId', [])).resolves.toBe('0x1644');
    expect(captured).toHaveLength(2);
  });

  it('expires ordinary identity on the shared thirty-second read owner', async () => {
    const now = jest.spyOn(Date, 'now');
    let time = 100000;
    now.mockImplementation(() => time);
    try {
      const provider = providerFor();
      let actual = '0x1644';
      fetchMock.mockImplementation(async (_url, init) =>
        response(resultFor(JSON.parse(init.body), actual))
      );
      await expect(provider.send('eth_chainId', [])).resolves.toBe('0x1644');
      actual = '0x1';
      time += 29999;
      await expect(provider.send('eth_chainId', [])).resolves.toBe('0x1644');
      expect(fetchMock).toHaveBeenCalledTimes(1);
      time += 1;
      await expect(provider.send('eth_chainId', [])).resolves.toBe('0x1');
      expect(fetchMock).toHaveBeenCalledTimes(2);
      await expect(provider.verifyConfiguredChainId(true)).rejects.toThrow(
        'does not match'
      );
      expect(fetchMock).toHaveBeenCalledTimes(3);
    } finally {
      now.mockRestore();
    }
  });

  it('does not reuse cached identity after a failed fresh probe', async () => {
    const provider = providerFor();
    fetchMock.mockImplementation(async (_url, init) =>
      response(resultFor(JSON.parse(init.body), '0x1644'))
    );
    await provider.send('eth_chainId', []);
    fetchMock.mockRejectedValueOnce(new Error('probe unavailable'));
    await expect(provider.verifyConfiguredChainId(true)).rejects.toThrow(
      'probe unavailable'
    );
    await provider.send('eth_chainId', []);
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it('refuses construction without an explicit session guard factory', () => {
    const unavailable = jest.fn(() => {
      throw new Error('A missing guard must reject before using the wallet');
    });
    expect(() =>
      Reflect.construct(EthereumTransactions, [
        unavailable,
        unavailable,
        unavailable,
        undefined,
        undefined,
        undefined,
        null,
      ])
    ).toThrow('Ethereum transactions require a signing context');
    expect(unavailable).not.toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([
    ['missing guard', () => undefined],
    [
      'async factory',
      async () => {
        throw new Error('Late factory rejection');
      },
    ],
    [
      'async guard',
      () => async () => {
        throw new Error('Late guard rejection');
      },
    ],
  ])(
    'rejects a %s before EVM submission is admitted',
    async (_label, capture) => {
      const chain = { ...network, kind: 'ethereum', slip44: 60 };
      const type = KeyringAccountType.Imported;
      const key = jest.fn();
      const captureSubmission = jest.fn();
      const sdk = new EthereumTransactions(
        () => chain,
        key,
        () => ({
          activeNetwork: chain,
          activeAccountId: 0,
          activeAccountType: type,
          accounts: { [type]: { 0: { address: FROM } } },
        }),
        undefined,
        undefined,
        capture,
        captureSubmission
      );
      try {
        await expect(
          sdk.sendFormattedTransaction(
            { to: FROM },
            true,
            withEvmSendIdentity(sdk, {
              mode: 'specialized',
              assertCurrent: () => undefined,
            })
          )
        ).rejects.toMatchObject({
          message: expect.stringContaining('synchronous'),
          transactionNotBroadcast: true,
        });
        expect(key).not.toHaveBeenCalled();
        expect(captureSubmission).not.toHaveBeenCalled();
        expect(fetchMock).not.toHaveBeenCalled();
      } finally {
        sdk.web3Provider.destroy();
      }
    }
  );

  it.each(['blockbook', 'trezor'])(
    'uses the explicit network family when an EVM RPC URL contains %s',
    async (name) => {
      const url = `https://${name}.example/evm`;
      let selected = { url, kind: 'ethereum', chainId: 5700 };
      const sdk = new EthereumTransactions(
        () => selected,
        () => {
          throw new Error('Read-only fixture must not access a signing key');
        },
        () => ({ activeNetwork: selected }),
        undefined,
        undefined,
        () => () => undefined,
        null
      );
      const ethereum = sdk.web3Provider;
      expect(ethereum).toBeInstanceOf(CustomJsonRpcProvider);
      providers.push(ethereum);
      await expect(ethereum.send('eth_blockNumber', [])).resolves.toBe(
        '0x5208'
      );
      expect(fetchMock.mock.calls[0][0]).toBe(url);
      selected = { ...selected, kind: 'syscoin' };
      expect(sdk.web3Provider).toBeUndefined();
      expect(ethereum.signal.aborted).toBe(true);
      expect(fetchMock).toHaveBeenCalledTimes(1);
    }
  );

  it.each(['before-sign', 'after-persist', 'revoked', 'current'])(
    'checks the RPC chain on both sides of real Ledger signing (%s)',
    async (scenario) => {
      const provider = providerFor();
      const wallet = new Wallet(`0x${'11'.repeat(32)}`);
      const chain = { ...network, kind: 'ethereum', slip44: 60 };
      const ledgerType = KeyringAccountType.Ledger;
      const state = {
        activeAccountType: ledgerType,
        activeAccountId: 0,
        activeNetwork: chain,
        accounts: { [ledgerType]: { 0: { address: wallet.address } } },
      };
      const events: string[] = [];
      let stored: EvmSignedSubmission | undefined;
      let live = true;
      let chainReads = 0;
      let chainEntered!: () => void;
      let releaseChain!: () => void;
      const entered = new Promise<void>((resolve) => {
        chainEntered = resolve;
      });
      const held = new Promise<void>((resolve) => {
        releaseChain = resolve;
      });
      const sign = jest.fn(async ({ unsignedTxHex }, authority) => {
        authority?.assertCurrent();
        events.push('sign');
        const tx = Transaction.from(`0x${unsignedTxHex}`);
        const signature = wallet.signingKey.sign(tx.unsignedHash);
        return {
          r: signature.r.slice(2),
          s: signature.s.slice(2),
          v: signature.v.toString(16),
        };
      });
      const host = {
        getStatus: () => ({ connected: true }),
        evm: { signTransaction: sign },
      } as unknown as LedgerHost;
      const sdk = new EthereumTransactions(
        () => chain,
        () => {
          throw Error('Hardware send reached software key access');
        },
        () => state,
        new LedgerKeyring(undefined, host),
        undefined,
        () => () => undefined,
        () => ({
          assertCurrent: () => undefined,
          dispatchSigned: admitTestSignedDispatch,
          async persistSigned(record: EvmSignedSubmission) {
            events.push('persist');
            stored = record;
          },
        })
      );
      Object.defineProperty(sdk, 'web3Provider', { get: () => provider });
      fetchMock.mockImplementation(async (_url, options) => {
        const request = JSON.parse(options.body);
        switch (request.method) {
          case 'eth_chainId': {
            chainReads++;
            events.push('chain');
            if (scenario === 'revoked' && chainReads === 2) {
              chainEntered();
              await held;
            }
            const wrong =
              scenario === 'before-sign' ||
              (scenario === 'after-persist' && chainReads === 2);
            return response(resultFor(request, wrong ? '0x1' : '0x1644'));
          }
          case 'eth_blockNumber':
            return response(resultFor(request, '0x1'));
          case 'eth_sendRawTransaction':
            events.push('post');
            expect(request.params).toEqual([stored?.rawTransaction]);
            return response(resultFor(request, stored?.hash));
          default:
            throw new Error(`Unexpected RPC ${request.method}`);
        }
      });
      const sending = sdk.sendFormattedTransaction(
        {
          to: FROM,
          nonce: 0,
          gasLimit: '21000',
          gasPrice: '1',
          value: '1',
        },
        true,
        withEvmSendIdentity(sdk, {
          mode: 'specialized',
          assertCurrent() {
            if (!live) throw new Error('Review closed');
          },
        })
      );
      if (scenario === 'before-sign') {
        await expect(sending).rejects.toMatchObject({
          transactionNotBroadcast: true,
          message: expect.stringContaining('does not match'),
        });
        expect(sign).not.toHaveBeenCalled();
        expect(stored).toBeUndefined();
        expect(events).toEqual(['chain']);
      } else if (scenario === 'current') {
        const sent = await sending;
        expect(sent.hash).toBe(stored?.hash);
        expect(sign).toHaveBeenCalledWith(
          expect.anything(),
          expect.objectContaining({
            assertCurrent: expect.any(Function),
            signal: expect.any(AbortSignal),
          })
        );
        expect(events).toEqual(['chain', 'sign', 'persist', 'chain', 'post']);
      } else {
        if (scenario === 'revoked') {
          await Promise.race([entered, sending]);
          live = false;
          releaseChain();
        }
        const error = await sending.catch((cause) => cause);
        expect(error).toMatchObject({
          transactionNotBroadcast: true,
          signedTransactionHash: stored?.hash,
          message: expect.stringContaining(
            scenario === 'revoked' ? 'Review closed' : 'does not match'
          ),
        });
        expect(stored?.rawTransaction).toMatch(/^0x/);
        expect(events).toEqual(['chain', 'sign', 'persist', 'chain']);
      }
    }
  );

  it('does not borrow a live-chain verification started before hardware dispatch admission', async () => {
    const provider = providerFor();
    let respond!: () => void;
    fetchMock.mockImplementationOnce(
      (_url, options) =>
        new Promise((resolve) => {
          respond = () =>
            resolve(response(resultFor(JSON.parse(options.body), '0x1644')));
        })
    );
    fetchMock.mockImplementationOnce(async (_url, options) =>
      response(resultFor(JSON.parse(options.body), '0x1'))
    );
    const earlier = provider.verifyConfiguredChainId();
    try {
      await expect(provider.verifyConfiguredChainId(true)).rejects.toThrow(
        'does not match'
      );
    } finally {
      respond();
    }
    await expect(earlier).resolves.toBeUndefined();
    expect(requestsFrom(fetchMock).map(({ method }) => method)).toEqual([
      'eth_chainId',
      'eth_chainId',
    ]);
  });

  it('keeps a healthy read on the original URL with one request', async () => {
    await expect(
      providerFor().send('eth_getBalance', [FROM, 'latest'])
    ).resolves.toBe('0x5208');
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][0]).toBe(RPC_URL);
  });

  it('captures endpoint fetch policy consistently for reads and controls', async () => {
    const headers = new Headers({ Authorization: 'Bearer fixture' });
    const init: RequestInit = {
      headers,
      credentials: 'include',
      cache: 'no-store',
      referrerPolicy: 'no-referrer',
      redirect: 'follow',
    };
    const provider = new CustomJsonRpcProvider(
      new AbortController().signal,
      RPC_URL,
      1,
      { requestInit: init }
    );
    providers.push(provider);
    headers.set('Authorization', 'changed');
    await provider.send('eth_getBalance', [FROM, 'latest']);
    await provider.send('eth_newBlockFilter', []);
    for (const [, actual] of fetchMock.mock.calls) {
      expect(actual).toMatchObject({
        credentials: 'include',
        cache: 'no-store',
        referrerPolicy: 'no-referrer',
        redirect: 'error',
      });
      expect(new Headers(actual.headers).get('Authorization')).toBe(
        'Bearer fixture'
      );
    }
  });

  it.each([307, 308])(
    'refuses an actual HTTP %s stateful redirect without a second POST',
    async (status) => {
      const http = jest.requireActual('http');
      const nodeFetch = jest.requireActual('node-fetch');
      const redirected: string[] = [];
      const target = http.createServer((request, reply) => {
        redirected.push(request.method);
        reply.end('{}');
      });
      await new Promise<void>((resolve) =>
        target.listen(0, '127.0.0.1', resolve)
      );
      const endpoint = http.createServer((request, reply) => {
        request.resume();
        reply.writeHead(status, {
          Location: `http://127.0.0.1:${target.address().port}/redirected`,
        });
        reply.end();
      });
      await new Promise<void>((resolve) =>
        endpoint.listen(0, '127.0.0.1', resolve)
      );
      const fetcher = jest.fn(nodeFetch.default ?? nodeFetch);
      const provider = new CustomJsonRpcProvider(
        new AbortController().signal,
        `http://127.0.0.1:${endpoint.address().port}/rpc`,
        1,
        { fetch: fetcher }
      );
      try {
        await expect(
          provider.send('eth_sendRawTransaction', ['0xdeadbeef'])
        ).rejects.toBeDefined();
        expect(fetcher).toHaveBeenCalledTimes(1);
        expect(redirected).toEqual([]);
      } finally {
        provider.destroy();
        await Promise.all([
          new Promise<void>((resolve) => endpoint.close(resolve)),
          new Promise<void>((resolve) => target.close(resolve)),
        ]);
      }
    }
  );

  it('cancels only the owned control request and keeps the shared provider usable', async () => {
    const provider = providerFor();
    const owner = new AbortController();
    let ready!: () => void;
    let release!: () => void;
    const started = new Promise<void>((resolve) => {
      ready = resolve;
    });
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    let physical!: AbortSignal;
    fetchMock.mockImplementationOnce(async (_url, init) => {
      physical = init.signal;
      ready();
      await held;
      return response(resultFor(JSON.parse(init.body), '0x1'));
    });
    const request = provider.send('eth_newBlockFilter', [], {
      signal: owner.signal,
    });
    const failed = expect(request).rejects.toMatchObject({
      name: 'AbortError',
    });
    await started;
    owner.abort();
    await failed;
    expect(physical.aborted).toBe(true);
    expect(provider.signal.aborted).toBe(false);
    await expect(provider.send('eth_blockNumber', [])).resolves.toBe('0x5208');
    release();
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('keeps exact bigint chain configuration out of serializable provider state', async () => {
    const chainId = 9007199254740993n;
    const provider = new CustomJsonRpcProvider(
      new AbortController().signal,
      RPC_URL,
      chainId
    );
    providers.push(provider);
    expect(() => JSON.stringify(provider)).not.toThrow();
    const transaction = {
      provider,
      chainId,
      value: 0n,
      gasLimit: 1n,
      gasPrice: 1n,
      maxFeePerGas: null,
      maxPriorityFeePerGas: null,
      wait: async () => ({}),
    };
    expect(() =>
      JSON.stringify(wrapTransactionResponse(transaction))
    ).not.toThrow();
    fetchMock.mockImplementation(async (_url, init) =>
      response(resultFor(JSON.parse(init.body), `0x${chainId.toString(16)}`))
    );
    await expect(
      provider.verifyConfiguredChainId(true)
    ).resolves.toBeUndefined();
    fetchMock.mockImplementation(async (_url, init) =>
      response(
        resultFor(JSON.parse(init.body), `0x${(chainId - 1n).toString(16)}`)
      )
    );
    await expect(provider.verifyConfiguredChainId(true)).rejects.toThrow(
      'does not match'
    );
  });

  it('shares physical capacity across read, stateful and fee HTTP requests', async () => {
    let release!: () => void;
    let started!: () => void;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    const ready = new Promise<void>((resolve) => {
      started = resolve;
    });
    const requests: string[] = [];
    const rpc = jest.fn(async (_url, init) => {
      const row = JSON.parse(init.body);
      if (Array.isArray(row)) {
        requests.push('fee-reads');
        return feeResponse(init.body, (request) =>
          resultFor(
            request,
            request.method === 'eth_getBlockByNumber'
              ? { baseFeePerGas: '0x7' }
              : '0x2'
          )
        );
      }
      requests.push(row.method);
      if (row.method === 'eth_getBalance')
        return {
          ...response(resultFor(row)),
          text: async () => {
            started();
            await held;
            return JSON.stringify(resultFor(row));
          },
        };
      return response(resultFor(row));
    });
    const provider = new CustomJsonRpcProvider(
      new AbortController().signal,
      RPC_URL,
      137,
      { fetch: rpc, maxConcurrency: 1 }
    );
    providers.push(provider);
    jest.spyOn(provider, 'getNetwork').mockResolvedValue(Network.from(137));
    jest.spyOn(provider, '_perform').mockResolvedValue('0x2');
    const block = jest
      .spyOn(JsonRpcProvider.prototype, 'getBlock')
      .mockResolvedValue({ baseFeePerGas: 7n });
    fetchMock.mockImplementation(async () => {
      requests.push('fee-http');
      return new Response(
        JSON.stringify({ standard: { maxFee: 3, maxPriorityFee: 1 } }),
        { headers: { 'content-type': 'application/json' } }
      );
    });
    try {
      const reading = provider.readMany([
        { method: 'eth_getBalance', params: [FROM, 'latest'] },
      ]);
      await ready;
      const writing = provider.send('eth_sendRawTransaction', ['0x01']);
      const fees = provider.getFeeData();
      for (let i = 0; i < 10; i++) await Promise.resolve();
      expect(requests).toEqual(['eth_getBalance']);
      release();
      await Promise.all([reading, writing, fees]);
      expect(requests).toEqual([
        'eth_getBalance',
        'eth_sendRawTransaction',
        'fee-http',
        'fee-reads',
      ]);
    } finally {
      release();
      block.mockRestore();
    }
  });

  it('captures nested request input once before the ethers collection delay', async () => {
    const provider = providerFor();
    let captures = 0;
    const transaction = {
      toJSON: () => {
        captures++;
        return { to: FROM, data: '0x01' };
      },
    };
    const call = provider.send('eth_call', [transaction, 'latest']);
    transaction.toJSON = () => ({ to: FROM, data: '0xff' });
    await call;
    expect(captures).toBe(1);
    expect(requestsFrom(fetchMock)[0].params[0].data).toBe('0x01');
  });

  it('reuses the original fee block when a plugin invokes its callback twice', async () => {
    const provider = providerFor();
    const block = jest
      .spyOn(JsonRpcProvider.prototype, 'getBlock')
      .mockResolvedValue({ baseFeePerGas: 7n });
    const plugin = {
      url: 'https://fees.example',
      processFunc: async (read) => {
        const first = await read();
        expect(await read()).toBe(first);
        return first;
      },
    };
    jest
      .spyOn(provider, 'getNetwork')
      .mockResolvedValue({ getPlugin: () => plugin });
    fetchMock.mockImplementation(async (_url, init) =>
      feeResponse(init.body, (row) => resultFor(row, '0x2'))
    );
    try {
      await expect(provider.getFeeData()).resolves.toMatchObject({
        maxFeePerGas: BigNumber.from(16),
      });
      expect(
        requestsFrom(fetchMock)
          .flat()
          .filter((request) => request.method === 'eth_getBlockByNumber')
      ).toHaveLength(1);
      expect(requestsFrom(fetchMock).flat()).toHaveLength(3);
    } finally {
      block.mockRestore();
    }
  });

  it('cancels ordinary fee RPC bodies at the quote deadline', async () => {
    let started!: () => void;
    let release!: () => void;
    const ready = new Promise<void>((resolve) => {
      started = resolve;
    });
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    let observedSignal!: AbortSignal;
    const fetcher = jest.fn(async (_url, init) => {
      observedSignal = init.signal;
      return {
        ...response([]),
        text: async () => {
          started();
          await held;
          return '[]';
        },
      };
    });
    const provider = new CustomJsonRpcProvider(
      new AbortController().signal,
      RPC_URL,
      1,
      { fetch: fetcher, timeoutMs: 40 }
    );
    providers.push(provider);
    const originalNetwork = provider.getNetwork.bind(provider);
    jest.spyOn(provider, 'getNetwork').mockImplementation(async () => {
      await new Promise((resolve) => setTimeout(resolve, 15));
      return originalNetwork();
    });
    const reading = provider.getFeeData();
    const rejected = expect(reading).rejects.toMatchObject({
      name: 'AbortError',
    });
    await ready;
    await rejected;
    expect(observedSignal.aborted).toBe(true);
    expect(provider.signal.aborted).toBe(false);
    release();
  });

  it.each(['invalid', [], 3])(
    'rejects malformed fee block %p',
    async (block) => {
      const provider = providerFor();
      fetchMock.mockImplementation(async (_url, init) =>
        response(
          JSON.parse(init.body).map((request) =>
            resultFor(
              request,
              request.method === 'eth_getBlockByNumber' ? block : '0x2'
            )
          )
        )
      );
      await expect(provider.getFeeData()).rejects.toMatchObject({
        code: SENTINEL,
      });
    }
  );

  it('preserves a fee request-size failure even when a plugin supplies a fallback', async () => {
    const provider = new CustomJsonRpcProvider(
      new AbortController().signal,
      RPC_URL,
      1,
      { maxRequestBytes: 200 }
    );
    providers.push(provider);
    jest.spyOn(provider, 'getNetwork').mockResolvedValue({
      getPlugin: () => ({
        url: 'https://fees.example',
        processFunc: async (_read, _provider, request) => {
          request.body = 'x'.repeat(201);
          try {
            await request.send();
          } catch {
            /* The original transport error must survive fallback. */
          }
          return { gasPrice: 1n, maxFeePerGas: 2n, maxPriorityFeePerGas: 1n };
        },
      }),
    });
    const reader = {
      getBlock: async () => ({ baseFeePerGas: 0n }),
      send: async () => '0x1',
    };
    await expect(provider.getFeeData(reader)).rejects.toThrow(
      'request exceeded size limit'
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('uses one header and no market fee reads for a legacy type-zero estimate', async () => {
    const provider = providerFor();
    const block = jest
      .spyOn(JsonRpcProvider.prototype, 'getBlock')
      .mockResolvedValue({ baseFeePerGas: null });
    try {
      await provider.estimateGas({ from: FROM, to: FROM, type: 0 });
      expect(block).toHaveBeenCalledTimes(1);
      expect(requestsFrom(fetchMock).map((row) => row.method)).toEqual([
        'eth_estimateGas',
      ]);
      expect(requestsFrom(fetchMock)[0].params[0].type).toBeUndefined();
    } finally {
      block.mockRestore();
    }
  });

  it('reuses bounded ordinary fee block evidence for a type-zero estimate', async () => {
    const provider = providerFor();
    fetchMock.mockImplementation(async (_url, init) =>
      response(
        (Array.isArray(JSON.parse(init.body))
          ? JSON.parse(init.body)
          : [JSON.parse(init.body)]
        ).map((request) =>
          resultFor(
            request,
            request.method === 'eth_getBlockByNumber'
              ? { baseFeePerGas: null }
              : '0x2'
          )
        )
      )
    );
    await provider.getFeeData();
    fetchMock
      .mockClear()
      .mockImplementation(async (_url, init) =>
        feeResponse(init.body, (request) => resultFor(request, '0x5208'))
      );
    await provider.estimateGas({ from: FROM, to: FROM, type: 0 });
    expect(requestsFrom(fetchMock).map((request) => request.method)).toEqual([
      'eth_estimateGas',
    ]);
  });

  it('keeps send bound when passed to a caller as a callback', async () => {
    const provider = providerFor();
    const send = provider.send;
    await expect(send('eth_getBalance', [FROM, 'latest'])).resolves.toBe(
      '0x5208'
    );
    await enableBatch(provider, fetchMock);
    await expect(send('eth_getBalance', [FROM, 'latest'])).resolves.toBe(
      '0x5208'
    );
  });

  it('uses the ethers queue for distinct reads across adjacent message turns', async () => {
    fetchMock.mockImplementation(async (_url, init) =>
      feeResponse(init.body, (row) => resultFor(row, row.params[0]))
    );
    const provider = providerFor();
    await enableBatch(provider, fetchMock);
    const first = provider.send('eth_getBalance', ['0x01', 'latest']);
    await new Promise((resolve) => setImmediate(resolve));
    const second = provider.send('eth_getBalance', ['0x02', 'latest']);
    await expect(Promise.all([first, second])).resolves.toEqual([
      '0x01',
      '0x02',
    ]);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(requestsFrom(fetchMock)[0]).toHaveLength(2);
  });

  it('preserves mixed batch results and the original per-item rejection', async () => {
    fetchMock.mockImplementation(async (_url, init) =>
      feeResponse(init.body, (row) =>
        row.params[0] === 'bad'
          ? {
              jsonrpc: '2.0',
              id: row.id,
              error: { code: 3, message: 'reverted', data: '0x1234' },
            }
          : resultFor(row, row.params[0])
      )
    );
    const provider = providerFor();
    await enableBatch(provider, fetchMock);
    const result = await Promise.allSettled(
      ['good', 'bad'].map((value) =>
        provider.send('eth_call', [value, 'latest'])
      )
    );
    expect(result[0]).toEqual({ status: 'fulfilled', value: 'good' });
    expect(result[1]).toMatchObject({
      status: 'rejected',
      reason: {
        name: 'RpcReadError',
        code: 3,
        data: '0x1234',
        message: 'reverted',
      },
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('keeps a large singleton failure isolated inside the ethers queue', async () => {
    const provider = new CustomJsonRpcProvider(
      new AbortController().signal,
      RPC_URL,
      5700,
      { maxResponseBytes: 200 }
    );
    providers.push(provider);
    await enableBatch(provider, fetchMock);
    fetchMock.mockImplementation(async (_url, init) =>
      feeResponse(init.body, (row) =>
        resultFor(row, row.params[0] === 'large' ? 'x'.repeat(300) : 'small')
      )
    );
    const result = await Promise.allSettled(
      ['small', 'large'].map((value) =>
        provider.send('eth_call', [value, 'latest'])
      )
    );
    expect(result[0]).toEqual({ status: 'fulfilled', value: 'small' });
    expect(result[1]).toMatchObject({
      status: 'rejected',
      reason: { code: SENTINEL, retryable: false },
    });
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it.each(['owner', 'destroy'])(
    'rejects a queued read on %s cancellation before dispatch',
    async (mode) => {
      const owner = new AbortController();
      const provider = new CustomJsonRpcProvider(owner.signal, RPC_URL, 5700);
      providers.push(provider);
      const reading = provider.send('eth_getBalance', [FROM, 'latest']);
      const rejected = expect(reading).rejects.toMatchObject({
        name: 'AbortError',
      });
      if (mode === 'destroy') provider.destroy();
      else owner.abort(new DOMException('Owner ended', 'AbortError'));
      await rejected;
      expect(fetchMock).not.toHaveBeenCalled();
    }
  );

  it('keeps writes out of the ordinary read queue', async () => {
    const provider = providerFor();
    await enableBatch(provider, fetchMock);
    fetchMock.mockImplementation(async (_url, init) =>
      feeResponse(init.body, (row) => resultFor(row, row.method))
    );
    const reading = provider.send('eth_getBalance', [FROM, 'latest']);
    const writing = provider.send('eth_sendRawTransaction', ['0x01']);
    await expect(writing).resolves.toBe('eth_sendRawTransaction');
    expect(requestsFrom(fetchMock)).toEqual([
      expect.objectContaining({ method: 'eth_sendRawTransaction' }),
    ]);
    await expect(reading).resolves.toBe('eth_getBalance');
    expect(requestsFrom(fetchMock)).toHaveLength(2);
  });

  it('does not start background network discovery for an unconfigured provider', async () => {
    const provider = providerFor(RPC_URL, null);
    await expect(
      provider.send('eth_getBalance', [FROM, 'latest'])
    ).resolves.toBe('0x5208');
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(requestsFrom(fetchMock).map((row) => row.method)).toEqual([
      'eth_getBalance',
    ]);
  });

  it.each([false, true])(
    'learns cold endpoint batching and expires negative capability (unsupported=%s)',
    async (unsupported) => {
      let now = Date.now();
      const clock = jest.spyOn(Date, 'now').mockImplementation(() => now);
      const provider = providerFor();
      fetchMock.mockImplementation(async (_url, init) => {
        const payload = JSON.parse(init.body);
        if (Array.isArray(payload) && unsupported)
          return response({
            jsonrpc: '2.0',
            id: null,
            error: { code: -32600, message: 'Batch unsupported' },
          });
        return feeResponse(init.body, (row) => resultFor(row, '0x2'));
      });
      const observe = async () => {
        const start = fetchMock.mock.calls.length;
        await Promise.all(
          Array.from({ length: 20 }, () =>
            provider.send('eth_getBalance', [FROM, 'latest'])
          )
        );
        const sent = requestsFrom(fetchMock).slice(start);
        return { methods: sent.flat().length, posts: sent.length };
      };
      try {
        await expect(observe()).resolves.toEqual({
          methods: unsupported ? 40 : 20,
          posts: unsupported ? 21 : 1,
        });
        await expect(observe()).resolves.toEqual({
          methods: 20,
          posts: unsupported ? 20 : 1,
        });
        await provider.readMany([
          { method: 'eth_gasPrice', params: [] },
          { method: 'eth_maxPriorityFeePerGas', params: [] },
        ]);
        await expect(observe()).resolves.toEqual({
          methods: 20,
          posts: unsupported ? 20 : 1,
        });
        now += 30001;
        await expect(observe()).resolves.toEqual({
          methods: unsupported ? 40 : 20,
          posts: unsupported ? 21 : 1,
        });
      } finally {
        clock.mockRestore();
      }
    }
  );

  it.each(['json', 'id'])(
    'does not classify invalid %s responses as batch refusal',
    async (failure) => {
      const provider = providerFor();
      fetchMock.mockImplementation(async (_url, init) =>
        failure === 'json'
          ? new Response('{', {
              headers: { 'content-type': 'application/json' },
            })
          : response(
              JSON.parse(init.body).map((row) => resultFor({ ...row, id: -1 }))
            )
      );
      const result = await provider.readMany([
        { method: 'eth_gasPrice', params: [] },
        { method: 'eth_maxPriorityFeePerGas', params: [] },
      ]);
      expect(result.every((row) => row.status === 'rejected')).toBe(true);
      fetchMock
        .mockReset()
        .mockImplementation(async (_url, init) =>
          feeResponse(init.body, (row) => resultFor(row, '0x2'))
        );
      await Promise.all(
        Array.from({ length: 20 }, () =>
          provider.send('eth_getBalance', [FROM, 'latest'])
        )
      );
      expect(fetchMock).toHaveBeenCalledTimes(1);
      expect(requestsFrom(fetchMock)[0]).toHaveLength(20);
    }
  );

  it('reserves distinct IDs before concurrent requests settle', async () => {
    const deferred: Array<{ request: any; resolve: (value: any) => void }> = [];
    fetchMock.mockImplementation(
      (_url, options) =>
        new Promise((resolve) => {
          deferred.push({ request: JSON.parse(options.body), resolve });
        })
    );
    const provider = providerFor();
    await enableBatch(provider, fetchMock);
    const first = provider.send('eth_call', [{ data: '0x01' }, 'latest']);
    const second = provider.send('eth_call', [{ data: '0x02' }, 'latest']);
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(deferred).toHaveLength(1);
    expect(deferred[0].request).toHaveLength(2);
    expect(deferred[0].request[0].id).not.toBe(deferred[0].request[1].id);
    deferred[0].resolve(
      response(
        deferred[0].request
          .map((request) => resultFor(request, request.params[0].data))
          .reverse()
      )
    );
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
    await enableBatch(provider, fetchMock);
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
    await new Promise((resolve) => setImmediate(resolve));
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
      headers: new Headers(),
      text: async () => '{',
    });
    await expect(
      sdkFor(providerFor()).getTxGasLimit({ data: '0x6000' })
    ).rejects.toMatchObject({ code: SENTINEL });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it.each([
    ['invalid byte', [0xff]],
    ['truncated UTF-8 tail', [0xe2, 0x82]],
  ])(
    'rejects %s as response corruption before legacy gas fallback',
    async (_label, tail) => {
      const cancellations: jest.SpyInstance[] = [];
      fetchMock.mockImplementation(async (_url, init) => {
        const request = JSON.parse(init.body);
        const prefix = new TextEncoder().encode(
          `{"jsonrpc":"2.0","id":${request.id},"result":"`
        );
        const stream = new ReadableStream({
          start(controller) {
            controller.enqueue(prefix);
            controller.enqueue(Uint8Array.from(tail as number[]));
            controller.close();
          },
        });
        const getReader = stream.getReader.bind(stream);
        jest.spyOn(stream, 'getReader').mockImplementation(() => {
          const reader = getReader();
          cancellations.push(jest.spyOn(reader, 'cancel'));
          return reader;
        });
        return new Response(stream, {
          headers: { 'content-type': 'application/json' },
        });
      });
      await expect(
        sdkFor(providerFor()).getTxGasLimit({ data: '0x6000' })
      ).rejects.toMatchObject({ code: SENTINEL });
      expect(fetchMock).toHaveBeenCalledTimes(1);
      expect(requestsFrom(fetchMock)[0].method).toBe('eth_estimateGas');
      expect(cancellations).toHaveLength(1);
      expect(cancellations[0]).toHaveBeenCalledTimes(1);
    }
  );

  it('accepts valid multibyte UTF-8 split across response chunks', async () => {
    fetchMock.mockImplementation(async (_url, init) => {
      const request = JSON.parse(init.body);
      const encoded = new TextEncoder().encode(
        JSON.stringify(resultFor(request, '✓'))
      );
      const offset = encoded.indexOf(0xe2);
      return new Response(
        new ReadableStream({
          start(controller) {
            controller.enqueue(encoded.slice(0, offset + 1));
            controller.enqueue(encoded.slice(offset + 1, offset + 2));
            controller.enqueue(encoded.slice(offset + 2));
            controller.close();
          },
        }),
        { headers: { 'content-type': 'application/json' } }
      );
    });
    await expect(providerFor().send('web3_clientVersion', [])).resolves.toBe(
      '✓'
    );
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it.each(['eth_gasPrice', 'eth_maxPriorityFeePerGas'])(
    'rejects malformed UTF-8 in %s before optional fee fallback or cache publication',
    async (method) => {
      const parentGetBlock = jest
        .spyOn(JsonRpcProvider.prototype, 'getBlock')
        .mockResolvedValue({ baseFeePerGas: 7n });
      const provider = providerFor();
      let corrupt = true;
      fetchMock.mockImplementation(async (_url, init) => {
        const request = JSON.parse(init.body);
        const requests = Array.isArray(request) ? request : [request];
        if (corrupt && requests.some((row) => row.method === method))
          return new Response(
            new ReadableStream({
              start(controller) {
                controller.enqueue(Uint8Array.from([0xff]));
                controller.close();
              },
            }),
            { headers: { 'content-type': 'application/json' } }
          );
        return feeResponse(init.body, (row) => resultFor(row, '0x2'));
      });
      try {
        await expect(provider.getFeeData()).rejects.toMatchObject({
          code: SENTINEL,
        });
        expect(
          requestsFrom(fetchMock)
            .flat()
            .filter((request) => request.method === method)
        ).toHaveLength(1);
        corrupt = false;
        await expect(provider.getFeeData()).resolves.toMatchObject({
          gasPrice: BigNumber.from(2),
          maxPriorityFeePerGas: BigNumber.from(2),
          maxFeePerGas: BigNumber.from(16),
        });
        expect(
          requestsFrom(fetchMock)
            .flat()
            .filter((request) => request.method === method)
        ).toHaveLength(2);
      } finally {
        parentGetBlock.mockRestore();
      }
    }
  );

  it('preserves an aborted response-body read', async () => {
    fetchMock.mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers(),
      text: async () => {
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
      if (
        (Array.isArray(request) ? request : [request]).some(
          (row) => row.method === 'eth_maxPriorityFeePerGas'
        )
      )
        throw new DOMException('Priority fee aborted', 'AbortError');
      return feeResponse(options.body, (row) => resultFor(row, '0x7'));
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
        return feeResponse(options.body, (request) =>
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
      return feeResponse(options.body, (request) =>
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
      expect(fetchMock).toHaveBeenCalledTimes(1);
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

  it('uses an explicit fee reader without reusing or publishing the provider cache', async () => {
    const provider = providerFor();
    const reader = {
      getBlock: jest.fn().mockResolvedValue({ baseFeePerGas: 7n }),
      send: jest.fn(async (method: string) =>
        method === 'eth_gasPrice' ? '0x2' : '0x3'
      ),
    };
    await expect(provider.getFeeData(reader)).resolves.toEqual({
      gasPrice: BigNumber.from(2),
      maxFeePerGas: BigNumber.from(17),
      maxPriorityFeePerGas: BigNumber.from(3),
    });
    reader.getBlock.mockResolvedValue({ baseFeePerGas: 10n });
    await expect(provider.getFeeData(reader)).resolves.toMatchObject({
      maxFeePerGas: BigNumber.from(23),
    });
    expect(reader.getBlock).toHaveBeenCalledTimes(2);
    expect(reader.send).toHaveBeenCalledTimes(4);
    expect(fetchMock).not.toHaveBeenCalled();
    provider.destroy();
    await expect(provider.getFeeData(reader)).rejects.toMatchObject({
      name: 'AbortError',
    });
    expect(reader.send).toHaveBeenCalledTimes(4);
  });

  it('preserves the network plugin when a phase owns its fee reads', async () => {
    const provider = providerFor();
    const reader = {
      getBlock: jest.fn().mockResolvedValue({ baseFeePerGas: 7n }),
      send: jest.fn().mockResolvedValue('0x2'),
    };
    const plugin = {
      url: 'https://fees.example/quote',
      processFunc: jest.fn(async (read, observedProvider, request) => {
        expect(observedProvider).toBe(provider);
        expect(request.url).toBe('https://fees.example/quote');
        const fees = await read();
        return { ...fees, maxFeePerGas: 99n, maxPriorityFeePerGas: 11n };
      }),
    };
    jest.spyOn(provider, 'getNetwork').mockResolvedValue({
      getPlugin: () => plugin,
    });
    await expect(provider.getFeeData(reader)).resolves.toEqual({
      gasPrice: BigNumber.from(2),
      maxFeePerGas: BigNumber.from(99),
      maxPriorityFeePerGas: BigNumber.from(11),
    });
    expect(plugin.processFunc).toHaveBeenCalledTimes(1);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('retires an unfinished host fee reader when the provider is destroyed', async () => {
    const provider = providerFor();
    let release!: (value: string) => void;
    let start!: () => void;
    const started = new Promise<void>((resolve) => {
      start = resolve;
    });
    const held = new Promise<string>((resolve) => {
      release = resolve;
    });
    const reader = {
      getBlock: jest.fn().mockResolvedValue({ baseFeePerGas: 7n }),
      send: jest.fn(async () => {
        start();
        return held;
      }),
    };
    const reading = provider.getFeeData(reader);
    const failed = expect(reading).rejects.toMatchObject({
      name: 'AbortError',
    });
    await started;
    provider.destroy();
    await failed;
    release('0x2');
    await Promise.resolve();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('does not invoke a host fee reader after destruction while resolving the network', async () => {
    const provider = providerFor();
    let release!: (value: unknown) => void;
    const networkReady = new Promise((resolve) => {
      release = resolve;
    });
    jest.spyOn(provider, 'getNetwork').mockReturnValue(networkReady);
    const reader = {
      getBlock: jest.fn().mockResolvedValue({ baseFeePerGas: 7n }),
      send: jest.fn().mockResolvedValue('0x2'),
    };
    const reading = provider.getFeeData(reader);
    const rejected = expect(reading).rejects.toMatchObject({
      name: 'AbortError',
    });
    provider.destroy();
    await rejected;
    release(Network.from(1));
    for (let i = 0; i < 12; i++) await Promise.resolve();
    expect(reader.getBlock).not.toHaveBeenCalled();
    expect(reader.send).not.toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each(['ordinary', 'reader'])(
    'rejects a late Polygon plugin result for the %s fee path without publishing cache',
    async (path) => {
      const parentGetBlock = jest
        .spyOn(JsonRpcProvider.prototype, 'getBlock')
        .mockResolvedValue({ baseFeePerGas: 7n });
      let release!: (value: unknown) => void;
      let started!: () => void;
      const stationStarted = new Promise<void>((resolve) => {
        started = resolve;
      });
      const stationResult = new Promise((resolve) => {
        release = resolve;
      });
      const gasStation = jest
        .spyOn(FetchRequest.prototype, 'send')
        .mockImplementation(() => {
          started();
          return stationResult;
        });
      const provider = providerFor();
      jest.spyOn(provider, 'getNetwork').mockResolvedValue(Network.from(137));
      jest.spyOn(provider, '_perform').mockResolvedValue('0x2');
      const reader = {
        getBlock: jest.fn().mockResolvedValue({ baseFeePerGas: 7n }),
        send: jest.fn().mockResolvedValue('0x2'),
      };
      try {
        const reading = provider.getFeeData(
          path === 'reader' ? reader : undefined
        );
        let settled = false;
        void reading.then(
          () => {
            settled = true;
          },
          () => {
            settled = true;
          }
        );
        const rejected = expect(reading).rejects.toMatchObject({
          name: 'AbortError',
        });
        await stationStarted;
        for (let i = 0; i < 12; i++) await Promise.resolve();
        provider.destroy();
        for (let i = 0; i < 12; i++) await Promise.resolve();
        expect(settled).toBe(true);
        release({ bodyJson: { standard: { maxFee: 3, maxPriorityFee: 1 } } });
        await rejected;
        for (let i = 0; i < 12; i++) await Promise.resolve();
        expect(provider.feeDataCache).toBeNull();
        expect(gasStation).toHaveBeenCalledTimes(1);
      } finally {
        gasStation.mockRestore();
        parentGetBlock.mockRestore();
      }
    }
  );

  it('preserves legacy fallback and integrity errors from the phase fee reader', async () => {
    const provider = providerFor();
    const reader = {
      getBlock: jest.fn().mockResolvedValue({ baseFeePerGas: null }),
      send: jest.fn(async (method: string) => {
        if (method === 'eth_maxPriorityFeePerGas')
          throw new Error('unsupported');
        return '0x2';
      }),
    };
    await expect(provider.getFeeData(reader)).resolves.toEqual({
      gasPrice: BigNumber.from(2),
      maxFeePerGas: null,
      maxPriorityFeePerGas: null,
    });
    const integrity = new RpcResponseIntegrityError(
      'Malformed phase fees',
      false
    );
    reader.send.mockRejectedValue(integrity);
    await expect(provider.getFeeData(reader)).rejects.toBe(integrity);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each(['', true, false, Number.MAX_SAFE_INTEGER + 1, null])(
    'keeps ethers fallback for malformed optional gas price: %p',
    async (value) => {
      const parentGetBlock = jest
        .spyOn(JsonRpcProvider.prototype, 'getBlock')
        .mockResolvedValue({ baseFeePerGas: 7n });
      fetchMock.mockImplementation(async (_url, options) => {
        return feeResponse(options.body, (request) =>
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
        return feeResponse(options.body, (request) =>
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
        return feeResponse(options.body, (request) =>
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
        expect(fetchMock).toHaveBeenCalledTimes(1);
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
        if (
          (Array.isArray(request) ? request : [request]).some(
            (row) => row.method === 'eth_maxPriorityFeePerGas'
          )
        ) {
          if (failure === 'abort')
            throw new DOMException('Fee read cancelled', 'AbortError');
          return response(resultFor({ id: -1 }, '0x2'));
        }
        return feeResponse(options.body, (row) => resultFor(row, '0x7'));
      });
      try {
        await expect(provider.getFeeData()).rejects.toMatchObject(
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

  describe('Polygon fee plugin HTTP ownership', () => {
    const station = 'https://gasstation.polygon.technology/v2';
    const payload = JSON.stringify({
      standard: { maxFee: 3, maxPriorityFee: 1 },
    });
    const setup = (
      options: Record<string, unknown> = {},
      owner = new AbortController()
    ) => {
      const provider = new CustomJsonRpcProvider(
        owner.signal,
        RPC_URL,
        137,
        options
      );
      providers.push(provider);
      jest.spyOn(provider, 'getNetwork').mockResolvedValue(Network.from(137));
      jest.spyOn(provider, '_perform').mockResolvedValue('0x2');
      const block = jest
        .spyOn(JsonRpcProvider.prototype, 'getBlock')
        .mockResolvedValue({ baseFeePerGas: 7n });
      const reader = {
        getBlock: async () => ({ baseFeePerGas: 7n }),
        send: async () => '0x2',
      };
      const originalFees = provider.getFeeData.bind(provider);
      provider.getFeeData = (override?: any) =>
        originalFees(override ?? reader);
      return { provider, owner, block };
    };

    it.each(['owner', 'destroy', 'deadline'])(
      'stops actual HTTP retries after %s cancellation',
      async (kind) => {
        jest.useFakeTimers();
        const { provider, owner, block } = setup({ timeoutMs: 100 });
        fetchMock.mockResolvedValue(
          new Response('', { status: 429, headers: { 'retry-after': '25' } })
        );
        try {
          const reading = provider.getFeeData();
          const rejected = expect(reading).rejects.toMatchObject({
            name: 'AbortError',
          });
          await jest.advanceTimersByTimeAsync(0);
          expect(fetchMock).toHaveBeenCalledTimes(1);
          if (kind === 'owner')
            owner.abort(new DOMException('Owner ended', 'AbortError'));
          if (kind === 'destroy') provider.destroy();
          await jest.advanceTimersByTimeAsync(kind === 'deadline' ? 100 : 0);
          await rejected;
          const attemptsAtCancellation = fetchMock.mock.calls.length;
          await jest.advanceTimersByTimeAsync(1000);
          expect(fetchMock).toHaveBeenCalledTimes(attemptsAtCancellation);
          expect(fetchMock.mock.calls[0][1].signal.aborted).toBe(true);
        } finally {
          block.mockRestore();
          jest.useRealTimers();
        }
      }
    );

    it('preserves a healthy bounded Polygon request and HTTP429 retry', async () => {
      const { provider, block } = setup();
      fetchMock
        .mockResolvedValueOnce(
          new Response('', { status: 429, headers: { 'retry-after': '1' } })
        )
        .mockResolvedValueOnce(
          new Response(payload, {
            headers: { 'content-type': 'application/json' },
          })
        );
      try {
        await expect(provider.getFeeData()).resolves.toEqual({
          gasPrice: BigNumber.from(2),
          maxFeePerGas: BigNumber.from('3000000000'),
          maxPriorityFeePerGas: BigNumber.from('1000000000'),
        });
        expect(fetchMock).toHaveBeenCalledTimes(2);
        expect(
          fetchMock.mock.calls.every(
            ([url, init]) =>
              url === station &&
              init.method === 'GET' &&
              init.redirect === 'manual'
          )
        ).toBe(true);
        expect(fetchMock.mock.calls[0][1].headers['user-agent']).toBe('ethers');
      } finally {
        block.mockRestore();
      }
    });

    it.each(['seconds', 'date'])(
      'honors %s Retry-After before retrying fee HTTP',
      async (kind) => {
        jest.useFakeTimers();
        jest.setSystemTime(new Date('2026-11-15T12:00:00Z'));
        const { provider, block } = setup();
        const retryAfter =
          kind === 'seconds' ? '1' : new Date(Date.now() + 1000).toUTCString();
        fetchMock
          .mockResolvedValueOnce(
            new Response('', {
              status: 429,
              headers: { 'retry-after': retryAfter },
            })
          )
          .mockResolvedValueOnce(
            new Response(payload, {
              headers: { 'content-type': 'application/json' },
            })
          );
        try {
          const reading = provider.getFeeData();
          await jest.advanceTimersByTimeAsync(0);
          expect(fetchMock).toHaveBeenCalledTimes(1);
          await jest.advanceTimersByTimeAsync(999);
          expect(fetchMock).toHaveBeenCalledTimes(1);
          await jest.advanceTimersByTimeAsync(1);
          await expect(reading).resolves.toMatchObject({
            maxFeePerGas: BigNumber.from('3000000000'),
          });
          expect(fetchMock).toHaveBeenCalledTimes(2);
        } finally {
          provider.destroy();
          block.mockRestore();
          jest.useRealTimers();
        }
      }
    );

    it.each(['0', 'invalid', 'Sun, 15 Nov 2020 12:00:00 GMT'])(
      'keeps bounded retry behavior for Retry-After %s',
      async (retryAfter) => {
        jest.useFakeTimers();
        const { provider, block } = setup();
        fetchMock
          .mockResolvedValueOnce(
            new Response('', {
              status: 429,
              headers: { 'retry-after': retryAfter },
            })
          )
          .mockResolvedValueOnce(
            new Response(payload, {
              headers: { 'content-type': 'application/json' },
            })
          );
        try {
          const reading = provider.getFeeData();
          await jest.advanceTimersByTimeAsync(0);
          await jest.advanceTimersByTimeAsync(1000);
          await expect(reading).resolves.toMatchObject({
            maxFeePerGas: BigNumber.from('3000000000'),
          });
          expect(fetchMock).toHaveBeenCalledTimes(2);
        } finally {
          provider.destroy();
          block.mockRestore();
          jest.useRealTimers();
        }
      }
    );

    it.each(['1', '9'.repeat(400)])(
      'does not retry beyond the operation deadline for Retry-After %s',
      async (retryAfter) => {
        jest.useFakeTimers();
        const { provider, block } = setup({ timeoutMs: 50 });
        fetchMock.mockResolvedValue(
          new Response('', {
            status: 429,
            headers: { 'retry-after': retryAfter },
          })
        );
        try {
          const reading = provider.getFeeData();
          const failed = expect(reading).rejects.toMatchObject({
            name: 'AbortError',
          });
          await jest.advanceTimersByTimeAsync(50);
          await failed;
          await jest.advanceTimersByTimeAsync(1000);
          expect(fetchMock).toHaveBeenCalledTimes(1);
        } finally {
          provider.destroy();
          block.mockRestore();
          jest.useRealTimers();
        }
      }
    );

    it('stops fee-plugin retries when its read phase ends while the provider stays alive', async () => {
      jest.useFakeTimers();
      const { provider, block } = setup();
      const phase = new AbortController();
      const reader = {
        signal: phase.signal,
        getBlock: jest.fn().mockResolvedValue({ baseFeePerGas: 7n }),
        send: jest.fn().mockResolvedValue('0x2'),
      };
      fetchMock.mockResolvedValue(
        new Response('', { status: 429, headers: { 'retry-after': '25' } })
      );
      try {
        const reading = provider.getFeeData(reader);
        const rejected = expect(reading).rejects.toMatchObject({
          name: 'AbortError',
        });
        await jest.advanceTimersByTimeAsync(0);
        expect(fetchMock).toHaveBeenCalledTimes(1);
        phase.abort(new DOMException('Read phase expired', 'AbortError'));
        await jest.advanceTimersByTimeAsync(0);
        await rejected;
        await jest.advanceTimersByTimeAsync(100);
        expect(fetchMock).toHaveBeenCalledTimes(1);
        expect(fetchMock.mock.calls[0][1].signal.aborted).toBe(true);
        expect(provider.signal.aborted).toBe(false);
        fetchMock.mockResolvedValue(
          new Response(payload, {
            headers: { 'content-type': 'application/json' },
          })
        );
        const healthy = provider.getFeeData();
        await jest.advanceTimersByTimeAsync(10);
        await expect(healthy).resolves.toMatchObject({
          maxFeePerGas: BigNumber.from('3000000000'),
        });
        expect(fetchMock).toHaveBeenCalledTimes(2);
      } finally {
        phase.abort();
        provider.destroy();
        await jest.runOnlyPendingTimersAsync();
        block.mockRestore();
        jest.useRealTimers();
      }
    });

    it('does not start fee reads for an expired phase or after delayed network discovery', async () => {
      const { provider, block } = setup();
      const phase = new AbortController();
      let release!: (value: unknown) => void;
      const networkReady = new Promise((resolve) => {
        release = resolve;
      });
      jest.spyOn(provider, 'getNetwork').mockReturnValue(networkReady);
      const reader = {
        signal: phase.signal,
        getBlock: jest.fn(),
        send: jest.fn(),
      };
      try {
        const reading = provider.getFeeData(reader);
        const rejected = expect(reading).rejects.toMatchObject({
          name: 'AbortError',
        });
        phase.abort(new DOMException('Read phase expired', 'AbortError'));
        release(Network.from(137));
        await rejected;
        await expect(provider.getFeeData(reader)).rejects.toMatchObject({
          name: 'AbortError',
        });
        expect(reader.send).not.toHaveBeenCalled();
        expect(reader.getBlock).not.toHaveBeenCalled();
        expect(fetchMock).not.toHaveBeenCalled();
        expect(provider.signal.aborted).toBe(false);
      } finally {
        block.mockRestore();
      }
    });

    it.each(['declared', 'stream', 'json', 'utf8', 'content-type', 'http'])(
      'rejects a %s response without retry or fee fallback',
      async (kind) => {
        const { provider, block } = setup({ maxResponseBytes: 100 });
        const cleanup = jest.fn();
        let value: Response;
        if (kind === 'declared')
          value = new Response(payload, {
            headers: { 'content-length': '101' },
          });
        else if (kind === 'stream')
          value = new Response(
            new ReadableStream({
              pull(controller) {
                controller.enqueue(new Uint8Array(101));
              },
              cancel: cleanup,
            })
          );
        else if (kind === 'utf8') value = new Response(new Uint8Array([0xff]));
        else
          value = new Response(kind === 'json' ? '{' : payload, {
            status: kind === 'http' ? 503 : 200,
            headers: {
              'content-type':
                kind === 'content-type' ? 'text/html' : 'application/json',
            },
          });
        fetchMock.mockResolvedValue(value);
        try {
          await expect(provider.getFeeData()).rejects.toMatchObject(
            kind === 'http'
              ? { status: 503 }
              : { code: SENTINEL, retryable: false }
          );
          expect(fetchMock).toHaveBeenCalledTimes(1);
          if (kind === 'stream') expect(cleanup).toHaveBeenCalledTimes(1);
          expect(provider.feeDataCache).toBeNull();
        } finally {
          block.mockRestore();
        }
      }
    );

    it('keeps redirects inside the bounded transport', async () => {
      const { provider, block } = setup({ maxResponseBytes: 100 });
      fetchMock
        .mockResolvedValueOnce(
          new Response('', {
            status: 302,
            headers: { location: 'https://fees.example/redirected' },
          })
        )
        .mockResolvedValueOnce(
          new Response('x'.repeat(101), {
            headers: { 'content-type': 'application/json' },
          })
        );
      try {
        await expect(provider.getFeeData()).rejects.toMatchObject({
          code: SENTINEL,
          retryable: false,
        });
        expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
          station,
          'https://fees.example/redirected',
        ]);
        expect(
          fetchMock.mock.calls.every(([, init]) => init.redirect === 'manual')
        ).toBe(true);
      } finally {
        block.mockRestore();
      }
    });

    it.each([
      'Window',
      'ServiceWorkerGlobalScope',
      'DedicatedWorkerGlobalScope',
    ])(
      'preserves %s browser-managed redirects and validates the final URL',
      async (tag) => {
        const { provider, block } = setup();
        const originalTag = Object.getOwnPropertyDescriptor(
          window,
          Symbol.toStringTag
        );
        Object.defineProperty(window, Symbol.toStringTag, {
          value: tag,
          configurable: true,
        });
        const redirected = new Response(payload, {
          headers: { 'content-type': 'application/json' },
        });
        Object.defineProperty(redirected, 'url', {
          value: 'https://fees.example/final',
        });
        fetchMock.mockResolvedValue(redirected);
        try {
          await expect(provider.getFeeData()).resolves.toMatchObject({
            maxFeePerGas: BigNumber.from('3000000000'),
          });
          expect(fetchMock.mock.calls[0][1].redirect).toBe('follow');
          provider.feeDataCache = null;
          const downgrade = new Response(payload, {
            headers: { 'content-type': 'application/json' },
          });
          Object.defineProperty(downgrade, 'url', {
            value: 'http://fees.example/final',
          });
          fetchMock.mockResolvedValue(downgrade);
          await expect(provider.getFeeData()).rejects.toThrow(
            'unsupported redirect'
          );
        } finally {
          if (originalTag)
            Object.defineProperty(window, Symbol.toStringTag, originalTag);
          else delete window[Symbol.toStringTag];
          block.mockRestore();
        }
      }
    );

    it('preserves a transport failure when a plugin attempts its own fallback', async () => {
      const { provider, block } = setup();
      const plugin = {
        url: station,
        processFunc: async (_read, _provider, request) => {
          try {
            await request.send();
          } catch {
            /* A plugin may offer a fallback. */
          }
          return { gasPrice: 1n, maxFeePerGas: 2n, maxPriorityFeePerGas: 1n };
        },
      };
      jest
        .spyOn(provider, 'getNetwork')
        .mockResolvedValue({ getPlugin: () => plugin });
      fetchMock.mockResolvedValue(
        new Response('{', { headers: { 'content-type': 'application/json' } })
      );
      try {
        await expect(provider.getFeeData()).rejects.toMatchObject({
          code: SENTINEL,
        });
        expect(fetchMock).toHaveBeenCalledTimes(1);
      } finally {
        block.mockRestore();
      }
    });

    it('cancels a noncooperative plugin body without accepting its late result', async () => {
      const { provider, block } = setup();
      let release!: (value: { done: boolean; value?: Uint8Array }) => void;
      let started!: () => void;
      const readingBody = new Promise<void>((resolve) => {
        started = resolve;
      });
      const held = new Promise<{ done: boolean; value?: Uint8Array }>(
        (resolve) => {
          release = resolve;
        }
      );
      const cancel = jest.fn().mockResolvedValue(undefined);
      const unlock = jest.fn();
      fetchMock.mockResolvedValue({
        status: 200,
        statusText: 'OK',
        headers: new Headers({ 'content-type': 'application/json' }),
        body: {
          getReader: () => ({
            read: () => {
              started();
              return held;
            },
            cancel,
            releaseLock: unlock,
          }),
        },
      });
      try {
        const reading = provider.getFeeData();
        const rejected = expect(reading).rejects.toMatchObject({
          name: 'AbortError',
        });
        await readingBody;
        provider.destroy();
        await rejected;
        expect(cancel).toHaveBeenCalledTimes(1);
        release({ done: false, value: new TextEncoder().encode(payload) });
        for (let i = 0; i < 20; i++) await Promise.resolve();
        expect(cancel).toHaveBeenCalledTimes(1);
        expect(unlock).toHaveBeenCalledTimes(1);
        expect(fetchMock).toHaveBeenCalledTimes(1);
        expect(provider.feeDataCache).toBeNull();
      } finally {
        block.mockRestore();
      }
    });

    it('keeps redirect credential and downgrade restrictions', async () => {
      const { provider, block } = setup();
      const polygon = Network.from(137).getPlugin(
        'org.ethers.plugins.network.FetchUrlFeeDataPlugin'
      );
      const plugin = {
        ...polygon,
        url: 'https://fees.example/start',
        processFunc: (read, observed, request) => {
          request.setCredentials('user', 'password');
          return polygon.processFunc(read, observed, request);
        },
      };
      jest
        .spyOn(provider, 'getNetwork')
        .mockResolvedValue({ getPlugin: () => plugin });
      fetchMock
        .mockResolvedValueOnce(
          new Response('', {
            status: 302,
            headers: { location: 'https://other.example/fees' },
          })
        )
        .mockResolvedValueOnce(
          new Response(payload, {
            headers: { 'content-type': 'application/json' },
          })
        );
      try {
        await expect(provider.getFeeData()).resolves.toMatchObject({
          maxFeePerGas: BigNumber.from('3000000000'),
        });
        expect(fetchMock.mock.calls[0][1].headers.authorization).toBeDefined();
        expect(
          fetchMock.mock.calls[1][1].headers.authorization
        ).toBeUndefined();
        provider.feeDataCache = null;
        fetchMock.mockReset().mockResolvedValue(
          new Response('', {
            status: 302,
            headers: { location: 'http://other.example/fees' },
          })
        );
        await expect(provider.getFeeData()).rejects.toThrow(
          'unsupported redirect'
        );
        expect(fetchMock).toHaveBeenCalledTimes(1);
      } finally {
        block.mockRestore();
      }
    });
  });
});
