import {
  CHAIN_ID_HEX,
  CHAIN_ID_NUMBER,
  RPC_URL,
  VALID_ETH_RPC_RESPONSE,
} from './constants';
import * as networkSdk from '../src';
import {
  clearRpcCaches,
  isValidChainIdForEthNetworks,
  validateChainId,
  validateEvmRpcBatch,
  validateEthRpc,
} from '../src/rpc';
import 'isomorphic-fetch';

describe('rpc tests', () => {
  it('should check if given chain id is a safe integer and it is between 0 and 4503599627370476', () => {
    const isValid = isValidChainIdForEthNetworks(CHAIN_ID_NUMBER);

    expect(isValid).toBe(true);
  });

  it('should validate an ethereum chain id', () => {
    const isValid = validateChainId(CHAIN_ID_NUMBER);

    expect(isValid.valid).toBe(true);
    expect(isValid.hexChainId).toBe(CHAIN_ID_HEX);
  });

  it('should validate given eth rpc', async () => {
    const response = await validateEthRpc(RPC_URL, false);

    expect(response).toStrictEqual(VALID_ETH_RPC_RESPONSE);
  });
});

describe('EVM discovery chain cache', () => {
  const endpoint = 'https://evm-discovery-cache.invalid/';
  beforeEach(() => {
    clearRpcCaches();
  });
  afterEach(() => {
    clearRpcCaches();
    jest.restoreAllMocks();
    jest.useRealTimers();
  });

  it.each([
    [0, 'Invalid RPC URL. Could not get chain ID for network.'],
    ['0x0', 'Invalid RPC URL. Could not get chain ID for network.'],
    ['not-a-chain-id', 'Invalid RPC URL. Could not get chain ID for network.'],
    [undefined, 'Invalid RPC URL. Could not get chain ID for network.'],
    [-1, 'Invalid chain ID for ethereum networks.'],
    [1.5, 'Invalid chain ID for ethereum networks.'],
    [4503599627370477, 'Invalid chain ID for ethereum networks.'],
    [Number.MAX_SAFE_INTEGER + 1, 'Invalid chain ID for ethereum networks.'],
  ])(
    'does not cache rejected discovery result %p before a healthy retry',
    async (result, message) => {
      const read = jest
        .spyOn(globalThis, 'fetch')
        .mockReset()
        .mockResolvedValueOnce(Response.json({ jsonrpc: '2.0', id: 1, result }))
        .mockResolvedValueOnce(
          Response.json({ jsonrpc: '2.0', id: 1, result: '0x1' })
        );
      await expect(validateEthRpc(endpoint, false)).rejects.toThrow(
        String(message)
      );
      await expect(validateEthRpc(endpoint, false)).resolves.toMatchObject({
        chainId: 1,
        valid: true,
      });
      expect(read).toHaveBeenCalledTimes(2);
      await expect(validateEthRpc(endpoint, false)).resolves.toMatchObject({
        chainId: 1,
        valid: true,
      });
      expect(read).toHaveBeenCalledTimes(2);
    }
  );

  it('retains a validated discovery for five minutes and replaces it at expiry', async () => {
    jest.useFakeTimers({ now: 1700000000000 });
    const read = jest
      .spyOn(globalThis, 'fetch')
      .mockReset()
      .mockResolvedValueOnce(
        Response.json({ jsonrpc: '2.0', id: 1, result: '0x1' })
      )
      .mockResolvedValueOnce(
        Response.json({ jsonrpc: '2.0', id: 1, result: '0x2' })
      );
    await expect(validateEthRpc(endpoint, false)).resolves.toMatchObject({
      chainId: 1,
    });
    jest.setSystemTime(1700000000000 + 5 * 60 * 1000 - 1);
    await expect(validateEthRpc(endpoint, false)).resolves.toMatchObject({
      chainId: 1,
    });
    expect(read).toHaveBeenCalledTimes(1);
    jest.setSystemTime(1700000000000 + 5 * 60 * 1000);
    await expect(validateEthRpc(endpoint, false)).resolves.toMatchObject({
      chainId: 2,
    });
    expect(read).toHaveBeenCalledTimes(2);
  });

  it.each(['0x1', '1', 1, 4503599627370476])(
    'preserves accepted discovery representation %p',
    async (result) => {
      jest
        .spyOn(globalThis, 'fetch')
        .mockReset()
        .mockResolvedValueOnce(
          Response.json({ jsonrpc: '2.0', id: 1, result })
        );
      await expect(validateEthRpc(endpoint, false)).resolves.toMatchObject({
        chainId: Number(result),
        valid: true,
      });
    }
  );
});

describe('EVM endpoint latency probe', () => {
  afterEach(() => {
    jest.restoreAllMocks();
    jest.useRealTimers();
  });

  it('samples the existing two-method EVM batch and checks the selected chain', async () => {
    jest.useFakeTimers();
    const read = jest
      .spyOn(globalThis, 'fetch')
      .mockImplementation(async (_url, options) =>
        Response.json(
          JSON.parse(String(options?.body)).map((request: any) => ({
            jsonrpc: '2.0',
            id: request.id,
            result: request.method === 'eth_chainId' ? '0x539' : '0x2',
          }))
        )
      );
    const endpoint = 'https://evm-catalogue-probe.invalid/';
    const result = validateEvmRpcBatch(endpoint, 1337);
    await jest.runAllTimersAsync();
    await expect(result).resolves.toMatchObject({
      success: true,
      chainId: 1337,
    });
    const samples = read.mock.calls.filter(([url]) => url === endpoint);
    expect(samples).toHaveLength(3);
    for (const [, options] of samples) {
      expect(options?.method).toBe('POST');
      expect(JSON.parse(String(options?.body))).toMatchObject([
        { method: 'eth_chainId', id: expect.any(Number) },
        { method: 'eth_blockNumber', id: expect.any(Number) },
      ]);
    }
  });

  it('exposes no status-only UTXO probe through the package entry', () => {
    expect('validateRpcBatchUniversal' in networkSdk).toBe(false);
  });
});
