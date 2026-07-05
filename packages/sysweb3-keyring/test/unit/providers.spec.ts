import {
  BigNumber,
  JsonRpcProvider,
  normalizeTransactionRequest,
} from '../../src/ethers-v6';

const { CustomJsonRpcProvider, wrapTransactionResponse } = jest.requireActual(
  '../../src/providers'
);

describe('CustomJsonRpcProvider', () => {
  it('wraps read-only transaction response numeric fields without redefining them', async () => {
    const transaction = {
      chainId: 57n,
      hash: '0x1234567890123456789012345678901234567890123456789012345678901234',
      from: '0x0000000000000000000000000000000000000001',
      to: '0x0000000000000000000000000000000000000002',
      nonce: 7,
      blockNumber: 10,
      wait: jest.fn().mockResolvedValue({
        status: 1,
        gasUsed: 21000n,
        cumulativeGasUsed: 42000n,
        gasPrice: 7n,
      }),
    };
    Object.defineProperty(transaction, 'gasLimit', {
      value: 21000n,
      enumerable: true,
      configurable: false,
    });

    const wrapped = wrapTransactionResponse(transaction);

    expect(wrapped.chainId).toBe(57);
    expect(wrapped.gasLimit).toEqual(BigNumber.from(21000));
    expect({ ...wrapped }).toMatchObject({
      chainId: 57,
      hash: transaction.hash,
      from: transaction.from,
      to: transaction.to,
      nonce: transaction.nonce,
      blockNumber: transaction.blockNumber,
    });
    expect(() => JSON.stringify(wrapped)).not.toThrow();

    const receipt = await wrapped.wait();
    expect(receipt.status).toBe(1);
    expect(receipt.gasUsed).toEqual(BigNumber.from(21000));
    expect(receipt.cumulativeGasUsed).toEqual(BigNumber.from(42000));
    expect(receipt.gasPrice).toEqual(BigNumber.from(7));
    expect(() => JSON.stringify(receipt)).not.toThrow();
    expect(transaction.wait).toHaveBeenCalledTimes(1);
  });

  it('normalizes JSON-RPC transaction type values to numbers', () => {
    expect(normalizeTransactionRequest({ type: '0x0' }).type).toBe(0);
    expect(normalizeTransactionRequest({ type: '0x1' }).type).toBe(1);
  });

  it('rejects unsafe numeric transaction values', () => {
    expect(() =>
      normalizeTransactionRequest({
        gasLimit: Number.MAX_SAFE_INTEGER + 1,
      })
    ).toThrow('unsafe numeric transaction value');
    expect(() =>
      normalizeTransactionRequest({
        nonce: Number.MAX_SAFE_INTEGER + 1,
      })
    ).toThrow('unsafe numeric transaction value');
    expect(() =>
      normalizeTransactionRequest({
        type: Number.MAX_SAFE_INTEGER + 1,
      })
    ).toThrow('unsafe numeric transaction value');
  });

  it('populates EIP-1559 fees for zero-base-fee blocks', async () => {
    const parentFeeData = jest
      .spyOn(JsonRpcProvider.prototype, 'getFeeData')
      .mockResolvedValue({
        gasPrice: 7n,
        maxFeePerGas: null,
        maxPriorityFeePerGas: null,
      });
    const parentGetBlock = jest
      .spyOn(JsonRpcProvider.prototype, 'getBlock')
      .mockResolvedValue({ baseFeePerGas: 0n });
    const parentSend = jest
      .spyOn(JsonRpcProvider.prototype, 'send')
      .mockResolvedValue('0x2');
    const provider = new CustomJsonRpcProvider(new AbortController().signal);

    try {
      await expect(provider.getFeeData()).resolves.toEqual({
        gasPrice: BigNumber.from(7),
        maxFeePerGas: BigNumber.from(2),
        maxPriorityFeePerGas: BigNumber.from(2),
      });
    } finally {
      parentFeeData.mockRestore();
      parentGetBlock.mockRestore();
      parentSend.mockRestore();
    }
  });

  it('coalesces concurrent fee data requests and briefly reuses the result', async () => {
    const parentFeeData = jest
      .spyOn(JsonRpcProvider.prototype, 'getFeeData')
      .mockResolvedValue({
        gasPrice: 7n,
        maxFeePerGas: 9n,
        maxPriorityFeePerGas: 2n,
      });
    const provider = new CustomJsonRpcProvider(new AbortController().signal);

    try {
      const [first, second] = await Promise.all([
        provider.getFeeData(),
        provider.getFeeData(),
      ]);
      const third = await provider.getFeeData();

      expect(parentFeeData).toHaveBeenCalledTimes(1);
      expect(first).toEqual({
        gasPrice: BigNumber.from(7),
        maxFeePerGas: BigNumber.from(9),
        maxPriorityFeePerGas: BigNumber.from(2),
      });
      expect(second).toBe(first);
      expect(third).toBe(first);
    } finally {
      parentFeeData.mockRestore();
    }
  });

  it('fetches gas price without running full ethers fee discovery', async () => {
    const parentFeeData = jest
      .spyOn(JsonRpcProvider.prototype, 'getFeeData')
      .mockRejectedValue(new Error('unexpected fee data call'));
    const provider = new CustomJsonRpcProvider(new AbortController().signal);
    const providerSend = jest.spyOn(provider, 'send').mockResolvedValue('0x07');

    try {
      await expect(provider.getGasPrice()).resolves.toEqual(BigNumber.from(7));
      expect(parentFeeData).not.toHaveBeenCalled();
      expect(providerSend).toHaveBeenCalledWith('eth_gasPrice', []);
    } finally {
      parentFeeData.mockRestore();
      providerSend.mockRestore();
    }
  });

  it('forwards block tags for balance requests', async () => {
    const parentGetBalance = jest
      .spyOn(JsonRpcProvider.prototype, 'getBalance')
      .mockResolvedValue(123n);
    const provider = new CustomJsonRpcProvider(new AbortController().signal);
    const address = '0x0000000000000000000000000000000000000001';

    try {
      await expect(provider.getBalance(address, 'pending')).resolves.toEqual(
        BigNumber.from(123)
      );

      expect(parentGetBalance).toHaveBeenCalledWith(address, 'pending');
    } finally {
      parentGetBalance.mockRestore();
    }
  });

  it('forwards block tags for eth_call requests', async () => {
    const parentCall = jest
      .spyOn(JsonRpcProvider.prototype, 'call')
      .mockResolvedValue('0x');
    const provider = new CustomJsonRpcProvider(new AbortController().signal);
    const transaction = {
      to: '0x0000000000000000000000000000000000000001',
      data: '0x',
    };

    try {
      await expect(provider.call(transaction, 'pending')).resolves.toBe('0x');

      expect(parentCall).toHaveBeenCalledWith({
        ...transaction,
        blockTag: 'pending',
      });
    } finally {
      parentCall.mockRestore();
    }
  });
});
