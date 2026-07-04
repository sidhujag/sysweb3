import { BigNumber, normalizeTransactionRequest } from '../../src/ethers-v6';

const { wrapTransactionResponse } = jest.requireActual('../../src/providers');

describe('CustomJsonRpcProvider', () => {
  it('wraps read-only transaction response numeric fields without redefining them', async () => {
    const transaction = {
      hash: '0x1234567890123456789012345678901234567890123456789012345678901234',
      from: '0x0000000000000000000000000000000000000001',
      to: '0x0000000000000000000000000000000000000002',
      nonce: 7,
      blockNumber: 10,
      wait: jest.fn().mockResolvedValue({ status: 1 }),
    };
    Object.defineProperty(transaction, 'gasLimit', {
      value: 21000n,
      enumerable: true,
      configurable: false,
    });

    const wrapped = wrapTransactionResponse(transaction);

    expect(wrapped.gasLimit).toEqual(BigNumber.from(21000));
    expect({ ...wrapped }).toMatchObject({
      hash: transaction.hash,
      from: transaction.from,
      to: transaction.to,
      nonce: transaction.nonce,
      blockNumber: transaction.blockNumber,
    });
    await expect(wrapped.wait()).resolves.toEqual({ status: 1 });
    expect(transaction.wait).toHaveBeenCalledTimes(1);
  });

  it('normalizes JSON-RPC transaction type values to numbers', () => {
    expect(normalizeTransactionRequest({ type: '0x0' }).type).toBe(0);
    expect(normalizeTransactionRequest({ type: '0x1' }).type).toBe(1);
  });
});
