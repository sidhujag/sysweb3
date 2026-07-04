import { BigNumber } from '../../src/ethers-v6';

const { wrapTransactionResponse } = jest.requireActual('../../src/providers');

describe('CustomJsonRpcProvider', () => {
  it('wraps read-only transaction response numeric fields without redefining them', async () => {
    const transaction = {
      hash: '0x1234567890123456789012345678901234567890123456789012345678901234',
      wait: jest.fn().mockResolvedValue({ status: 1 }),
    };
    Object.defineProperty(transaction, 'gasLimit', {
      value: 21000n,
      enumerable: true,
      configurable: false,
    });

    const wrapped = wrapTransactionResponse(transaction);

    expect(wrapped.gasLimit).toEqual(BigNumber.from(21000));
    await expect(wrapped.wait()).resolves.toEqual({ status: 1 });
    expect(transaction.wait).toHaveBeenCalledTimes(1);
  });
});
