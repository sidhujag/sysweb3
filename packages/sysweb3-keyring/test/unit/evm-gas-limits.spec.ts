import {
  assertEvmGasLimit,
  bufferedEvmGasLimit,
  EvmGasLimitError,
} from '../../src/evm-fees';

const CAP = 16777216n;
describe('activated EVM transaction gas bounds', () => {
  it.each([1n, 560048n])(
    'bounds activated Ethereum chain %s inclusively',
    (chainId) => {
      expect(assertEvmGasLimit(CAP, chainId, 30000000n)).toBe(CAP);
      expect(() => assertEvmGasLimit(CAP + 1n, chainId, 30000000n)).toThrow(
        EvmGasLimitError
      );
      expect(() =>
        assertEvmGasLimit(bufferedEvmGasLimit(14000000n), chainId, 30000000n)
      ).toThrow(EvmGasLimitError);
    }
  );
  it('applies the activated Sepolia total-gas bound inclusively without confusing execution gas', () => {
    const totalCap = 4294967295n;
    expect(assertEvmGasLimit(totalCap, 11155111n)).toBe(totalCap);
    expect(() => assertEvmGasLimit(totalCap + 1n, 11155111n)).toThrow(
      EvmGasLimitError
    );
    expect(assertEvmGasLimit(bufferedEvmGasLimit(14000000n), 11155111n)).toBe(
      16800000n
    );
  });
  it('keeps the independently sampled block ceiling on Sepolia', () => {
    expect(assertEvmGasLimit(30000000n, 11155111n, 30000000n)).toBe(30000000n);
    expect(() => assertEvmGasLimit(30000001n, 11155111n, 30000000n)).toThrow(
      EvmGasLimitError
    );
  });
  it.each([0n, 10n, 57n, 5700n, 8453n, 42161n, 57057n, 324n, 999999n])(
    'does not infer Ethereum activation on unrelated chain %s',
    (chainId) => {
      expect(assertEvmGasLimit(16800000n, chainId, 30000000n)).toBe(16800000n);
    }
  );
  it('uses a lower sampled block limit and rejects excessive gas on any chain', () => {
    expect(assertEvmGasLimit(10000000n, 1n, 10000000n)).toBe(10000000n);
    expect(() => assertEvmGasLimit(10000001n, 1n, 10000000n)).toThrow(
      EvmGasLimitError
    );
    expect(() => assertEvmGasLimit(31000000n, 5700n, 30000000n)).toThrow(
      EvmGasLimitError
    );
  });
  it('preserves exact bigint arithmetic and allows cap-only validation without a sampled block', () => {
    const large = 2n ** 200n + 1n;
    expect(assertEvmGasLimit(large, 999999n)).toBe(large);
    expect(assertEvmGasLimit(CAP, 1n)).toBe(CAP);
  });
  it.each([null, undefined, 0n, -1n, 1, '21000', 1n << 256n])(
    'rejects invalid gas input %p',
    (gas) => {
      expect(() => assertEvmGasLimit(gas as bigint, 1n)).toThrow(
        'Invalid EVM gas limit'
      );
    }
  );
  it.each([null, undefined, -1n, 1, '1', 1n << 256n])(
    'rejects invalid chain input %p',
    (chainId) => {
      expect(() => assertEvmGasLimit(21000n, chainId as bigint)).toThrow(
        'Invalid EVM gas limit'
      );
    }
  );
  it.each([null, 0n, -1n, 30000000, '30000000', 1n << 256n])(
    'rejects invalid optional block input %p',
    (block) => {
      expect(() => assertEvmGasLimit(21000n, 1n, block as bigint)).toThrow(
        'Invalid EVM gas limit'
      );
    }
  );
});
