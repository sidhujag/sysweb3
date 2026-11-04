import { getEvmProtocolLimits } from '../src/evm';

describe('shared EVM protocol metadata', () => {
  it.each([1n, 560048n])(
    'exposes the activated Ethereum transaction cap for chain %s',
    (chainId) => {
      expect(getEvmProtocolLimits(chainId)).toEqual({
        maxTransactionGas: '16777216',
      });
    }
  );

  it('uses the activated Sepolia total-gas bound rather than its execution-gas cap', () => {
    expect(getEvmProtocolLimits(11155111n)).toEqual({
      maxTransactionGas: '4294967295',
    });
  });

  it.each([0n, 57n, 5700n, 57057n, 8453n, 42161n, 324n, 2n ** 200n])(
    'does not guess an unconfigured EVM or L2 cap for chain %s',
    (chainId) => {
      expect(getEvmProtocolLimits(chainId)).toEqual({});
    }
  );

  it('prevents a consumer from changing later metadata lookups', () => {
    const known = getEvmProtocolLimits(1n);
    const unknown = getEvmProtocolLimits(57057n);
    expect(Object.isFrozen(known)).toBe(true);
    expect(Object.isFrozen(unknown)).toBe(true);
    expect(Reflect.set(known, 'maxTransactionGas', '1')).toBe(false);
    expect(Reflect.set(unknown, 'maxTransactionGas', '1')).toBe(false);
    expect(Reflect.deleteProperty(known, 'maxTransactionGas')).toBe(false);
    expect(getEvmProtocolLimits(1n).maxTransactionGas).toBe('16777216');
    expect(getEvmProtocolLimits(57057n)).toEqual({});
  });
});
