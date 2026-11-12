import { utxoFeeRateUnits } from '../../src/utils/utxo-fee-rate';

describe('decimal UTXO fee rate conversion', () => {
  it('preserves every integer atomic rate through the public coin/vbyte API', () => {
    for (let units = 1; units <= 5000; units++)
      expect(utxoFeeRateUnits(units / 1e8)).toBe(units);
  });
  it.each([
    [7e-8, 7],
    [0.00000014, 14],
    [7.01e-8, 8],
    [0.000000001, 1],
    [Number.MIN_VALUE, 1],
    [0.00004999, 4999],
    [1.23456789, 123456789],
    [90071992.5474099, 9007199254740990],
  ])('ceil(%p coins/vbyte) is %p atomic units', (rate, units) => {
    expect(utxoFeeRateUnits(rate)).toBe(units);
  });
  it.each([
    0,
    -1,
    NaN,
    Infinity,
    -Infinity,
    Number.MAX_VALUE,
    90071992.54740992,
    Number.MAX_SAFE_INTEGER / 1e8 + 1,
  ])('rejects invalid or unrepresentable rate %p', (rate) => {
    expect(() => utxoFeeRateUnits(rate)).toThrow('Invalid UTXO fee rate');
  });
});
