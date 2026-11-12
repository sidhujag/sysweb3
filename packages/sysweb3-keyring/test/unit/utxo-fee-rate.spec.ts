import { readFileSync } from 'fs';
import { join } from 'path';
import ts from 'typescript';
import { runInNewContext } from 'vm';

import { utxoFeeRateUnits } from '../../src/utils/utxo-fee-rate';

function downlevelConsumer(): typeof utxoFeeRateUnits {
  const source = readFileSync(
    join(__dirname, '../../src/utils/utxo-fee-rate.ts'),
    'utf8'
  );
  const packaged = ts.transpileModule(source, {
    compilerOptions: {
      target: ts.ScriptTarget.ES2020,
      module: ts.ModuleKind.CommonJS,
    },
  }).outputText;
  const consumer = ts.transpileModule(packaged, {
    fileName: 'utxo-fee-rate.js',
    compilerOptions: {
      allowJs: true,
      target: ts.ScriptTarget.ES2015,
      module: ts.ModuleKind.CommonJS,
    },
  }).outputText;
  const exports: { utxoFeeRateUnits?: typeof utxoFeeRateUnits } = {};
  runInNewContext(consumer, { exports });
  if (!exports.utxoFeeRateUnits) throw new Error('Missing fee-rate export');
  return exports.utxoFeeRateUnits;
}

describe.each([
  ['SDK source', utxoFeeRateUnits],
  ['ES2015 consumer of packaged CommonJS', downlevelConsumer()],
] as const)('decimal UTXO fee rate conversion: %s', (_target, convert) => {
  it('preserves every integer atomic rate through the public coin/vbyte API', () => {
    for (let units = 1; units <= 5000; units++)
      expect(convert(units / 1e8)).toBe(units);
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
    expect(convert(rate)).toBe(units);
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
    expect(() => convert(rate)).toThrow('Invalid UTXO fee rate');
  });
});
