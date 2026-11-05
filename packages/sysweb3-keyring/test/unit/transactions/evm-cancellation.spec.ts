import { Transaction } from 'ethers/transaction';
import { Wallet } from 'ethers/wallet';

import { planEvmCancellationFees } from '../../../src/evm-fees';
import { assertEvmCancellationEnvelope } from '../../../src/transactions/evm-cancellation';

const wallet = new Wallet(`0x${'11'.repeat(32)}`);
const other = `0x${'33'.repeat(20)}`;
const feePlan = planEvmCancellationFees({
  type: 2,
  currentMaxFeePerGas: 100n,
  currentMaxPriorityFeePerGas: 10n,
});
const legacyPlan = planEvmCancellationFees({ type: 0, currentGasPrice: 100n });
const intent = { payer: wallet.address, chainId: '5700', nonce: '0', feePlan };
const envelope = {
  type: 2,
  to: wallet.address,
  chainId: 5700,
  nonce: 0,
  value: 0n,
  gasLimit: feePlan.gasLimit,
  data: '0x',
  maxFeePerGas: feePlan.type === 2 ? feePlan.maxFeePerGas : 0n,
  maxPriorityFeePerGas: feePlan.type === 2 ? feePlan.maxPriorityFeePerGas : 0n,
};
const bytes = Transaction.from(envelope).unsignedSerialized;
const invalid = 'Invalid EVM cancellation envelope';

it('accepts exact planner envelopes for both supported types including nonce zero', () => {
  expect(() => assertEvmCancellationEnvelope(bytes, intent)).not.toThrow();
  const legacy = Transaction.from({
    type: 0,
    chainId: 5700,
    to: wallet.address,
    nonce: 0,
    value: 0,
    data: '0x',
    gasLimit: legacyPlan.gasLimit,
    gasPrice: legacyPlan.type === 0 ? legacyPlan.gasPrice : 0n,
  });
  expect(() =>
    assertEvmCancellationEnvelope(legacy.unsignedSerialized, {
      ...intent,
      feePlan: legacyPlan,
    })
  ).not.toThrow();
});

it.each([
  ['recipient', { to: other }],
  ['creation', { to: null }],
  ['nonce', { nonce: 91 }],
  ['chain', { chainId: 1 }],
  ['data', { data: '0x01' }],
  ['value', { value: 1n }],
  ['gas', { gasLimit: 42001n }],
  ['fee cap', { maxFeePerGas: 121n }],
  ['tip', { maxPriorityFeePerGas: 13n }],
  ['access list', { accessList: [{ address: other, storageKeys: [] }] }],
])('rejects changed %s', (_name, field) => {
  const actual = Transaction.from({ ...envelope, ...field }).unsignedSerialized;
  expect(() => assertEvmCancellationEnvelope(actual, intent)).toThrow(invalid);
});

it('rejects signatures, unplanned fee totals and another transaction type', () => {
  const signed = Transaction.from(bytes);
  signed.signature = wallet.signingKey.sign(signed.unsignedHash);
  expect(() =>
    assertEvmCancellationEnvelope(signed.serialized, intent)
  ).toThrow(invalid);
  expect(() =>
    assertEvmCancellationEnvelope(bytes, {
      ...intent,
      feePlan: { ...feePlan, maximumFee: 0n },
    })
  ).toThrow(invalid);
  const accessList = Transaction.from({
    type: 1,
    chainId: 5700,
    to: wallet.address,
    nonce: 0,
    gasLimit: 42000n,
    gasPrice: 120n,
    accessList: [],
  });
  expect(() =>
    assertEvmCancellationEnvelope(accessList.unsignedSerialized, intent)
  ).toThrow(invalid);
});
