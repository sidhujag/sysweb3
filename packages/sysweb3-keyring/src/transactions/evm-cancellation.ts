import { getAddress } from 'ethers/address';
import { Transaction } from 'ethers/transaction';

import { EVM_CANCELLATION_GAS_LIMIT, parseEvmFeeQuantity } from '../evm-fees';

import type { planEvmCancellationFees } from '../evm-fees';

/** A host supplies the authenticated original identity and the captured fee plan. */
export type EvmCancellationEnvelopeIntent = Readonly<{
  payer: string;
  chainId: number | string;
  nonce: number | string;
  feePlan: ReturnType<typeof planEvmCancellationFees>;
}>;

const invalid = () => new Error('Invalid EVM cancellation envelope');

/** Checks the exact unsigned bytes. Original eligibility and approval remain host checks. */
export function assertEvmCancellationEnvelope(
  unsigned: string,
  { payer, chainId, nonce, feePlan }: EvmCancellationEnvelopeIntent
): void {
  // A type-0/type-2 empty self-transfer fits within this bound at wire maxima.
  if (typeof unsigned !== 'string' || unsigned.length > 512) throw invalid();
  let tx: Transaction;
  try {
    tx = Transaction.from(unsigned);
  } catch {
    throw invalid();
  }
  if (
    tx.isSigned() ||
    (tx.type !== 0 && tx.type !== 2) ||
    tx.type !== feePlan.type ||
    tx.unsignedSerialized !== unsigned ||
    tx.chainId !== parseEvmFeeQuantity(chainId, 'cancellation chain ID') ||
    BigInt(tx.nonce) !== parseEvmFeeQuantity(nonce, 'cancellation nonce') ||
    tx.to !== getAddress(payer) ||
    tx.value !== 0n ||
    tx.data !== '0x' ||
    tx.accessList?.length ||
    tx.gasLimit !== EVM_CANCELLATION_GAS_LIMIT ||
    tx.gasLimit !== feePlan.gasLimit
  )
    throw invalid();

  const cap = feePlan.type === 0 ? tx.gasPrice : tx.maxFeePerGas;
  if (
    cap === null ||
    cap <= 0n ||
    tx.gasLimit * cap !== feePlan.maximumFee ||
    (feePlan.type === 0
      ? cap !== feePlan.gasPrice
      : cap !== feePlan.maxFeePerGas ||
        tx.maxPriorityFeePerGas !== feePlan.maxPriorityFeePerGas)
  )
    throw invalid();
}
