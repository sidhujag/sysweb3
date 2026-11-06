import { getAddress } from 'ethers/address';
import { Transaction } from 'ethers/transaction';

import { EVM_CANCELLATION_GAS_LIMIT, parseEvmFeeQuantity } from '../evm-fees';

import type { planEvmCancellationFees } from '../evm-fees';
import type { EvmRetainedCancellationOrigin } from '../types';

/** A host supplies the authenticated original identity and the captured fee plan. */
export type EvmCancellationEnvelopeIntent = Readonly<{
  payer: string;
  chainId: number | string;
  nonce: number | string;
  feePlan: ReturnType<typeof planEvmCancellationFees>;
}>;

const invalid = () => new Error('Invalid EVM cancellation envelope');
const MAX_RETAINED_TRANSACTION_HEX = 32 * 1024 * 1024 + 2;

/** Verify the selected signed bytes and snapshot the host's exact fee floor. */
export function authenticateRetainedCancellation(
  origin: EvmRetainedCancellationOrigin,
  hash: string,
  payer: string,
  chainId: number
): EvmRetainedCancellationOrigin {
  const invalidOrigin = () =>
    new Error('Invalid retained cancellation original');
  try {
    const { kind, rawTransaction, nonce, tipHash, feeFloor } = origin;
    if (
      kind !== 'retained' ||
      typeof rawTransaction !== 'string' ||
      rawTransaction.length > MAX_RETAINED_TRANSACTION_HEX ||
      !Number.isSafeInteger(nonce) ||
      nonce < 0 ||
      typeof tipHash !== 'string' ||
      !/^0x[0-9a-f]{64}$/.test(tipHash)
    )
      throw invalidOrigin();
    const tx = Transaction.from(rawTransaction);
    if (
      !tx.isSigned() ||
      tx.serialized !== rawTransaction ||
      tx.hash !== hash ||
      tx.chainId !== BigInt(chainId) ||
      tx.from?.toLowerCase() !== payer.toLowerCase() ||
      tx.nonce !== nonce ||
      (tx.type !== 0 && tx.type !== 2) ||
      feeFloor.type !== tx.type
    )
      throw invalidOrigin();
    const rate = (value: unknown, signed: bigint | null) => {
      if (typeof value !== 'bigint' || signed === null || value < signed)
        throw invalidOrigin();
      return parseEvmFeeQuantity(value, 'retained cancellation fee floor');
    };
    const fees =
      feeFloor.type === 0
        ? { type: 0 as const, gasPrice: rate(feeFloor.gasPrice, tx.gasPrice) }
        : {
            type: 2 as const,
            maxFeePerGas: rate(feeFloor.maxFeePerGas, tx.maxFeePerGas),
            maxPriorityFeePerGas: rate(
              feeFloor.maxPriorityFeePerGas,
              tx.maxPriorityFeePerGas
            ),
          };
    if (fees.type === 2 && fees.maxPriorityFeePerGas > fees.maxFeePerGas)
      throw invalidOrigin();
    return Object.freeze({
      kind,
      rawTransaction,
      nonce,
      tipHash,
      feeFloor: Object.freeze(fees),
    });
  } catch {
    throw invalidOrigin();
  }
}

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
