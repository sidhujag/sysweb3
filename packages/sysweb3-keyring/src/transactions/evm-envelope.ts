import { getAddress } from 'ethers/address';
import { Transaction } from 'ethers/transaction';

import { assertEvmGasLimit } from '../evm-fees';

export type EvmAccessList = readonly Readonly<{
  address: string;
  storageKeys: readonly string[];
}>[];

/**
 * Fully specified type-0/type-2 transaction. Quantities are canonical decimal
 * integer strings, nonce is at most MAX_SAFE_INTEGER, and gasLimit is uint64.
 * The sender is a nonzero hex address. A null destination creates a contract.
 * Data is even-length 0x hex, at most 512 KiB. Type 2 requires an access list.
 */
export type PreparedEvmTransaction = Readonly<
  {
    from: string;
    to: string | null;
    chainId: string;
    nonce: string;
    value: string;
    gasLimit: string;
    data: string;
  } & (
    | { type: 0; gasPrice: string }
    | {
        type: 2;
        maxFeePerGas: string;
        maxPriorityFeePerGas: string;
        accessList: EvmAccessList;
      }
  )
>;

const UINT256 = (1n << 256n) - 1n;
const UINT64 = (1n << 64n) - 1n;
// A 1 MiB JSON RPC request can contain less than 512 KiB of hex calldata.
const MAX_DATA_BYTES = 512 * 1024;
const MAX_ACCESS_LIST_ITEMS = 10_000;
const invalid = () => new TypeError('Invalid prepared EVM signing request');

/** Snapshot values without invoking accessors or accepting hidden fields. */
/** @internal Strict own-data snapshot shared with prepared request binding. */
export function readEvmOwnData(
  value: unknown,
  keys: readonly string[]
): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw invalid();
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw invalid();
  const names = Reflect.ownKeys(value);
  if (
    names.length !== keys.length ||
    names.some((key) => typeof key !== 'string' || !keys.includes(key))
  )
    throw invalid();
  const result: Record<string, unknown> = Object.create(null);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      !descriptor ||
      !descriptor.enumerable ||
      !Object.prototype.hasOwnProperty.call(descriptor, 'value')
    )
      throw invalid();
    result[key] = descriptor.value;
  }
  return result;
}

function quantity(value: unknown, maximum = UINT256, positive = false): string {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,77})$/.test(value))
    throw invalid();
  const parsed = BigInt(value);
  if (parsed > maximum || (positive && parsed === 0n)) throw invalid();
  return value;
}

function address(value: unknown): string {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(value))
    throw invalid();
  let canonical: string;
  try {
    canonical = getAddress(value);
  } catch {
    throw invalid();
  }
  return canonical;
}

function sender(value: unknown): string {
  const canonical = address(value);
  if (/^0x0{40}$/i.test(canonical)) throw invalid();
  return canonical;
}

function arrayData(value: unknown, maximum: number): unknown[] {
  if (
    !Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Array.prototype ||
    value.length > maximum ||
    Reflect.ownKeys(value).length !== value.length + 1
  )
    throw invalid();
  const values: unknown[] = [];
  for (let index = 0; index < value.length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(value, index);
    if (!descriptor?.enumerable || !('value' in descriptor)) throw invalid();
    values.push(descriptor.value);
  }
  return values;
}

/** Copy bounded own data while preserving the signed order and duplicates. */
export function snapshotEvmAccessList(value: unknown): EvmAccessList {
  const entries = arrayData(value, MAX_ACCESS_LIST_ITEMS);
  let remaining = MAX_ACCESS_LIST_ITEMS - entries.length;
  return Object.freeze(
    entries.map((entry) => {
      const fields = readEvmOwnData(entry, ['address', 'storageKeys']);
      const keys = arrayData(fields.storageKeys, remaining);
      remaining -= keys.length;
      const storageKeys = keys.map((key) => {
        if (typeof key !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(key))
          throw invalid();
        return key.toLowerCase();
      });
      return Object.freeze({
        address: address(fields.address),
        storageKeys: Object.freeze(storageKeys),
      });
    })
  );
}

export function snapshotPreparedEvmTransaction(
  input: unknown
): PreparedEvmTransaction {
  // Read the discriminator from a data property before choosing the exact schema.
  if (!input || typeof input !== 'object') throw invalid();
  const typeDescriptor = Object.getOwnPropertyDescriptor(input, 'type');
  if (
    !typeDescriptor ||
    !Object.prototype.hasOwnProperty.call(typeDescriptor, 'value')
  )
    throw invalid();
  const type = typeDescriptor.value;
  if (type !== 0 && type !== 2) throw invalid();
  const fields = [
    'type',
    'from',
    'to',
    'chainId',
    'nonce',
    'value',
    'gasLimit',
    'data',
  ];
  const transaction = readEvmOwnData(
    input,
    type === 0
      ? [...fields, 'gasPrice']
      : [...fields, 'maxFeePerGas', 'maxPriorityFeePerGas', 'accessList']
  );
  const from = sender(transaction.from);
  const chainId = quantity(transaction.chainId, UINT256, true);
  if (
    typeof transaction.data !== 'string' ||
    transaction.data.length > 2 + 2 * MAX_DATA_BYTES ||
    !/^0x(?:[0-9a-fA-F]{2})*$/.test(transaction.data)
  )
    throw invalid();
  const common = {
    from,
    to: transaction.to === null ? null : address(transaction.to),
    chainId,
    nonce: quantity(transaction.nonce, BigInt(Number.MAX_SAFE_INTEGER)),
    value: quantity(transaction.value),
    gasLimit: quantity(transaction.gasLimit, UINT64, true),
    data: transaction.data.toLowerCase(),
  };
  assertEvmGasLimit(BigInt(common.gasLimit), BigInt(chainId));
  const fees =
    type === 0
      ? { type: 0 as const, gasPrice: quantity(transaction.gasPrice) }
      : {
          type: 2 as const,
          maxFeePerGas: quantity(transaction.maxFeePerGas),
          maxPriorityFeePerGas: quantity(transaction.maxPriorityFeePerGas),
          accessList: snapshotEvmAccessList(transaction.accessList),
        };
  if (
    fees.type === 2 &&
    BigInt(fees.maxPriorityFeePerGas) > BigInt(fees.maxFeePerGas)
  )
    throw invalid();
  const maximumFee =
    BigInt(common.gasLimit) *
    BigInt(fees.type === 0 ? fees.gasPrice : fees.maxFeePerGas);
  if (maximumFee + BigInt(common.value) > UINT256) throw invalid();
  return Object.freeze({ ...common, ...fees });
}

/** @internal The same validated fields feed unsigned serialization and signing. */
export function prepareUnsignedEvmEnvelope(input: PreparedEvmTransaction) {
  const transaction = snapshotPreparedEvmTransaction(input);
  const unsigned = {
    type: transaction.type,
    to: transaction.to,
    chainId: BigInt(transaction.chainId),
    nonce: Number(transaction.nonce),
    value: BigInt(transaction.value),
    gasLimit: BigInt(transaction.gasLimit),
    data: transaction.data,
    ...(transaction.type === 0
      ? { gasPrice: BigInt(transaction.gasPrice) }
      : {
          maxFeePerGas: BigInt(transaction.maxFeePerGas),
          maxPriorityFeePerGas: BigInt(transaction.maxPriorityFeePerGas),
          accessList: transaction.accessList.map((entry) => ({
            address: entry.address,
            storageKeys: [...entry.storageKeys],
          })),
        }),
  };
  const expectedUnsigned = Transaction.from(unsigned).unsignedSerialized;
  return { transaction, unsigned, expectedUnsigned };
}

/** Validate and serialize the exact envelope used by prepared signing. */
export function serializePreparedEvmTransaction(
  transaction: PreparedEvmTransaction
): string {
  return prepareUnsignedEvmEnvelope(transaction).expectedUnsigned;
}
