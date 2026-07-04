import {
  Contract as EthersContract,
  JsonRpcProvider,
  Transaction,
  getAddress,
  dataSlice,
  hexlify,
  isHexString,
  parseEther as ethersParseEther,
  parseUnits as ethersParseUnits,
  formatEther as formatEtherBase,
  formatUnits as formatUnitsBase,
  keccak256,
  Signature,
  type BytesLike,
  type Networkish,
} from 'ethers';

export {
  JsonRpcProvider,
  getAddress,
  dataSlice,
  hexlify,
  isHexString,
  keccak256,
  type BytesLike,
  type Networkish,
};

export type TransactionRequest = Record<string, any>;
export type TransactionResponse = any;
export const Contract: any = EthersContract;

export type BigNumberish =
  | bigint
  | number
  | string
  | BigNumberCompat
  | { _hex?: string; hex?: string; toString?: () => string };

export type Deferrable<T> = {
  [K in keyof T]: T[K] | Promise<T[K]>;
};

const strip0x = (value: string) =>
  value.startsWith('0x') || value.startsWith('0X') ? value.slice(2) : value;

const toBigIntValue = (value: BigNumberish | null | undefined): bigint => {
  if (value == null) return 0n;
  if (value instanceof BigNumberCompat) return value.value;
  if (typeof value === 'bigint') return value;
  if (typeof value === 'number') return BigInt(Math.trunc(value));
  if (typeof value === 'string') {
    if (value === '') return 0n;
    return BigInt(value);
  }

  const hex = value._hex ?? value.hex;
  if (hex) return BigInt(hex);

  if (value.toString) return BigInt(value.toString());
  return 0n;
};

export class BigNumberCompat {
  readonly _isBigNumber = true;
  readonly value: bigint;

  private constructor(value: BigNumberish | null | undefined) {
    this.value = toBigIntValue(value);
  }

  static from(value: BigNumberish | null | undefined) {
    return new BigNumberCompat(value);
  }

  static isBigNumber(value: unknown): value is BigNumberCompat {
    return (
      value instanceof BigNumberCompat || Boolean((value as any)?._isBigNumber)
    );
  }

  get _hex() {
    return this.toHexString();
  }

  get hex() {
    return this.toHexString();
  }

  add(value: BigNumberish) {
    return BigNumberCompat.from(this.value + toBigIntValue(value));
  }

  sub(value: BigNumberish) {
    return BigNumberCompat.from(this.value - toBigIntValue(value));
  }

  mul(value: BigNumberish) {
    return BigNumberCompat.from(this.value * toBigIntValue(value));
  }

  div(value: BigNumberish) {
    return BigNumberCompat.from(this.value / toBigIntValue(value));
  }

  eq(value: BigNumberish) {
    return this.value === toBigIntValue(value);
  }

  lt(value: BigNumberish) {
    return this.value < toBigIntValue(value);
  }

  gt(value: BigNumberish) {
    return this.value > toBigIntValue(value);
  }

  isZero() {
    return this.value === 0n;
  }

  isNegative() {
    return this.value < 0n;
  }

  toBigInt() {
    return this.value;
  }

  toNumber() {
    return Number(this.value);
  }

  toHexString() {
    const sign = this.value < 0n ? '-' : '';
    const abs = this.value < 0n ? -this.value : this.value;
    const hex = abs.toString(16);
    return `${sign}0x${hex.length % 2 ? `0${hex}` : hex}`;
  }

  toString() {
    return this.value.toString();
  }
}

export { BigNumberCompat as BigNumber };
export const Zero = BigNumberCompat.from(0);

export const parseUnits = (value: string, unit?: string | number) =>
  BigNumberCompat.from(ethersParseUnits(value, unit));

export const parseEther = (value: string) =>
  BigNumberCompat.from(ethersParseEther(value));

export const formatUnits = (value: BigNumberish, unit?: string | number) =>
  formatUnitsBase(toBigIntValue(value), unit);

export const formatEther = (value: BigNumberish) =>
  formatEtherBase(toBigIntValue(value));

export const resolveProperties = async <T extends Record<string, any>>(
  value: Deferrable<T>
): Promise<T> => {
  const entries = await Promise.all(
    Object.entries(value).map(async ([key, entry]) => [key, await entry])
  );
  return Object.fromEntries(entries) as T;
};

export const shallowCopy = <T extends Record<string, any>>(value: T): T => ({
  ...value,
});

export const toQuantityHex = (value: BigNumberish) =>
  BigNumberCompat.from(value).toHexString();

export const normalizeTxValue = (value: any): any => {
  if (value == null) return value;
  if (value instanceof BigNumberCompat) return value.toBigInt();
  if (typeof value === 'bigint') return value;
  if (typeof value === 'number') return BigInt(Math.trunc(value));
  if (typeof value === 'string') {
    if (value === '') return 0n;
    return value.startsWith('0x') || value.startsWith('0X')
      ? BigInt(value)
      : BigInt(value);
  }
  const hex = value._hex ?? value.hex;
  if (hex) return BigInt(hex);
  return value;
};

export const normalizeTransactionRequest = (tx: Record<string, any>) => {
  const normalized = { ...tx };
  for (const field of [
    'chainId',
    'gasLimit',
    'gasPrice',
    'maxFeePerGas',
    'maxPriorityFeePerGas',
    'nonce',
    'value',
  ]) {
    if (normalized[field] != null)
      normalized[field] = normalizeTxValue(normalized[field]);
  }
  return normalized;
};

export const serializeTransaction = (
  tx: Record<string, any>,
  signature?: { r: string; s: string; v?: number; recoveryParam?: number }
) => {
  if (tx.type === 0 && tx.accessList != null) {
    throw new Error('legacy transactions do not support accessList');
  }

  const txForSerialization = { ...tx };
  if (
    txForSerialization.type == null &&
    txForSerialization.accessList != null &&
    txForSerialization.maxFeePerGas == null &&
    txForSerialization.maxPriorityFeePerGas == null
  ) {
    txForSerialization.type = 1;
  }

  if (
    txForSerialization.type === 2 &&
    txForSerialization.gasPrice != null &&
    txForSerialization.maxFeePerGas != null
  ) {
    const gasPrice = normalizeTxValue(txForSerialization.gasPrice);
    const maxFeePerGas = normalizeTxValue(txForSerialization.maxFeePerGas);
    if (gasPrice !== maxFeePerGas) {
      throw new Error('mismatch EIP-1559 gasPrice != maxFeePerGas');
    }
  }

  const transaction = Transaction.from(
    normalizeTransactionRequest(txForSerialization)
  );
  if (!signature) return transaction.unsignedSerialized;

  transaction.signature = Signature.from(
    signature.v != null
      ? {
          r: signature.r,
          s: signature.s,
          v: signature.v,
        }
      : {
          r: signature.r,
          s: signature.s,
          yParity: (signature.recoveryParam ?? 0) as 0 | 1,
        }
  );
  return transaction.serialized;
};

export const arrayify = (value: BytesLike) =>
  Buffer.from(strip0x(hexlify(value)), 'hex');

export const hexZeroPad = (value: BytesLike, length: number) => {
  const hex = strip0x(hexlify(value));
  return `0x${hex.padStart(length * 2, '0')}`;
};

export const joinSignature = (signature: {
  r: string;
  s: string;
  v?: number;
  recoveryParam?: number;
}) =>
  Signature.from(
    signature.v != null
      ? {
          r: signature.r,
          s: signature.s,
          v: signature.v,
        }
      : {
          r: signature.r,
          s: signature.s,
          yParity: (signature.recoveryParam ?? 0) as 0 | 1,
        }
  ).serialized;
