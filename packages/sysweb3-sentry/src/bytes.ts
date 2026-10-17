import { sha256 } from '@noble/hashes/sha2.js';

export const MAX_TX_BYTES = 100_000;
export const MAX_MONEY = 888_000_000n * 100_000_000n;

export class SentryValidationError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = 'SentryValidationError';
    this.code = code;
  }
}

export function fail(code: string, message: string): never {
  throw new SentryValidationError(code, message);
}

export function fromHex(
  value: unknown,
  name = 'hex',
  length?: number
): Uint8Array {
  if (
    typeof value !== 'string' ||
    value.length % 2 !== 0 ||
    !/^[0-9a-f]*$/i.test(value) ||
    value.length > MAX_TX_BYTES * 2 ||
    (length !== undefined && value.length !== length * 2)
  ) {
    fail(
      'INVALID_HEX',
      `${name} must be canonical byte hex${
        length === undefined ? '' : ` (${length} bytes)`
      }`
    );
  }
  const out = new Uint8Array(value.length / 2);
  for (let i = 0; i < out.length; i++)
    out[i] = parseInt(value.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function hex(bytes: Uint8Array): string {
  let result = '';
  for (const value of bytes) result += value.toString(16).padStart(2, '0');
  return result;
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(
    parts.reduce((size, part) => size + part.length, 0)
  );
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function nonzero(bytes: Uint8Array): boolean {
  return bytes.some((value) => value !== 0);
}
export function hash256(bytes: Uint8Array): Uint8Array {
  return sha256(sha256(bytes));
}
export function displayHash(bytes: Uint8Array): string {
  return hex(bytes.slice().reverse());
}
export function hashBytes(value: unknown, name = 'hash'): Uint8Array {
  const bytes = fromHex(value, name, 32);
  if (!nonzero(bytes)) fail('INVALID_HASH', `${name} cannot be zero`);
  return bytes.reverse();
}

export function uint(value: unknown, bits: 8 | 16 | 32, name: string): number {
  if (
    typeof value !== 'number' ||
    !Number.isSafeInteger(value) ||
    value < 0 ||
    value > 2 ** bits - 1
  ) {
    fail('INVALID_INTEGER', `${name} must be an unsigned ${bits}-bit integer`);
  }
  return value;
}

export function integerBytes(
  value: number | bigint,
  size: number,
  bigEndian = false
): Uint8Array {
  let remaining = BigInt(value);
  if (remaining < 0n || remaining >= 1n << BigInt(size * 8))
    fail('INVALID_INTEGER', 'Integer out of range');
  const out = new Uint8Array(size);
  for (let i = 0; i < size; i++) {
    out[i] = Number(remaining & 255n);
    remaining >>= 8n;
  }
  return bigEndian ? out.reverse() : out;
}

export function compactSize(size: number): Uint8Array {
  uint(size, 32, 'CompactSize');
  if (size < 253) return Uint8Array.of(size);
  if (size <= 65535) return concat(Uint8Array.of(253), integerBytes(size, 2));
  return concat(Uint8Array.of(254), integerBytes(size, 4));
}

export function vector(bytes: Uint8Array): Uint8Array {
  return concat(compactSize(bytes.length), bytes);
}

export function amount(value: unknown, name: string): bigint {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,16})$/.test(value))
    fail('INVALID_AMOUNT', `${name} must be integer satoshis`);
  const result = BigInt(value);
  if (result > MAX_MONEY) fail('INVALID_AMOUNT', `${name} exceeds MAX_MONEY`);
  return result;
}

export function object(
  value: unknown,
  keys: readonly string[],
  name: string
): Record<string, unknown> {
  if (
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    (Object.getPrototypeOf(value) !== Object.prototype &&
      Object.getPrototypeOf(value) !== null)
  ) {
    fail('INVALID_REQUEST', `${name} must be a plain object`);
  }
  const result = value as Record<string, unknown>;
  for (const key of Object.keys(result))
    if (!keys.includes(key))
      fail('INVALID_REQUEST', `Unsupported ${name} field: ${key}`);
  return result;
}

export class Reader {
  offset = 0;
  constructor(readonly bytes: Uint8Array) {}
  read(size: number): Uint8Array {
    if (
      !Number.isSafeInteger(size) ||
      size < 0 ||
      size > this.bytes.length - this.offset
    )
      fail('TRUNCATED', 'Truncated serialization');
    const out = this.bytes.slice(this.offset, this.offset + size);
    this.offset += size;
    return out;
  }
  integer(size: number, bigEndian = false): bigint {
    const bytes = this.read(size);
    let value = 0n;
    for (const byte of bigEndian ? bytes : bytes.reverse())
      value = (value << 8n) | BigInt(byte);
    return value;
  }
  number(size: number, bigEndian = false): number {
    const value = this.integer(size, bigEndian);
    if (value > BigInt(Number.MAX_SAFE_INTEGER))
      fail('INVALID_INTEGER', 'Integer too large');
    return Number(value);
  }
  size(limit: number): number {
    const prefix = this.number(1);
    const value =
      prefix < 253
        ? prefix
        : this.number(prefix === 253 ? 2 : prefix === 254 ? 4 : 8);
    if (
      (prefix === 253 && value < 253) ||
      (prefix === 254 && value <= 65535) ||
      (prefix === 255 && value <= 0xffffffff)
    )
      fail('NON_CANONICAL', 'Non-canonical CompactSize');
    if (value > limit) fail('LIMIT', 'Serialization exceeds bounded size');
    return value;
  }
  vector(limit: number): Uint8Array {
    return this.read(this.size(limit));
  }
  end(): void {
    if (this.offset !== this.bytes.length)
      fail('TRAILING_DATA', 'Unexpected trailing bytes');
  }
}
