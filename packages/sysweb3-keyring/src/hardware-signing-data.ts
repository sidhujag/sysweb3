const MAX_SIGNING_NODES = 16384;
const MAX_SIGNING_BYTES = 1024 * 1024;
const MAX_INTEGER_MAGNITUDE = 1n << 256n;

/** Own a bounded signing payload before initialization or platform code can await. */
export function captureHardwareSigningData(
  value: unknown,
  invalid: () => Error
): any {
  const seen = new WeakSet<object>();
  let nodes = 0;
  let bytes = 0;
  const charge = (size: number) => {
    bytes += size;
    if (bytes > MAX_SIGNING_BYTES) throw invalid();
  };
  const text = (input: string) => {
    // Refuse oversized input before computing its encoded size or copying it.
    if (input.length > MAX_SIGNING_BYTES - bytes) throw invalid();
    charge(Buffer.byteLength(input, 'utf8'));
    return input;
  };
  const capture = (input: unknown, depth: number): any => {
    if (depth > 64 || ++nodes > MAX_SIGNING_NODES) throw invalid();
    charge(8);
    if (input === null || typeof input === 'boolean') return input;
    if (typeof input === 'string') return text(input);
    if (typeof input === 'bigint') {
      // EIP-712 numeric types are at most 256 bits; bound conversion allocation.
      if (input <= -MAX_INTEGER_MAGNITUDE || input >= MAX_INTEGER_MAGNITUDE)
        throw invalid();
      return text(input.toString());
    }
    if (typeof input === 'number') {
      if (!Number.isFinite(input)) throw invalid();
      return input;
    }
    if (input instanceof Uint8Array) {
      charge(2 + input.byteLength * 2);
      return `0x${Buffer.from(input).toString('hex')}`;
    }
    if (!input || typeof input !== 'object' || seen.has(input)) throw invalid();
    const array = Array.isArray(input);
    const prototype = Object.getPrototypeOf(input);
    if (!array && prototype !== Object.prototype && prototype !== null)
      throw invalid();
    if (array && input.length > MAX_SIGNING_NODES) throw invalid();
    seen.add(input);
    try {
      const result: any = array ? [] : Object.create(null);
      let count = 0;
      // Avoid allocating an unbounded key array before applying the work budget.
      for (const key in input) {
        if (!Object.prototype.hasOwnProperty.call(input, key)) continue;
        if (++nodes > MAX_SIGNING_NODES) throw invalid();
        text(key);
        if (array && key !== String(count++)) throw invalid();
        const descriptor = Object.getOwnPropertyDescriptor(input, key)!;
        if (
          !('value' in descriptor) ||
          (array && descriptor.value === undefined)
        )
          throw invalid();
        if (descriptor.value !== undefined)
          result[key] = capture(descriptor.value, depth + 1);
      }
      if (array && count !== input.length) throw invalid();
      return Object.freeze(result);
    } finally {
      seen.delete(input);
    }
  };
  return capture(value, 0);
}
