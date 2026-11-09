/** Own the signing payload before initialization, retry or platform code can await. */
export function captureHardwareSigningData(
  value: unknown,
  invalid: () => Error,
  seen = new WeakSet<object>(),
  depth = 0
): any {
  if (depth > 64) throw invalid();
  if (value === null || typeof value === 'string' || typeof value === 'boolean')
    return value;
  if (typeof value === 'bigint') return value.toString();
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw invalid();
    return value;
  }
  if (value instanceof Uint8Array)
    return `0x${Buffer.from(value).toString('hex')}`;
  if (!value || typeof value !== 'object' || seen.has(value)) throw invalid();
  const array = Array.isArray(value);
  const prototype = Object.getPrototypeOf(value);
  if (!array && prototype !== Object.prototype && prototype !== null)
    throw invalid();
  seen.add(value);
  try {
    const result: any = array ? [] : Object.create(null);
    for (const key of Object.keys(value)) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key)!;
      if (!('value' in descriptor)) throw invalid();
      if (descriptor.value !== undefined)
        result[key] = captureHardwareSigningData(
          descriptor.value,
          invalid,
          seen,
          depth + 1
        );
    }
    return Object.freeze(result);
  } finally {
    seen.delete(value);
  }
}
