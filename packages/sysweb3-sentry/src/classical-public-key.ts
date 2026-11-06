import { fail } from './bytes.js';

export type SentryClassicalScheme = 'bls-basic' | 'secp256k1';

// Read the built-in view and backing-store slots instead of overridable properties.
const typedArray = Object.getPrototypeOf(Uint8Array.prototype);
const viewType = Object.getOwnPropertyDescriptor(typedArray, Symbol.toStringTag)!.get!;
const viewLength = Object.getOwnPropertyDescriptor(typedArray, 'byteLength')!.get!;
const viewBuffer = Object.getOwnPropertyDescriptor(typedArray, 'buffer')!.get!;
const bufferLength = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'byteLength')!.get!;

/** Derive only the compressed public key. The caller still owns its input. */
export async function deriveSentryClassicalPublicKey(
  scheme: SentryClassicalScheme,
  secret: Uint8Array
): Promise<Uint8Array> {
  if (scheme !== 'bls-basic' && scheme !== 'secp256k1')
    return fail('UNSUPPORTED_SCHEME', 'Unsupported Sentry key scheme');
  let owned: Uint8Array | undefined;
  try {
    if (viewType.call(secret) !== 'Uint8Array' || viewLength.call(secret) !== 32 ||
        bufferLength.call(viewBuffer.call(secret)) < 32)
      return fail('INVALID_SECRET_KEY', 'Invalid Sentry secret key');
    // Own the exact borrowed view before yielding to the curve loader.
    owned = new Uint8Array(secret);
    const Point = scheme === 'bls-basic'
      ? (await import('@noble/curves/bls12-381.js')).bls12_381.G1.Point
      : (await import('@noble/curves/secp256k1.js')).secp256k1.Point;
    let scalar = 0n;
    for (const byte of owned) scalar = (scalar << 8n) | BigInt(byte);
    // Core imports the canonical nonzero scalar without modular reduction.
    if (scalar === 0n || scalar >= Point.Fn.ORDER)
      return fail('INVALID_SECRET_KEY', 'Invalid Sentry secret key');
    return Point.BASE.multiply(scalar).toBytes(true);
  } catch {
    return fail('INVALID_SECRET_KEY', 'Invalid Sentry secret key');
  } finally {
    owned?.fill(0);
  }
}
