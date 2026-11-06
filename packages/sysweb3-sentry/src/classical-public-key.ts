import { fail } from './bytes.js';

export type SentryClassicalScheme = 'bls-basic' | 'secp256k1';

/** Derive only the compressed public key. The caller still owns its input. */
export async function deriveSentryClassicalPublicKey(
  scheme: SentryClassicalScheme,
  secret: Uint8Array
): Promise<Uint8Array> {
  if (scheme !== 'bls-basic' && scheme !== 'secp256k1')
    return fail('UNSUPPORTED_SCHEME', 'Unsupported Sentry key scheme');
  let owned: Uint8Array | undefined;
  try {
    if (!ArrayBuffer.isView(secret) || !(secret instanceof Uint8Array) ||
        secret.byteLength !== 32 || !(secret.buffer instanceof ArrayBuffer))
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
