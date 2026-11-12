/**
 * The public rate is coins/vbyte. Convert its decimal representation exactly:
 * multiplying a binary Number first can make 7e-8 round up to 8 atomic units.
 */
export function utxoFeeRateUnits(rate: number): number {
  if (!Number.isFinite(rate) || rate <= 0)
    throw new Error('Invalid UTXO fee rate');
  const [coefficient, scientific = '0'] = rate
    .toString()
    .toLowerCase()
    .split('e');
  const [whole, fraction = ''] = coefficient.split('.');
  const digits = BigInt(whole + fraction);
  const scale = Number(scientific) - fraction.length + 8;
  // ES2015 consumer transforms rewrite exponentiation to Math.pow, which
  // cannot accept BigInt. Finite Number input keeps this decimal string bounded.
  const power = BigInt('1' + '0'.repeat(Math.abs(scale)));
  const units = scale < 0 ? (digits + power - 1n) / power : digits * power;
  if (units > BigInt(Number.MAX_SAFE_INTEGER))
    throw new Error('Invalid UTXO fee rate');
  return Math.max(1, Number(units));
}
