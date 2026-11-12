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
  const divisor = scale < 0 ? 10n ** BigInt(-scale) : 1n;
  const units =
    scale < 0
      ? (digits + divisor - 1n) / divisor
      : digits * 10n ** BigInt(scale);
  if (units > BigInt(Number.MAX_SAFE_INTEGER))
    throw new Error('Invalid UTXO fee rate');
  return Math.max(1, Number(units));
}
