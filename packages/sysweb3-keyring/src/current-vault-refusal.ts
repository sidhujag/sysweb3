/** Internal ciphertext comparison for a current-vault tag refusal. */
export const currentVaultRefusals = new WeakMap<
  Error,
  (vault: string) => boolean
>();
