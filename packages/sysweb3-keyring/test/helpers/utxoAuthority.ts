export function ownedUtxoTestRead(
  fetch: typeof globalThis.fetch = async () => {
    throw new Error('Unexpected Blockbook request');
  }
) {
  return {
    assertCurrent: () => undefined,
    fetch,
    signal: new AbortController().signal,
  };
}
