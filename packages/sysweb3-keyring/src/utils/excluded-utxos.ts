export interface ExcludedOutpoint {
  txid: string;
  vout: number;
}

const invalid = () =>
  Object.assign(new Error('Invalid protected UTXO selection.'), {
    error: true,
    code: 'INVALID_EXCLUDED_UTXOS',
  });

export const excludedOutpointIds = (
  outpoints: readonly ExcludedOutpoint[] = []
): Set<string> => {
  if (!Array.isArray(outpoints) || outpoints.length > 1000) throw invalid();
  return new Set(
    outpoints.map((entry) => {
      if (
        !entry ||
        typeof entry.txid !== 'string' ||
        !/^[0-9a-fA-F]{64}$/.test(entry.txid) ||
        !Number.isSafeInteger(entry.vout) ||
        entry.vout < 0 ||
        entry.vout > 0xffffffff
      )
        throw invalid();
      return `${entry.txid.toLowerCase()}:${entry.vout}`;
    })
  );
};

/** Preserve the backend's asset metadata while removing only reserved outputs. */
export const filterExcludedUtxos = (
  raw: any,
  excluded: ReadonlySet<string>
) => {
  const rows = Array.isArray(raw) ? raw : raw?.utxos;
  if (!Array.isArray(rows)) throw invalid();
  const utxos = rows.filter((row) => {
    const txid = row?.txId ?? row?.txid;
    if (
      typeof txid !== 'string' ||
      !/^[0-9a-fA-F]{64}$/.test(txid) ||
      !Number.isSafeInteger(row.vout) ||
      row.vout < 0 ||
      row.vout > 0xffffffff ||
      (row.txId !== undefined &&
        row.txid !== undefined &&
        (typeof row.txId !== 'string' ||
          typeof row.txid !== 'string' ||
          row.txId.toLowerCase() !== row.txid.toLowerCase()))
    )
      throw invalid();
    return !excluded.has(`${txid.toLowerCase()}:${row.vout}`);
  });
  return Array.isArray(raw) ? { utxos } : { ...raw, utxos };
};

export const assertNoExcludedInputs = (
  psbt: { txInputs: { hash: Uint8Array; index: number }[] },
  excluded: ReadonlySet<string>
) => {
  if (!Array.isArray(psbt?.txInputs)) throw invalid();
  for (const input of psbt.txInputs) {
    const id = `${Buffer.from(input.hash).reverse().toString('hex')}:${
      input.index
    }`;
    if (excluded.has(id))
      throw Object.assign(
        new Error('This transaction would spend protected collateral.'),
        {
          error: true,
          code: 'PROTECTED_COLLATERAL',
        }
      );
  }
};
