it('loads and serializes public envelopes without private signing or provider modules', () => {
  const forbidden = [
    '../../../src/transactions/evm-local-signer',
    '../../../src/transactions/evm-submission',
    '../../../src/providers',
    '../../../src/keyring-core',
    '../../../src/keyring-manager',
    'syscoinjs-lib',
    'bip32',
  ];
  const loaded: string[] = [];
  for (const name of forbidden)
    jest.doMock(name, () => {
      loaded.push(name);
      throw new Error(`Envelope import loaded ${name}`);
    });
  try {
    jest.isolateModules(() => {
      const {
        snapshotEvmAccessList,
        serializePreparedEvmTransaction,
      } = require('../../../src/transactions/evm-envelope');
      const accessList = snapshotEvmAccessList([
        {
          address: '0x1111111111111111111111111111111111111111',
          storageKeys: ['0x' + '22'.repeat(32)],
        },
      ]);
      const bytes = serializePreparedEvmTransaction({
        type: 2,
        from: '0x1111111111111111111111111111111111111111',
        to: null,
        chainId: '1',
        nonce: '0',
        value: '0',
        gasLimit: '100000',
        data: '0x6080',
        maxFeePerGas: '2',
        maxPriorityFeePerGas: '1',
        accessList,
      });
      expect(bytes).toMatch(/^0x02[0-9a-f]+$/);
      expect(Object.isFrozen(accessList)).toBe(true);
    });
    expect(loaded).toEqual([]);
  } finally {
    for (const name of forbidden) jest.dontMock(name);
  }
});
