// The package's shared setup imports the SDK with a mocked builder. This
// regression intentionally exercises the installed builder and sanitizer.
jest.resetModules();
jest.unmock('syscoinjs-lib');
if ((global as any).window)
  (global as any).window.location = { href: 'http://localhost/' };

import * as syscoinjs from 'syscoinjs-lib';

import { SyscoinTransactions } from '../../../src/transactions/syscoin';
import { KeyringAccountType } from '../../../src/types';
import { PsbtUtils } from '../../../src/utils/psbt';

describe('explicit native sweep quotes', () => {
  const network = syscoinjs.utils.syscoinNetworks.testnet;
  const address = syscoinjs.utils.bitcoinjs.payments.p2wpkh({
    hash: Buffer.alloc(20, 2),
    network,
  }).address;
  const utxo = (value = '6547561', parent = 1, extra: any = {}) => ({
    txid: parent.toString(16).padStart(64, '0'),
    vout: 0,
    value,
    address,
    confirmations: 0,
    ...extra,
  });
  let main: any;
  let sdk: SyscoinTransactions;
  let fetchUtxos: jest.SpyInstance;
  let create: jest.SpyInstance;
  let getSigner: jest.Mock;
  let state: any;
  const request = {
    amount: '0.09775331',
    receivingAddress: address,
    feeRate: 0.000000012529296875,
    isMax: true,
    nativeSweep: true,
    token: null,
  };

  beforeEach(() => {
    main = new syscoinjs.SyscoinJSLib(null, 'https://offline.invalid', network);
    fetchUtxos = jest
      .spyOn(syscoinjs.utils, 'fetchBackendUTXOS')
      .mockImplementation(async () => [utxo()]);
    create = jest.spyOn(main, 'createTransaction');
    getSigner = jest.fn(() => {
      throw new Error('No signing is permitted');
    });
    state = {
      activeAccountId: 0,
      activeAccountType: KeyringAccountType.HDAccount,
      accounts: { HDAccount: { 0: { xpub: 'vpub-offline', address } } },
      activeNetwork: { slip44: 1, currency: 'TSYS' },
    };
    sdk = new SyscoinTransactions(
      getSigner,
      () => ({ main }),
      () => state,
      async () => address,
      {} as any,
      {} as any
    );
  });
  afterEach(() => jest.restoreAllMocks());

  it('quotes the reported summary mismatch from one current UTXO snapshot', async () => {
    const sanitize = jest.spyOn(syscoinjs.utils, 'sanitizeBlockbookUTXOs');
    const quote = await sdk.getEstimateSysTransactionFee(request);
    expect(quote).toMatchObject({
      grossAmount: '0.06547561',
      recipientAmount: '0.06547335',
      fee: 0.00000226,
    });
    expect(fetchUtxos).toHaveBeenCalledTimes(1);
    expect(sanitize).toHaveBeenCalledTimes(1);
    expect(create.mock.calls[0][5].utxos).toHaveLength(1);
    const psbt = PsbtUtils.fromPali(quote.psbt, {
      slip44: 1,
      currency: 'TSYS',
    });
    expect(psbt.txOutputs[0].value.toString()).toBe('6547335');
    expect(psbt.data.inputs[0].witnessUtxo.value.toString()).toBe('6547561');
    expect(getSigner).not.toHaveBeenCalled();
  });

  it('quotes a fresh larger balance only when nativeSweep was explicitly requested', async () => {
    fetchUtxos.mockResolvedValue([utxo('12000000')]);
    const quote = await sdk.getEstimateSysTransactionFee(request);
    expect(quote.grossAmount).toBe('0.12');
    expect(quote.recipientAmount).toBe('0.11999774');
  });

  it('uses the public address scope for an imported single-address account', async () => {
    state.activeAccountType = KeyringAccountType.Imported;
    state.accounts.Imported = { 0: { xpub: address, address } };
    fetchUtxos.mockResolvedValue([utxo('6547561', 1, { address: undefined })]);
    const quote = await sdk.getEstimateSysTransactionFee(request);
    expect(fetchUtxos).toHaveBeenCalledWith(main.blockbookURL, address);
    expect(quote.grossAmount).toBe('0.06547561');
    expect(quote.recipientAmount).toBe('0.06547335');
    expect(getSigner).not.toHaveBeenCalled();
  });

  it('prepares four consecutive zero-confirmation native parents without a signing call', async () => {
    let value = 9775331n;
    for (let parent = 1; parent <= 4; parent++) {
      fetchUtxos.mockResolvedValueOnce([utxo(value.toString(), parent)]);
      const quote = await sdk.getEstimateSysTransactionFee(request);
      const psbt = PsbtUtils.fromPali(quote.psbt, {
        slip44: 1,
        currency: 'TSYS',
      });
      expect(psbt.data.inputs[0].witnessUtxo.value).toBe(value);
      value -= 226n;
      expect(psbt.txOutputs[0].value).toBe(value);
    }
    expect(value).toBe(9774427n);
    expect(fetchUtxos).toHaveBeenCalledTimes(4);
    expect(getSigner).not.toHaveBeenCalled();
  });

  it('keeps an ordinary full-balance manual request bounded and failing with the exact shortfall', async () => {
    await expect(
      sdk.getEstimateSysTransactionFee({ ...request, nativeSweep: false })
    ).rejects.toMatchObject({
      code: 'INSUFFICIENT_FUNDS',
      shortfall: 0.0322777,
    });
    expect(create.mock.calls[0]).toHaveLength(5);
  });

  it('retains the ordinary manual quote shape and exact recipient amount', async () => {
    const quote = await sdk.getEstimateSysTransactionFee({
      ...request,
      amount: '0.01',
      nativeSweep: false,
      isMax: false,
    });
    expect(Object.keys(quote).sort()).toEqual(['fee', 'psbt']);
    const psbt = PsbtUtils.fromPali(quote.psbt, {
      slip44: 1,
      currency: 'TSYS',
    });
    expect(psbt.txOutputs[0].value).toBe(1000000n);
  });

  it('leaves SPT carrier outpoints untouched instead of counting their native value', async () => {
    fetchUtxos.mockResolvedValue([
      utxo(),
      utxo('1000000', 2, { assetInfo: { assetGuid: '123', value: '10' } }),
    ]);
    const quote = await sdk.getEstimateSysTransactionFee(request);
    expect(quote.grossAmount).toBe('0.06547561');
    const psbt = PsbtUtils.fromPali(quote.psbt, {
      slip44: 1,
      currency: 'TSYS',
    });
    expect(psbt.txInputs).toHaveLength(1);
    expect(
      create.mock.calls[0][5].utxos.every((input: any) => !input.assetInfo)
    ).toBe(true);
  });

  it('spends rewards at the same address without spending linked collateral on MAX', async () => {
    const collateral = utxo('10000000000000', 2);
    fetchUtxos.mockResolvedValue([collateral, utxo('1000000')]);
    const quote = await sdk.getEstimateSysTransactionFee({
      ...request,
      excludedOutpoints: [{ txid: collateral.txid, vout: 0 }],
    });
    expect(quote.grossAmount).toBe('0.01');
    const psbt = PsbtUtils.fromPali(quote.psbt, {
      slip44: 1,
      currency: 'TSYS',
    });
    expect(psbt.txInputs).toHaveLength(1);
    expect(Buffer.from(psbt.txInputs[0].hash).reverse().toString('hex')).toBe(
      utxo().txid
    );
    expect(fetchUtxos).toHaveBeenCalledTimes(1);
  });

  it('excludes collateral for ordinary sends and fails if only collateral could fund the request', async () => {
    const collateral = utxo('10000000000000', 2);
    fetchUtxos.mockResolvedValue([collateral, utxo('1000000')]);
    const excludedOutpoints = [{ txid: collateral.txid, vout: 0 }];
    const quote = await sdk.getEstimateSysTransactionFee({
      ...request,
      nativeSweep: false,
      isMax: false,
      amount: '0.001',
      excludedOutpoints,
    });
    const psbt = PsbtUtils.fromPali(quote.psbt, {
      slip44: 1,
      currency: 'TSYS',
    });
    expect(psbt.txInputs).toHaveLength(1);
    expect(Buffer.from(psbt.txInputs[0].hash).reverse().toString('hex')).toBe(
      utxo().txid
    );
    await expect(
      sdk.getEstimateSysTransactionFee({
        ...request,
        nativeSweep: false,
        isMax: false,
        amount: '1',
        excludedOutpoints,
      })
    ).rejects.toMatchObject({ code: 'INSUFFICIENT_FUNDS' });
  });

  it('preserves SPT metadata when filtering collateral from fee funding', async () => {
    const collateral = utxo('10000000000000', 2);
    const assets = new Map([['123', { symbol: 'TEST', decimals: 8 }]]);
    fetchUtxos.mockResolvedValue({ utxos: [collateral, utxo()], assets });
    const allocate = jest.spyOn(main, 'assetAllocationSend').mockResolvedValue({
      psbt: new syscoinjs.utils.bitcoinjs.Psbt({ network }),
      fee: 226,
    });
    await sdk.getEstimateSysTransactionFee({
      ...request,
      nativeSweep: false,
      token: { guid: '123' },
      excludedOutpoints: [{ txid: collateral.txid, vout: 0 }],
    });
    expect(allocate.mock.calls[0][5]).toEqual({ utxos: [utxo()], assets });
    expect(fetchUtxos).toHaveBeenCalledTimes(1);
  });

  it.each([true, false])(
    'builds an actual SPT transfer with top-level metadata=%s and unprotected fee funds',
    async (withTopLevelMetadata) => {
      const collateral = utxo('10000000000000', 2);
      const carrier = utxo('1000', 3, {
        assetInfo: { assetGuid: '123', value: '1000' },
      });
      fetchUtxos.mockResolvedValue(
        withTopLevelMetadata
          ? {
              utxos: [collateral, utxo(), carrier],
              assets: [
                { assetGuid: '123', maxSupply: '1000000000', decimals: 8 },
              ],
            }
          : [collateral, utxo(), carrier]
      );
      const quote = await sdk.getEstimateSysTransactionFee({
        ...request,
        amount: '0.00000005',
        nativeSweep: false,
        isMax: false,
        token: { guid: '123' },
        excludedOutpoints: [{ txid: collateral.txid, vout: 0 }],
      });
      const psbt = PsbtUtils.fromPali(quote.psbt, {
        slip44: 1,
        currency: 'TSYS',
      });
      const ids = psbt.txInputs.map((input) =>
        Buffer.from(input.hash).reverse().toString('hex')
      );
      expect(ids).toContain(carrier.txid);
      expect(ids).not.toContain(collateral.txid);
      expect(fetchUtxos).toHaveBeenCalledTimes(1);
      expect(getSigner).not.toHaveBeenCalled();
    }
  );

  it('rejects a builder returning protected inputs despite the filtered funding set', async () => {
    const collateral = utxo('10000000000000', 2);
    fetchUtxos.mockResolvedValue([collateral, utxo()]);
    const psbt = new syscoinjs.utils.bitcoinjs.Psbt({ network });
    psbt.addInput({
      hash: collateral.txid,
      index: 0,
      witnessUtxo: {
        script: syscoinjs.utils.bitcoinjs.address.toOutputScript(
          address,
          network
        ),
        value: BigInt(collateral.value),
      },
    });
    jest
      .spyOn(main, 'assetAllocationSend')
      .mockResolvedValue({ psbt, fee: 226 });
    await expect(
      sdk.getEstimateSysTransactionFee({
        ...request,
        nativeSweep: false,
        token: { guid: '123' },
        excludedOutpoints: [{ txid: collateral.txid, vout: 0 }],
      })
    ).rejects.toMatchObject({ code: 'PROTECTED_COLLATERAL' });
  });

  it('includes an uneconomic native outpoint in the complete sweep', async () => {
    fetchUtxos.mockResolvedValue({ utxos: [utxo('1000000'), utxo('1', 2)] });
    const quote = await sdk.getEstimateSysTransactionFee(request);
    expect(quote.grossAmount).toBe('0.01000001');
    expect(quote.recipientAmount).toBe('0.00999639');
    expect(
      PsbtUtils.fromPali(quote.psbt, { slip44: 1, currency: 'TSYS' }).txInputs
    ).toHaveLength(2);
  });

  it('keeps the ordinary SPT estimate route and response shape when sweep is absent', async () => {
    const allocate = jest.spyOn(main, 'assetAllocationSend').mockResolvedValue({
      psbt: new syscoinjs.utils.bitcoinjs.Psbt({ network }),
      fee: 226,
    });
    const quote = await sdk.getEstimateSysTransactionFee({
      ...request,
      nativeSweep: false,
      token: { guid: '123' },
    });
    expect(Object.keys(quote).sort()).toEqual(['fee', 'psbt']);
    expect(allocate).toHaveBeenCalledTimes(1);
    expect(create).not.toHaveBeenCalled();
    expect(fetchUtxos).not.toHaveBeenCalled();
  });

  it.each([
    { isMax: false },
    { token: { guid: '123' } },
    { token: {} },
    { nativeSweep: 'true' },
  ])('rejects invalid sweep intent before fetching: %p', async (change) => {
    await expect(
      sdk.getEstimateSysTransactionFee({ ...request, ...change } as any)
    ).rejects.toMatchObject({ code: 'INVALID_NATIVE_SWEEP' });
    expect(fetchUtxos).not.toHaveBeenCalled();
    expect(create).not.toHaveBeenCalled();
  });

  it.each([
    [utxo(), utxo()],
    [utxo('-1')],
    [utxo('1.5')],
    [utxo('1e6')],
    [utxo('1', 1, { value: Number.MAX_SAFE_INTEGER + 1 })],
    [utxo('1', 1, { vout: -1 })],
    [utxo('1', 1, { txid: 'invalid' })],
    [utxo('1', 1, { assetInfo: false })],
  ])(
    'rejects duplicate or malformed raw outpoints/values: %p',
    async (...inputs) => {
      fetchUtxos.mockResolvedValue(inputs);
      await expect(
        sdk.getEstimateSysTransactionFee(request)
      ).rejects.toMatchObject({ code: 'INVALID_NATIVE_SWEEP_UTXOS' });
      expect(create).not.toHaveBeenCalled();
    }
  );

  it.each([
    [],
    [utxo('1000000', 1, { assetInfo: { assetGuid: '123', value: '10' } })],
    [utxo('294')],
  ])(
    'rejects empty, asset-only, or dust-limited funding: %p',
    async (...inputs) => {
      fetchUtxos.mockResolvedValue(inputs);
      await expect(
        sdk.getEstimateSysTransactionFee(request)
      ).rejects.toMatchObject({ error: true });
    }
  );

  it('rejects an oversized sweep instead of returning a partial quote', async () => {
    fetchUtxos.mockResolvedValue(
      Array.from({ length: 1500 }, (_, i) => utxo('10000', i + 1))
    );
    await expect(
      sdk.getEstimateSysTransactionFee(request)
    ).rejects.toMatchObject({ error: true });
  });

  it('sums large atomic strings without rounding the gross through Number', async () => {
    fetchUtxos.mockResolvedValue([
      utxo('4503599627370496'),
      utxo('4503599627370497', 2),
    ]);
    const quote = await sdk.getEstimateSysTransactionFee(request);
    expect(quote.grossAmount).toBe('90071992.54740993');
    expect(quote.recipientAmount).toBe('90071992.54740631');
    expect(create.mock.calls[0][2][0].value.toString()).toBe(
      '9007199254740993'
    );
  });

  it('fails closed when an individual input exceeds the existing builder numeric limit', async () => {
    fetchUtxos.mockResolvedValue([utxo('9007199254740993')]);
    await expect(
      sdk.getEstimateSysTransactionFee(request)
    ).rejects.toMatchObject({ error: true });
  });

  it('rejects a quote fee inconsistent with the returned recipient value', async () => {
    create.mockImplementationOnce(async (...args) => {
      const result =
        await syscoinjs.SyscoinJSLib.prototype.createTransaction.apply(
          main,
          args
        );
      return { ...result, fee: result.fee + 1 };
    });
    await expect(
      sdk.getEstimateSysTransactionFee(request)
    ).rejects.toMatchObject({ code: 'INCOMPLETE_NATIVE_SWEEP' });
  });

  it('rejects a builder result which omits a requested funding outpoint', async () => {
    fetchUtxos.mockResolvedValue([utxo(), utxo('1000000', 2)]);
    create.mockResolvedValue({ psbt: { txInputs: [], txOutputs: [] }, fee: 1 });
    await expect(
      sdk.getEstimateSysTransactionFee(request)
    ).rejects.toMatchObject({ code: 'INCOMPLETE_NATIVE_SWEEP' });
  });
});
