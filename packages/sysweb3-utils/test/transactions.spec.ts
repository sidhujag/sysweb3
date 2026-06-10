import * as syscoinjs from 'syscoinjs-lib';

import { clearRawTransactionCache, txUtils } from '../src/transactions';

jest.mock('syscoinjs-lib', () => ({
  utils: {
    fetchBackendRawTx: jest.fn(),
  },
}));

const fetchBackendRawTxMock = syscoinjs.utils.fetchBackendRawTx as jest.Mock;

const URL = 'https://blockbook.test';
const TXID = 'a'.repeat(64);

describe('txUtils getRawTransaction cache', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    clearRawTransactionCache();
    fetchBackendRawTxMock.mockResolvedValue({
      txid: TXID,
      hex: '0xdeadbeef',
      confirmations: 1,
    });
  });

  it('reuses the cached response for the same txid within the TTL', async () => {
    const { getRawTransaction } = txUtils();

    const first = await getRawTransaction(URL, TXID);
    const second = await getRawTransaction(URL, TXID);

    expect(fetchBackendRawTxMock).toHaveBeenCalledTimes(1);
    expect(second).toEqual(first);
  });

  it('shares the cache across txUtils instances', async () => {
    await txUtils().getRawTransaction(URL, TXID);
    await txUtils().getRawTransaction(URL, TXID);

    expect(fetchBackendRawTxMock).toHaveBeenCalledTimes(1);
  });

  it('fetches separately for different txids', async () => {
    const { getRawTransaction } = txUtils();

    await getRawTransaction(URL, TXID);
    await getRawTransaction(URL, 'b'.repeat(64));

    expect(fetchBackendRawTxMock).toHaveBeenCalledTimes(2);
  });

  it('expires entries after the TTL', async () => {
    const { getRawTransaction } = txUtils();
    const nowSpy = jest.spyOn(Date, 'now');
    const base = 1_750_000_000_000;

    nowSpy.mockReturnValue(base);
    await getRawTransaction(URL, TXID);

    nowSpy.mockReturnValue(base + 61_000); // TTL is 60s
    await getRawTransaction(URL, TXID);

    expect(fetchBackendRawTxMock).toHaveBeenCalledTimes(2);
    nowSpy.mockRestore();
  });

  it('does not cache failures', async () => {
    const { getRawTransaction } = txUtils();
    fetchBackendRawTxMock.mockRejectedValueOnce(new Error('boom'));

    await expect(getRawTransaction(URL, TXID)).rejects.toThrow('boom');
    const result = await getRawTransaction(URL, TXID);

    expect(fetchBackendRawTxMock).toHaveBeenCalledTimes(2);
    expect(result.hex).toBe('0xdeadbeef');
  });

  it('does not cache null responses (tx not indexed yet)', async () => {
    const { getRawTransaction } = txUtils();
    fetchBackendRawTxMock.mockResolvedValueOnce(null);

    await getRawTransaction(URL, TXID);
    await getRawTransaction(URL, TXID);

    expect(fetchBackendRawTxMock).toHaveBeenCalledTimes(2);
  });
});
