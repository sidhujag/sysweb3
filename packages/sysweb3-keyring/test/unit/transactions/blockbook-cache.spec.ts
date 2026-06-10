import * as syscoinjs from 'syscoinjs-lib';

import { SyscoinTransactions } from '../../../src/transactions/syscoin';
import {
  fetchBackendAccountCached,
  invalidateBlockbookAccountCache,
} from '../../../src/utils/blockbook-cache';

const URL = 'https://blockbook.test';
const XPUB = 'zpub-test-account';
const OPTIONS = 'tokens=used&details=tokens';

const fetchBackendAccountMock = syscoinjs.utils
  .fetchBackendAccount as jest.Mock;
const fetchEstimateFeeMock = syscoinjs.utils.fetchEstimateFee as jest.Mock;

describe('blockbook account cache', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    invalidateBlockbookAccountCache();
    fetchBackendAccountMock.mockResolvedValue({
      balance: 100000000,
      tokens: [{ name: 'addr1', path: "m/84'/57'/0'/0/0" }],
    });
  });

  it('collapses concurrent identical requests into a single fetch', async () => {
    let resolveFetch!: (value: any) => void;
    fetchBackendAccountMock.mockReturnValueOnce(
      new Promise((resolve) => {
        resolveFetch = resolve;
      })
    );

    const p1 = fetchBackendAccountCached(URL, XPUB, OPTIONS);
    const p2 = fetchBackendAccountCached(URL, XPUB, OPTIONS);

    expect(fetchBackendAccountMock).toHaveBeenCalledTimes(1);

    resolveFetch({ balance: 1, tokens: [] });
    const [first, second] = await Promise.all([p1, p2]);
    expect(second).toEqual(first);
  });

  it('refetches once the previous request has settled (no TTL caching)', async () => {
    await fetchBackendAccountCached(URL, XPUB, OPTIONS);
    await fetchBackendAccountCached(URL, XPUB, OPTIONS);

    expect(fetchBackendAccountMock).toHaveBeenCalledTimes(2);
  });

  it('keys in-flight requests by backend url, xpub and options', async () => {
    fetchBackendAccountMock.mockReturnValue(new Promise(() => undefined));

    fetchBackendAccountCached(URL, XPUB, OPTIONS);
    fetchBackendAccountCached(URL, 'zpub-other', OPTIONS);
    fetchBackendAccountCached(URL, XPUB, 'details=basic');
    fetchBackendAccountCached(URL, XPUB, OPTIONS);

    expect(fetchBackendAccountMock).toHaveBeenCalledTimes(3);
  });

  it('propagates failures to all deduplicated callers and refetches afterwards', async () => {
    fetchBackendAccountMock.mockRejectedValueOnce(new Error('boom'));

    await expect(fetchBackendAccountCached(URL, XPUB, OPTIONS)).rejects.toThrow(
      'boom'
    );
    const result = await fetchBackendAccountCached(URL, XPUB, OPTIONS);

    expect(fetchBackendAccountMock).toHaveBeenCalledTimes(2);
    expect(result.balance).toBe(100000000);
  });
});

describe('getRecommendedFee cache', () => {
  const buildTransactions = () =>
    new SyscoinTransactions(
      jest.fn() as any,
      jest.fn() as any,
      jest.fn() as any,
      jest.fn() as any,
      {} as any,
      {} as any
    );

  beforeEach(() => {
    jest.clearAllMocks();
    fetchEstimateFeeMock.mockResolvedValue(10);
  });

  it('caches the recommended fee per explorer url', async () => {
    const transactions = buildTransactions();

    const fee1 = await transactions.getRecommendedFee(URL);
    const fee2 = await transactions.getRecommendedFee(URL);

    expect(fetchEstimateFeeMock).toHaveBeenCalledTimes(1);
    expect(fee1).toBe(10 / 1024);
    expect(fee2).toBe(fee1);
  });

  it('fetches separately for different explorers', async () => {
    const transactions = buildTransactions();

    await transactions.getRecommendedFee(URL);
    await transactions.getRecommendedFee('https://other-blockbook.test');

    expect(fetchEstimateFeeMock).toHaveBeenCalledTimes(2);
  });

  it('refreshes the fee after the TTL expires', async () => {
    const transactions = buildTransactions();
    const nowSpy = jest.spyOn(Date, 'now');
    const base = 1_750_000_000_000;

    nowSpy.mockReturnValue(base);
    await transactions.getRecommendedFee(URL);

    nowSpy.mockReturnValue(base + 61_000); // TTL is 60s
    await transactions.getRecommendedFee(URL);

    expect(fetchEstimateFeeMock).toHaveBeenCalledTimes(2);
    nowSpy.mockRestore();
  });
});
