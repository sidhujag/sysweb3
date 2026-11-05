import * as syscoinjs from 'syscoinjs-lib';

import { readPublicSyscoinFee } from '../../../src/transactions/syscoin-core';
import {
  fetchBackendAccountCached,
  invalidateBlockbookAccountCache,
} from '../../../src/utils/blockbook-cache';
import { ownedUtxoTestRead } from '../../helpers/utxoAuthority';

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

describe('public Blockbook fee ownership', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    fetchEstimateFeeMock.mockResolvedValue(10);
  });

  it('requires a public read owner without opening any wallet session', async () => {
    await expect(
      Reflect.apply(readPublicSyscoinFee, undefined, [URL])
    ).rejects.toThrow('Missing owned UTXO read');
    expect(fetchEstimateFeeMock).not.toHaveBeenCalled();
    const authority = ownedUtxoTestRead();
    await expect(readPublicSyscoinFee(URL, authority)).resolves.toBe(10 / 1024);
    expect(fetchEstimateFeeMock).toHaveBeenCalledWith(
      URL,
      1,
      undefined,
      expect.objectContaining({
        signal: authority.signal,
        fetch: expect.any(Function),
      })
    );
  });
});
