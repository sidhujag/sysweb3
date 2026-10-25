import ecc from '@bitcoinerlab/secp256k1';
import { INetworkType } from '@sidhujag/sysweb3-network';

import { EthereumTransactions } from '../../../src/transactions/ethereum';
import { KeyringAccountType } from '../../../src/types';

const PRIVATE_KEY =
  '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const ADDRESS = '0xFCAd0B19bB29D4674531d6f115237E16AfCE377c';
const HASH = `0x${'12'.repeat(32)}`;
const deferred = <T>() => {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => (resolve = done));
  return { promise, resolve };
};

describe('formatted EVM transaction host admission', () => {
  let sdk: EthereumTransactions;
  let provider: any;
  let state: any;
  let current: boolean;
  let guard: jest.Mock;
  let sign: jest.SpyInstance;
  const request = () => ({
    from: ADDRESS,
    to: ADDRESS,
    chainId: 1,
    value: '0x0',
    gasLimit: '0x5208',
    gasPrice: '0x1',
    nonce: 0,
  });
  const send = (options: any = { assertCurrent: guard }) =>
    (sdk.sendFormattedTransaction as any)(request(), true, options);

  beforeEach(() => {
    const network = {
      kind: INetworkType.Ethereum,
      chainId: 1,
      url: 'https://rpc.ankr.com/eth',
      currency: 'eth',
    } as any;
    state = {
      activeAccountType: KeyringAccountType.HDAccount,
      activeAccountId: 0,
      activeNetwork: network,
      accounts: { HDAccount: { 0: { address: ADDRESS } } },
    };
    sdk = new EthereumTransactions(
      () => network,
      () => ({ address: ADDRESS, decryptedPrivateKey: PRIVATE_KEY }),
      () => state,
      {} as any,
      {} as any
    );
    provider = sdk.web3Provider as any;
    provider.sendTransaction.mockResolvedValue({ hash: HASH });
    current = true;
    guard = jest.fn(() => {
      if (!current) throw new Error('Host admission expired');
    });
    sign = jest.spyOn(ecc, 'signRecoverable');
  });

  afterEach(() => jest.restoreAllMocks());

  it.each(['snapshot validity', 'review expiry'])(
    'rechecks %s after chain verification and before private-key signing',
    async () => {
      const entered = deferred<void>();
      const resume = deferred<void>();
      provider.verifyConfiguredChainId.mockImplementationOnce(async () => {
        entered.resolve();
        await resume.promise;
      });
      const result = send();
      const rejected = expect(result).rejects.toMatchObject({
        message: 'Host admission expired',
        transactionNotBroadcast: true,
      });
      await entered.promise;
      current = false;
      resume.resolve();
      await rejected;
      expect(sign).not.toHaveBeenCalled();
      expect(provider.sendTransaction).not.toHaveBeenCalled();
    }
  );

  it('keeps the guard captured at entry when the options object changes', async () => {
    const entered = deferred<void>();
    const resume = deferred<void>();
    provider.verifyConfiguredChainId.mockImplementationOnce(async () => {
      entered.resolve();
      await resume.promise;
    });
    const options = { assertCurrent: guard };
    const result = send(options);
    const rejected = expect(result).rejects.toMatchObject({
      transactionNotBroadcast: true,
    });
    await entered.promise;
    options.assertCurrent = jest.fn();
    current = false;
    resume.resolve();
    await rejected;
    expect(options.assertCurrent).not.toHaveBeenCalled();
    expect(sign).not.toHaveBeenCalled();
    expect(provider.sendTransaction).not.toHaveBeenCalled();
  });

  it('preserves healthy signing and broadcasts exactly once', async () => {
    await expect(send()).resolves.toEqual({ hash: HASH });
    expect(guard.mock.calls.length).toBeGreaterThanOrEqual(3);
    expect(sign).toHaveBeenCalledTimes(1);
    expect(provider.sendTransaction).toHaveBeenCalledTimes(1);
  });

  it('rechecks admission between signing and broadcast', async () => {
    const implementation = sign.getMockImplementation()!;
    sign.mockImplementationOnce((...args) => {
      const signature = implementation(...args);
      current = false;
      return signature;
    });
    await expect(send()).rejects.toMatchObject({
      message: 'Host admission expired',
      transactionNotBroadcast: true,
    });
    expect(sign).toHaveBeenCalledTimes(1);
    expect(provider.sendTransaction).not.toHaveBeenCalled();
  });

  it.each([null, [], { assertCurrent: false }, { assertCurrent: 'yes' }])(
    'refuses invalid options before any preflight or signing: %p',
    async (options) => {
      await expect(send(options)).rejects.toMatchObject({
        transactionNotBroadcast: true,
      });
      expect(provider.verifyConfiguredChainId).not.toHaveBeenCalled();
      expect(sign).not.toHaveBeenCalled();
      expect(provider.sendTransaction).not.toHaveBeenCalled();
    }
  );

  it('refuses async admission and consumes its rejection without signing', async () => {
    await expect(
      send({ assertCurrent: () => Promise.reject(new Error('Late denial')) })
    ).rejects.toMatchObject({ transactionNotBroadcast: true });
    await Promise.resolve();
    expect(sign).not.toHaveBeenCalled();
    expect(provider.sendTransaction).not.toHaveBeenCalled();
  });

  it('refuses admission that becomes asynchronous after preflight', async () => {
    let verified = false;
    provider.verifyConfiguredChainId.mockImplementationOnce(async () => {
      verified = true;
    });
    const assertCurrent = jest.fn(() =>
      verified ? Promise.resolve() : undefined
    );
    await expect(send({ assertCurrent })).rejects.toMatchObject({
      message: 'Transaction context guard must be synchronous',
      transactionNotBroadcast: true,
    });
    expect(provider.verifyConfiguredChainId).toHaveBeenCalledTimes(1);
    expect(sign).not.toHaveBeenCalled();
    expect(provider.sendTransaction).not.toHaveBeenCalled();
  });

  it('does not let a host guard bypass the keyring account guard', async () => {
    provider.verifyConfiguredChainId.mockImplementationOnce(async () => {
      state.activeAccountId = 1;
    });
    await expect(send()).rejects.toMatchObject({
      message: 'Wallet signing context changed',
      transactionNotBroadcast: true,
    });
    expect(sign).not.toHaveBeenCalled();
    expect(provider.sendTransaction).not.toHaveBeenCalled();
  });

  it('preserves an acknowledged broadcast if admission expires while awaiting it', async () => {
    const entered = deferred<void>();
    const resume = deferred<{ hash: string }>();
    provider.sendTransaction.mockImplementationOnce(() => {
      entered.resolve();
      return resume.promise;
    });
    const result = send();
    await entered.promise;
    const callsAtBroadcast = guard.mock.calls.length;
    current = false;
    resume.resolve({ hash: HASH });
    await expect(result).resolves.toEqual({ hash: HASH });
    expect(guard).toHaveBeenCalledTimes(callsAtBroadcast);
    expect(sign).toHaveBeenCalledTimes(1);
    expect(provider.sendTransaction).toHaveBeenCalledTimes(1);
  });
});
