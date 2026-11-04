import { BigNumber } from '../../../src/ethers-v6';
import { EvmGasLimitError } from '../../../src/evm-fees';
import { EthereumTransactions } from '../../../src/transactions/ethereum';

const make = (chainId = 1) => {
  let network = {
    kind: 'ethereum',
    chainId,
    slip44: 60,
    url: 'https://offline.invalid',
  } as any;
  let provider = {
    estimateGas: jest.fn().mockResolvedValue(BigNumber.from('21000')),
  };
  const sdk = new EthereumTransactions(
    () => network,
    () => {
      throw new Error('No signing');
    },
    (() => ({ activeNetwork: network })) as any,
    {} as any,
    {} as any
  );
  Object.defineProperty(sdk, 'web3Provider', { get: () => provider });
  return {
    sdk,
    get provider() {
      return provider;
    },
    set provider(value) {
      provider = value;
    },
    get network() {
      return network;
    },
    set network(value) {
      network = value;
    },
  };
};
const deferred = <T>() => {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { resolve, promise };
};

describe('SDK estimates honor shared activated gas bounds', () => {
  it.each([undefined, '0x6000'])(
    'rejects padded 14M estimate without a lower-gas fallback (%s)',
    async (data) => {
      const f = make();
      f.provider.estimateGas.mockResolvedValue(BigNumber.from('14000000'));
      await expect(f.sdk.getTxGasLimit({ data })).rejects.toBeInstanceOf(
        EvmGasLimitError
      );
      expect(f.provider.estimateGas).toHaveBeenCalledTimes(1);
    }
  );
  it('preserves the same buffered estimate on unrelated chains', async () => {
    const f = make(5700);
    f.provider.estimateGas.mockResolvedValue(BigNumber.from('14000000'));
    expect((await f.sdk.getTxGasLimit({ data: '0x6000' })).toString()).toBe(
      '16800000'
    );
  });
  it('bounds configured minimums on successful estimates and calldata fallbacks', async () => {
    for (const fail of [false, true]) {
      const f = make();
      f.sdk.setGasOverrides({ minGasLimit: '16777217' });
      if (fail)
        f.provider.estimateGas.mockRejectedValue(new Error('No estimate'));
      await expect(
        f.sdk.getTxGasLimit({ data: '0x6000' })
      ).rejects.toBeInstanceOf(EvmGasLimitError);
      expect(f.provider.estimateGas).toHaveBeenCalledTimes(1);
    }
  });
  it('bounds the basic-transfer fallback without falling through to a fabricated lower result', async () => {
    const f = make();
    f.provider.estimateGas
      .mockRejectedValueOnce(new Error('No estimate'))
      .mockResolvedValueOnce(BigNumber.from('12000000'));
    await expect(f.sdk.getTxGasLimit({})).rejects.toBeInstanceOf(
      EvmGasLimitError
    );
    expect(f.provider.estimateGas).toHaveBeenCalledTimes(2);
  });
  it('bounds the ultimate fallback minimum', async () => {
    const f = make();
    f.sdk.setGasOverrides({ minGasLimit: '16777217' });
    f.provider.estimateGas.mockRejectedValue(new Error('No estimate'));
    await expect(f.sdk.getTxGasLimit({})).rejects.toBeInstanceOf(
      EvmGasLimitError
    );
    expect(f.provider.estimateGas).toHaveBeenCalledTimes(2);
  });
  it.each(['success', 'failure'])(
    'rejects network drift after %s without validating under the new chain',
    async (outcome) => {
      const f = make(),
        hold = deferred<any>();
      f.provider.estimateGas.mockReturnValue(hold.promise);
      const pending = f.sdk.getTxGasLimit({ data: '0x6000' });
      f.network = { ...f.network, chainId: 5700 };
      hold.resolve(
        outcome === 'success'
          ? BigNumber.from('14000000')
          : Promise.reject(new Error('No estimate'))
      );
      await expect(pending).rejects.toMatchObject({ name: 'AbortError' });
      expect(f.provider.estimateGas).toHaveBeenCalledTimes(1);
    }
  );
  it('rejects a replaced provider even on the same chain', async () => {
    const f = make(),
      hold = deferred<any>();
    f.provider.estimateGas.mockReturnValue(hold.promise);
    const pending = f.sdk.getTxGasLimit({});
    const original = f.provider;
    f.provider = {
      estimateGas: jest.fn().mockResolvedValue(BigNumber.from('21000')),
    };
    hold.resolve(BigNumber.from('21000'));
    await expect(pending).rejects.toMatchObject({ name: 'AbortError' });
    expect(original.estimateGas).toHaveBeenCalledTimes(1);
    expect(f.provider.estimateGas).not.toHaveBeenCalled();
  });
  it('snapshots the configured minimum and transaction before the asynchronous estimate', async () => {
    const f = make(),
      hold = deferred<any>();
    f.provider.estimateGas.mockReturnValue(hold.promise);
    const request = { data: '0x6000' };
    f.sdk.setGasOverrides({ minGasLimit: '65000' });
    const pending = f.sdk.getTxGasLimit(request);
    request.data = '0x6001';
    f.sdk.setGasOverrides({ minGasLimit: '16777217' });
    hold.resolve(BigNumber.from('21000'));
    expect((await pending).toString()).toBe('65000');
    expect(f.provider.estimateGas.mock.calls[0][0]).toEqual({ data: '0x6000' });
  });
});
