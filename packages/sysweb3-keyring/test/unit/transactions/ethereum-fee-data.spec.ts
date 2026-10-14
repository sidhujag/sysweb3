jest.resetModules();
(global as any).window.location = { href: 'http://localhost/' };
jest.mock('../../../src/transactions/evm-local-signer', () => ({
  ...jest.requireActual('../../../src/transactions/evm-local-signer'),
  sendLocalEvmTransaction: jest.fn(),
}));

import { INetworkType } from '@sidhujag/sysweb3-network';

import { BigNumber } from '../../../src/ethers-v6';
import { EthereumTransactions } from '../../../src/transactions/ethereum';
import { sendLocalEvmTransaction } from '../../../src/transactions/evm-local-signer';
import { KeyringAccountType } from '../../../src/types';

const FROM = `0x${'11'.repeat(20)}`;
const TO = `0x${'22'.repeat(20)}`;
const HASH = `0x${'33'.repeat(32)}`;
const network = {
  chainId: 5700,
  kind: INetworkType.Ethereum,
  url: 'https://unit-only.test',
} as any;
const transaction = {
  from: FROM,
  to: TO,
  chainId: 5700,
  nonce: 0,
  gasLimit: '21000',
  value: '0x7',
  data: '0x1234',
};
const localSend = sendLocalEvmTransaction as jest.Mock;

function fixture() {
  const provider = {
    getGasPrice: jest.fn().mockResolvedValue(BigNumber.from(7)),
    getBlock: jest.fn().mockResolvedValue({ baseFeePerGas: BigNumber.from(5) }),
    getFeeData: jest.fn().mockResolvedValue({
      gasPrice: BigNumber.from(7),
      maxFeePerGas: BigNumber.from(12),
      maxPriorityFeePerGas: BigNumber.from(0),
    }),
    send: jest.fn().mockResolvedValue('0x0'),
    estimateGas: jest.fn().mockResolvedValue(BigNumber.from(21000)),
    sendTransaction: jest.fn(),
  };
  // This getter and the local sender are mocks, never a library wallet/key.
  const getKey = jest.fn(() => ({
    address: FROM,
    decryptedPrivateKey: 'unit-test-placeholder',
  }));
  const sdk = new EthereumTransactions(
    () => network,
    getKey,
    () =>
      ({
        activeNetwork: network,
        activeAccountId: 0,
        activeAccountType: KeyringAccountType.HDAccount,
        accounts: {
          [KeyringAccountType.HDAccount]: { 0: { address: FROM } },
          Imported: {},
          Ledger: {},
          Trezor: {},
        },
      } as any),
    {} as any,
    {} as any
  );
  Object.defineProperty(sdk, 'web3Provider', { get: () => provider });
  return { sdk, provider, getKey };
}

beforeEach(() => {
  jest.clearAllMocks();
  localSend.mockImplementation(
    async (_provider, _key, _tx, beforeBroadcast) => {
      beforeBroadcast?.();
      return { hash: HASH };
    }
  );
});

describe('actual RPC fee data without a fabricated tip or model switch', () => {
  it.each([0, '0x0', '0', BigNumber.from(0)])(
    'retains a valid zero priority fee %p and the actual gas price separately',
    async (zero) => {
      const { sdk, provider } = fixture();
      provider.send.mockResolvedValue(zero);
      const fee: any = await sdk.getFeeDataWithDynamicMaxPriorityFeePerGas();
      expect(fee.maxPriorityFeePerGas.toString()).toBe('0');
      expect(fee.maxFeePerGas.toString()).toBe('12');
      expect(fee.gasPrice.toString()).toBe('7');
      expect(fee.baseFeePerGas.toString()).toBe('5');
      expect(provider.send).toHaveBeenCalledTimes(1);
      expect(provider.send).toHaveBeenCalledWith(
        'eth_maxPriorityFeePerGas',
        []
      );
    }
  );

  it('preserves a positive tip and existing maximum-fee calculation', async () => {
    const { sdk, provider } = fixture();
    provider.send.mockResolvedValue('0x2');
    const fee: any = await sdk.getFeeDataWithDynamicMaxPriorityFeePerGas();
    expect(fee.maxPriorityFeePerGas.toString()).toBe('2');
    expect(fee.maxFeePerGas.toString()).toBe('14');
    expect(fee.gasPrice.toString()).toBe('7');
  });

  it('classifies a zero base fee as EIP-1559 rather than legacy', async () => {
    const { sdk, provider } = fixture();
    provider.getBlock.mockResolvedValue({ baseFeePerGas: BigNumber.from(0) });
    const fee: any = await sdk.getFeeDataWithDynamicMaxPriorityFeePerGas();
    expect(fee.baseFeePerGas.toString()).toBe('0');
    expect(fee.maxPriorityFeePerGas.toString()).toBe('0');
    expect(fee.maxFeePerGas.gt(0)).toBe(true);
  });

  it('uses the legacy sentinel only for an actual header without a base fee', async () => {
    const { sdk, provider } = fixture();
    provider.getBlock.mockResolvedValue({} as any);
    const fee: any = await sdk.getFeeDataWithDynamicMaxPriorityFeePerGas();
    expect(fee.maxFeePerGas.toString()).toBe('0');
    expect(fee.maxPriorityFeePerGas.toString()).toBe('0');
    expect(fee.gasPrice.toString()).toBe('7');
    expect(fee.baseFeePerGas).toBeUndefined();
    expect(provider.send).not.toHaveBeenCalled();
  });

  it('preserves an explicitly configured priority floor, rather than inventing one', async () => {
    const { sdk } = fixture();
    sdk.setGasOverrides({ minPriorityFee: '2' });
    const fee = await sdk.getFeeDataWithDynamicMaxPriorityFeePerGas();
    expect(fee.maxPriorityFeePerGas.toString()).toBe('2');
  });

  it.each([null, undefined, 'corrupt', -1, Number.MAX_SAFE_INTEGER + 1])(
    'rejects unavailable or corrupt baseline fee data %p',
    async (gasPrice) => {
      const { sdk, provider } = fixture();
      provider.getGasPrice.mockResolvedValue(gasPrice as any);
      await expect(
        sdk.getFeeDataWithDynamicMaxPriorityFeePerGas()
      ).rejects.toThrow();
      expect(provider.send).not.toHaveBeenCalled();
    }
  );

  it.each([null, undefined])(
    'does not mistake an absent block %p for legacy support',
    async (block) => {
      const { sdk, provider } = fixture();
      provider.getBlock.mockResolvedValue(block as any);
      await expect(
        sdk.getFeeDataWithDynamicMaxPriorityFeePerGas()
      ).rejects.toThrow('Block not found');
      expect(provider.send).not.toHaveBeenCalled();
    }
  );

  it('preserves the explicit force-legacy fee recommendation', async () => {
    const { sdk, provider } = fixture();
    provider.getGasPrice.mockResolvedValue(BigNumber.from(100));
    const safe = await sdk.getSafeFeeData(true);
    expect(safe.gasPrice.toString()).toBe('110');
    expect(safe.maxFeePerGas).toBeUndefined();
    expect(provider.getBlock).not.toHaveBeenCalled();
    expect(provider.send).not.toHaveBeenCalled();
  });

  it('permits zero observed fee-history rewards when the priority RPC is explicitly unsupported', async () => {
    const { sdk, provider } = fixture();
    provider.send.mockRejectedValueOnce(
      Object.assign(new Error('unsupported method'), { code: -32601 })
    );
    provider.send.mockResolvedValueOnce({
      reward: [
        ['0x0', '0x0', '0x0'],
        ['0x1', '0x0', '0x2'],
      ],
    });
    const fee = await sdk.getFeeDataWithDynamicMaxPriorityFeePerGas();
    expect(fee.maxPriorityFeePerGas.toString()).toBe('0');
    expect(fee.maxFeePerGas.toString()).toBe('12');
    expect(provider.send).toHaveBeenCalledTimes(2);
  });

  it.each(['gas', 'block', 'priority'])(
    'does not turn a failed %s RPC into zeros, a minimum tip or legacy pricing',
    async (stage) => {
      const { sdk, provider } = fixture();
      const error = new Error('RPC unavailable');
      if (stage === 'gas') provider.getGasPrice.mockRejectedValue(error);
      if (stage === 'block') provider.getBlock.mockRejectedValue(error);
      if (stage === 'priority') provider.send.mockRejectedValue(error);
      await expect(
        sdk.getFeeDataWithDynamicMaxPriorityFeePerGas()
      ).rejects.toBe(error);
      expect(
        provider.send.mock.calls.some(([method]) => method === 'eth_feeHistory')
      ).toBe(false);
    }
  );

  it.each([null, 'corrupt', '-1', BigNumber.from(-1)])(
    'rejects malformed or negative priority data %p without guessing',
    async (priority) => {
      const { sdk, provider } = fixture();
      provider.send.mockResolvedValue(priority);
      await expect(
        sdk.getFeeDataWithDynamicMaxPriorityFeePerGas()
      ).rejects.toThrow();
    }
  );

  it.each([
    null,
    {},
    { reward: [] },
    { reward: [['0x0']] },
    { reward: [['0x0', '-1', '0x0']] },
  ])(
    'rejects unavailable or malformed history %p without a hardcoded tip',
    async (history) => {
      const { sdk, provider } = fixture();
      provider.send.mockRejectedValueOnce(
        Object.assign(new Error('unsupported method'), { code: -32601 })
      );
      provider.send.mockResolvedValueOnce(history);
      await expect(
        sdk.getFeeDataWithDynamicMaxPriorityFeePerGas()
      ).rejects.toThrow();
    }
  );

  it('getSafeFeeData retains a valid zero-tip EIP-1559 quote', async () => {
    const { sdk, provider } = fixture();
    const safe = await sdk.getSafeFeeData();
    expect(safe.maxFeePerGas.toString()).toBe('12');
    expect(safe.maxPriorityFeePerGas.toString()).toBe('0');
    expect(provider.getGasPrice).toHaveBeenCalledTimes(1);
  });

  it('getSafeFeeData preserves discovery failures rather than rereading a different legacy price', async () => {
    const { sdk, provider } = fixture();
    const error = new Error('RPC unavailable');
    jest
      .spyOn(sdk, 'getFeeDataWithDynamicMaxPriorityFeePerGas')
      .mockRejectedValue(error);
    await expect(sdk.getSafeFeeData()).rejects.toBe(error);
    expect(provider.getGasPrice).not.toHaveBeenCalled();
  });
});

describe('formatted standard transaction fee-model retention', () => {
  it('does not silently convert an explicit type-2 request through a legacy flag', async () => {
    const { sdk, getKey } = fixture();
    await expect(
      sdk.sendFormattedTransaction(
        {
          ...transaction,
          type: 2,
          maxFeePerGas: '100',
          maxPriorityFeePerGas: '0',
        } as any,
        true
      )
    ).rejects.toMatchObject({ transactionNotBroadcast: true });
    expect(getKey).not.toHaveBeenCalled();
    expect(localSend).not.toHaveBeenCalled();
  });
  it.each([0, '0x0', '0', BigNumber.from(0)])(
    'does not downgrade an explicit type-2 zero tip %p or fetch another price',
    async (zero) => {
      const { sdk, provider } = fixture();
      await expect(
        sdk.sendFormattedTransaction(
          {
            ...transaction,
            type: 2,
            maxFeePerGas: '100',
            maxPriorityFeePerGas: zero,
          } as any,
          false
        )
      ).resolves.toMatchObject({ hash: HASH });
      const sent = localSend.mock.calls[0][2];
      expect(sent.type).toBe(2);
      expect(BigNumber.from(sent.maxPriorityFeePerGas).isZero()).toBe(true);
      expect(BigNumber.from(sent.maxFeePerGas).toString()).toBe('100');
      expect(provider.getGasPrice).not.toHaveBeenCalled();
      expect(provider.getFeeData).not.toHaveBeenCalled();
    }
  );

  it.each([
    { maxFeePerGas: '0', maxPriorityFeePerGas: '0' },
    { maxFeePerGas: '-1', maxPriorityFeePerGas: '0' },
    { maxFeePerGas: '100', maxPriorityFeePerGas: '-1' },
    { maxFeePerGas: '100', maxPriorityFeePerGas: '101' },
  ])(
    'rejects invalid explicit EIP fees before key access or any signer/send: %p',
    async (fields) => {
      const { sdk, getKey } = fixture();
      await expect(
        sdk.sendFormattedTransaction(
          { ...transaction, type: 2, ...fields } as any,
          false
        )
      ).rejects.toMatchObject({ transactionNotBroadcast: true });
      expect(getKey).not.toHaveBeenCalled();
      expect(localSend).not.toHaveBeenCalled();
    }
  );

  it('refuses unavailable explicit EIP fees instead of silently falling back to legacy', async () => {
    const { sdk, provider, getKey } = fixture();
    provider.getFeeData.mockResolvedValue({
      gasPrice: BigNumber.from(7),
      maxFeePerGas: null,
      maxPriorityFeePerGas: null,
    } as any);
    await expect(
      sdk.sendFormattedTransaction({ ...transaction, type: 2 } as any, false)
    ).rejects.toMatchObject({ transactionNotBroadcast: true });
    expect(getKey).not.toHaveBeenCalled();
    expect(localSend).not.toHaveBeenCalled();
    expect(provider.getGasPrice).not.toHaveBeenCalled();
  });

  it.each([true, false])(
    'retains complete ordinary legacy=%s pricing',
    async (legacy) => {
      const { sdk, provider } = fixture();
      const fields = legacy
        ? { gasPrice: '7' }
        : { maxFeePerGas: '100', maxPriorityFeePerGas: '2' };
      await sdk.sendFormattedTransaction(
        { ...transaction, ...fields } as any,
        legacy
      );
      const sent = localSend.mock.calls[0][2];
      if (legacy) expect(BigNumber.from(sent.gasPrice).toString()).toBe('7');
      else
        expect(BigNumber.from(sent.maxPriorityFeePerGas).toString()).toBe('2');
      expect(provider.getGasPrice).not.toHaveBeenCalled();
      expect(provider.getFeeData).not.toHaveBeenCalled();
    }
  );
});
