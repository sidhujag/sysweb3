import ecc from '@bitcoinerlab/secp256k1';
import { Transaction, Wallet } from 'ethers';

import { BigNumber, serializeTransaction } from '../../../src/ethers-v6';
import { EvmGasLimitError } from '../../../src/evm-fees';
import { EthereumTransactions } from '../../../src/transactions/ethereum';
import { signTransaction } from '../../../src/transactions/evm-local-signer';
import { KeyringAccountType } from '../../../src/types';
import { createTestSubmissionCapture } from '../../helpers/evm-submission';

const specializedApproval = {
  mode: 'specialized' as const,
  assertCurrent: () => undefined,
};

const KEY = `0x${'11'.repeat(32)}`;
const wallet = new Wallet(KEY);
const to = `0x${'22'.repeat(20)}`;
const cap = 16777216n;
const customChain = 7654321;
const accessList = [{ address: to, storageKeys: [`0x${'00'.repeat(32)}`] }];

function fixture(kind: KeyringAccountType, chainId = 1) {
  const network = {
    kind: 'ethereum',
    chainId,
    slip44: 60,
    url: 'https://offline.invalid',
    currency: 'eth',
  } as any;
  const state = {
    activeAccountType: kind,
    activeAccountId: 0,
    activeNetwork: network,
    accounts: { [kind]: { 0: { id: 0, address: wallet.address } } },
  } as any;
  const getKey = jest.fn(() => ({
    address: wallet.address,
    decryptedPrivateKey: KEY,
  }));
  const device = jest.fn(async (tx: any) =>
    wallet.signingKey.sign(Transaction.from(tx).unsignedHash)
  );
  const ledger = {
    evm: {
      signEVMTransaction: jest.fn(async ({ rawTx }) => {
        const signature = await device(`0x${rawTx}`);
        return {
          r: signature.r.slice(2),
          s: signature.s.slice(2),
          v: signature.v.toString(16),
        };
      }),
    },
  } as any;
  const trezor = {
    signEthTransaction: jest.fn(async ({ tx }) => ({
      success: true,
      payload: await device(
        serializeTransaction({ ...tx, type: tx.gasPrice === undefined ? 2 : 0 })
      ),
    })),
  } as any;
  const sdk = new EthereumTransactions(
    () => network,
    getKey,
    () => state,
    ledger,
    trezor,
    undefined,
    createTestSubmissionCapture()
  );
  const provider = {
    verifyConfiguredChainId: jest.fn().mockResolvedValue(undefined),
    getTransactionCount: jest.fn().mockResolvedValue(7),
    getNetwork: jest.fn().mockResolvedValue({ chainId }),
    getFeeData: jest.fn().mockResolvedValue({
      gasPrice: BigNumber.from(2),
      maxFeePerGas: BigNumber.from(3),
      maxPriorityFeePerGas: BigNumber.from(1),
    }),
    getGasPrice: jest.fn().mockResolvedValue(BigNumber.from(2)),
    estimateGas: jest.fn().mockResolvedValue(BigNumber.from(21000)),
    sendTransaction: jest.fn(async (raw: string) => ({
      hash: Transaction.from(raw).hash,
    })),
  };
  Object.defineProperty(sdk, 'web3Provider', { get: () => provider });
  const request = (gasLimit: bigint, legacy: boolean) => ({
    from: wallet.address,
    to,
    value: '123',
    data: '0x',
    nonce: 7,
    chainId,
    gasLimit: gasLimit.toString(),
    ...(legacy
      ? { gasPrice: '2' }
      : { maxFeePerGas: '3', maxPriorityFeePerGas: '1' }),
  });
  return { sdk, provider, getKey, device, ledger, trezor, request };
}

describe('shared final EVM gas admission', () => {
  afterEach(() => jest.restoreAllMocks());

  for (const kind of [
    KeyringAccountType.HDAccount,
    KeyringAccountType.Imported,
    KeyringAccountType.Ledger,
    KeyringAccountType.Trezor,
  ]) {
    for (const legacy of [true, false]) {
      it(`${kind} type-${
        legacy ? 0 : 2
      } rejects supplied over-cap gas before key/device signing or broadcast`, async () => {
        const f = fixture(kind),
          sign = jest.spyOn(ecc, 'signRecoverable');
        await expect(
          f.sdk.sendFormattedTransaction(
            f.request(cap + 1n, legacy),
            legacy,
            specializedApproval
          )
        ).rejects.toMatchObject({
          code: 'SYSWEB3_EVM_GAS_LIMIT_EXCEEDED',
          transactionNotBroadcast: true,
        });
        expect(f.getKey).not.toHaveBeenCalled();
        expect(sign).not.toHaveBeenCalled();
        expect(f.device).not.toHaveBeenCalled();
        expect(f.provider.sendTransaction).not.toHaveBeenCalled();
        expect(f.provider.estimateGas).not.toHaveBeenCalled();
      });

      it(`${kind} type-${
        legacy ? 0 : 2
      } keeps exact-cap gas unchanged`, async () => {
        const f = fixture(kind);
        await f.sdk.sendFormattedTransaction(
          f.request(cap, legacy),
          legacy,
          specializedApproval
        );
        const signed = Transaction.from(
          f.provider.sendTransaction.mock.calls[0][0]
        );
        expect(signed.gasLimit).toBe(cap);
        expect(signed.from).toBe(wallet.address);
        expect(signed.to).toBe(to);
        expect(signed.value).toBe(123n);
        expect(signed.nonce).toBe(7);
      });

      it(`${kind} type-${
        legacy ? 0 : 2
      } does not invent the Ethereum cap on an unrelated configured chain`, async () => {
        const f = fixture(kind, customChain);
        await f.sdk.sendFormattedTransaction(
          f.request(cap + 1n, legacy),
          legacy,
          specializedApproval
        );
        const signed = Transaction.from(
          f.provider.sendTransaction.mock.calls[0][0]
        );
        expect(signed.chainId).toBe(BigInt(customChain));
        expect(signed.gasLimit).toBe(cap + 1n);
      });
    }
  }

  it.each([0, 1, 2])(
    'direct type-%s serialization rejects over-cap gas before ECC',
    (type) => {
      const sign = jest.spyOn(ecc, 'signRecoverable');
      expect(() =>
        signTransaction(
          {
            type,
            chainId: 1,
            gasLimit: cap + 1n,
            nonce: 0,
            to,
            ...(type === 2
              ? { maxFeePerGas: 3, maxPriorityFeePerGas: 1 }
              : { gasPrice: 2 }),
            ...(type === 1 ? { accessList } : {}),
          },
          KEY
        )
      ).toThrow(EvmGasLimitError);
      expect(sign).not.toHaveBeenCalled();
    }
  );

  it('preserves contract creation and EIP-2930 access-list serialization at the limit', () => {
    const creation = Transaction.from(
      signTransaction(
        {
          type: 2,
          chainId: 1,
          gasLimit: cap,
          nonce: 0,
          data: '0x6000',
          maxFeePerGas: 3,
          maxPriorityFeePerGas: 1,
        },
        KEY
      )
    );
    expect(creation.to).toBeNull();
    expect(creation.data).toBe('0x6000');
    expect(creation.gasLimit).toBe(cap);
    const listed = Transaction.from(
      signTransaction(
        {
          type: 1,
          chainId: 1,
          gasLimit: cap,
          nonce: 1,
          to,
          accessList,
          gasPrice: 2,
        },
        KEY
      )
    );
    expect(listed.type).toBe(1);
    expect(listed.accessList).toEqual(accessList);
    expect(listed.gasPrice).toBe(2n);
  });

  it('rejects a device-mutated over-cap envelope again before broadcast', async () => {
    const f = fixture(KeyringAccountType.Trezor);
    f.trezor.signEthTransaction.mockImplementationOnce(async ({ tx }: any) => {
      tx.gasLimit = `0x${(cap + 1n).toString(16)}`;
      return {
        success: true,
        payload: wallet.signingKey.sign(
          Transaction.from(serializeTransaction({ ...tx, type: 2 }))
            .unsignedHash
        ),
      };
    });
    await expect(
      f.sdk.sendFormattedTransaction(
        f.request(cap, false),
        false,
        specializedApproval
      )
    ).rejects.toMatchObject({ transactionNotBroadcast: true });
    expect(f.provider.sendTransaction).not.toHaveBeenCalled();
  });

  for (const kind of [KeyringAccountType.Ledger, KeyringAccountType.Trezor]) {
    for (const method of [
      'sendSignedErc20Transaction',
      'sendSignedErc721Transaction',
      'sendSignedErc1155Transaction',
    ] as const) {
      it(`${kind} ${method} applies the same supplied-gas limit before the device`, async () => {
        const f = fixture(kind);
        const request = {
          networkUrl: 'https://offline.invalid',
          receiver: to,
          tokenAddress: to,
          gasLimit: BigNumber.from((cap + 1n).toString()),
          gasPrice: BigNumber.from(2),
          isLegacy: true,
        };
        const sending =
          method === 'sendSignedErc20Transaction'
            ? f.sdk[method](
                { ...request, isLegacy: true, tokenAmountUnits: '1' },
                () => undefined
              )
            : f.sdk[method]({ ...request, tokenId: '1', tokenAmount: '1' });
        await expect(sending).rejects.toBeInstanceOf(EvmGasLimitError);
        expect(f.device).not.toHaveBeenCalled();
        expect(f.provider.sendTransaction).not.toHaveBeenCalled();
      });
    }
  }
});

it('pins an accessor gas limit before either unsigned or signed serialization', () => {
  let reads = 0;
  const tx: any = {
    type: 2,
    chainId: 1,
    to,
    nonce: 0,
    maxFeePerGas: 3,
    maxPriorityFeePerGas: 1,
  };
  Object.defineProperty(tx, 'gasLimit', {
    enumerable: true,
    get() {
      return reads++ === 0 ? cap : cap + 1n;
    },
  });
  const signed = Transaction.from(signTransaction(tx, KEY));
  expect(reads).toBe(1);
  expect(signed.gasLimit).toBe(cap);
  expect(signed.from).toBe(wallet.address);
});

it('pins an accessor chain ID to the same chain used for the gas decision', () => {
  let reads = 0;
  const tx: any = {
    type: 2,
    gasLimit: cap + 1n,
    to,
    nonce: 0,
    maxFeePerGas: 3,
    maxPriorityFeePerGas: 1,
  };
  Object.defineProperty(tx, 'chainId', {
    enumerable: true,
    get() {
      return reads++ === 0 ? customChain : 1;
    },
  });
  const signed = Transaction.from(signTransaction(tx, KEY));
  expect(reads).toBe(1);
  expect(signed.chainId).toBe(BigInt(customChain));
  expect(signed.gasLimit).toBe(cap + 1n);
  expect(signed.from).toBe(wallet.address);
});

it('converts mutable BigNumberish gas and chain fields to checked immutable scalars', () => {
  let gasReads = 0,
    chainReads = 0;
  const gas = {
    get _hex() {
      return `0x${(gasReads++ === 0 ? cap : cap + 1n).toString(16)}`;
    },
  };
  const chain = {
    get _hex() {
      return `0x${(chainReads++ === 0 ? 1 : customChain).toString(16)}`;
    },
  };
  const signed = Transaction.from(
    signTransaction(
      {
        type: 0,
        to,
        nonce: 0,
        gasLimit: gas,
        chainId: chain,
        gasPrice: 2,
      } as any,
      KEY
    )
  );
  expect(gasReads).toBe(1);
  expect(chainReads).toBe(1);
  expect(signed.gasLimit).toBe(cap);
  expect(signed.chainId).toBe(1n);
  expect(signed.from).toBe(wallet.address);
});

it('preserves omitted-chain legacy serialization instead of inserting a network default', () => {
  const signed = Transaction.from(
    signTransaction(
      { type: 0, to, nonce: 0, gasLimit: 21000, gasPrice: 2 },
      KEY
    )
  );
  expect(signed.chainId).toBe(0n);
  expect(signed.from).toBe(wallet.address);
});

it('bounds gas text before numeric normalization or cryptography', () => {
  const bigint = jest.spyOn(globalThis, 'BigInt');
  try {
    expect(() =>
      signTransaction(
        {
          type: 0,
          chainId: 1,
          to,
          nonce: 0,
          gasLimit: '9'.repeat(10000),
          gasPrice: 2,
        },
        KEY
      )
    ).toThrow('Invalid gas limit');
    expect(bigint).not.toHaveBeenCalled();
  } finally {
    bigint.mockRestore();
  }
});
