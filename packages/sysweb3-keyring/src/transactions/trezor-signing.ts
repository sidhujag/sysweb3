import { getAddress } from 'ethers/address';
import { Signature } from 'ethers/crypto';
import { Transaction } from 'ethers/transaction';
import { toBeHex } from 'ethers/utils';

import { assertSignedEvmTransactionMatches } from './evm-submission';
import { annotateEvmSubmissionFailure } from './evm-submission-failure';
import { assertEvmGasLimit } from '../evm-fees';
import { captureHardwareTransactionAuthority } from '../hardware-transaction-authority';

import type { HardwareTransactionAuthority } from '../hardware-transaction-authority';
import type { TrezorKeyring } from '../trezor';
import type {
  EthereumTransaction,
  EthereumTransactionEIP1559,
} from '@trezor/connect-webextension';

// Connect returns hexadecimal fields, including an optionally numeric recovery v.
const trezorSignature = (signature: {
  r: string;
  s: string;
  v: string | number;
}) => {
  const { r, s, v } = signature;
  if (![r, s].every((value) => /^(?:0x)?[0-9a-f]{64}$/i.test(value)))
    throw new Error('Invalid Trezor signature scalar encoding');
  if (typeof v === 'string' && !/^(?:0x)?[0-9a-f]+$/i.test(v))
    throw new Error('Invalid Trezor signature recovery value');
  const recovery = typeof v === 'number' ? v : Number.parseInt(v, 16);
  if (!Number.isSafeInteger(recovery) || recovery < 0)
    throw new Error('Invalid Trezor signature recovery value');
  return Signature.from({
    r: `0x${r.replace(/^0x/i, '')}`,
    s: `0x${s.replace(/^0x/i, '')}`,
    v: recovery,
  });
};

/** Sign reviewed bytes through an explicitly hosted Trezor keyring. */
export async function signTrezorEvmTransaction(
  signer: Pick<TrezorKeyring, 'signEthTransaction'>,
  request: Readonly<{
    accountIndex: number;
    coin: string;
    expectedAddress: string;
    slip44: number;
    unsignedTransaction: string;
  }>,
  authority: HardwareTransactionAuthority
): Promise<Readonly<{ rawTransaction: string; hash: string }>> {
  try {
    const owner = captureHardwareTransactionAuthority(authority);
    const { accountIndex, coin, slip44, unsignedTransaction } = request;
    const expectedAddress = getAddress(request.expectedAddress);
    if (
      !Number.isSafeInteger(accountIndex) ||
      accountIndex < 0 ||
      accountIndex > 0x7fffffff ||
      !Number.isSafeInteger(slip44) ||
      slip44 < 0 ||
      slip44 > 0x7fffffff ||
      typeof coin !== 'string' ||
      coin.length === 0 ||
      typeof unsignedTransaction !== 'string'
    )
      throw new TypeError('Invalid reviewed Trezor transaction');
    const transaction = Transaction.from(unsignedTransaction);
    if (
      transaction.isSigned() ||
      transaction.chainId <= 0n ||
      transaction.chainId > BigInt(Number.MAX_SAFE_INTEGER) ||
      (transaction.type !== 0 && transaction.type !== 2) ||
      transaction.unsignedSerialized !== unsignedTransaction
    )
      throw new TypeError(
        'Trezor signing requires canonical unsigned type 0 or type 2 transaction bytes'
      );
    assertEvmGasLimit(transaction.gasLimit, transaction.chainId);
    const common = {
      to: transaction.to,
      value: toBeHex(transaction.value),
      gasLimit: toBeHex(transaction.gasLimit),
      nonce: toBeHex(transaction.nonce),
      data: transaction.data,
      chainId: Number(transaction.chainId),
    };
    const tx: EthereumTransaction | EthereumTransactionEIP1559 =
      transaction.type === 0
        ? { ...common, gasPrice: toBeHex(transaction.gasPrice!) }
        : {
            ...common,
            maxFeePerGas: toBeHex(transaction.maxFeePerGas!),
            maxPriorityFeePerGas: toBeHex(transaction.maxPriorityFeePerGas!),
            accessList: transaction.accessList!.map(
              ({ address, storageKeys }) => ({
                address,
                storageKeys: [...storageKeys],
              })
            ),
          };
    owner.assertCurrent();
    const signature = await signer.signEthTransaction(
      { index: String(accountIndex), coin, slip44, tx },
      owner
    );
    owner.assertCurrent();
    if (signature.success !== true)
      throw new Error('Transaction signature failed');
    transaction.signature = trezorSignature(signature.payload);
    const rawTransaction = transaction.serialized;
    if (transaction.from?.toLowerCase() !== expectedAddress.toLowerCase())
      throw Object.assign(
        new Error('Hardware signature does not match the approved account'),
        { code: 'HARDWARE_ACCOUNT_MISMATCH' }
      );
    const checked = assertSignedEvmTransactionMatches(
      rawTransaction,
      unsignedTransaction,
      expectedAddress
    );
    owner.assertCurrent();
    return Object.freeze({ rawTransaction, hash: checked.hash! });
  } catch (cause) {
    throw annotateEvmSubmissionFailure(cause, {
      transactionNotBroadcast: true,
    });
  }
}
