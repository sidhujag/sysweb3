import { getAddress } from 'ethers/address';
import { Signature } from 'ethers/crypto';
import { Transaction } from 'ethers/transaction';

import { assertSignedEvmTransactionMatches } from './evm-submission';
import { annotateEvmSubmissionFailure } from './evm-submission-failure';
import { captureHardwareTransactionAuthority } from '../hardware-transaction-authority';

import type { HardwareTransactionAuthority } from '../hardware-transaction-authority';
import type { IEvmMethods } from '../ledger/types';

/** Sign the reviewed bytes through the shared Ledger adapter without changing fees or nonce. */
export async function signLedgerEvmTransaction(
  signer: { evm: Pick<IEvmMethods, 'signEVMTransaction'> },
  request: Readonly<{
    accountIndex: number;
    expectedAddress: string;
    unsignedTransaction: string;
  }>,
  authority: HardwareTransactionAuthority
): Promise<Readonly<{ rawTransaction: string; hash: string }>> {
  try {
    const owner = captureHardwareTransactionAuthority(authority);
    const { accountIndex, unsignedTransaction } = request;
    const expectedAddress = getAddress(request.expectedAddress);
    if (
      !Number.isSafeInteger(accountIndex) ||
      accountIndex < 0 ||
      accountIndex > 0x7fffffff ||
      typeof unsignedTransaction !== 'string'
    )
      throw new TypeError('Invalid reviewed Ledger transaction');
    const transaction = Transaction.from(unsignedTransaction);
    if (
      transaction.isSigned() ||
      transaction.chainId <= 0n ||
      transaction.unsignedSerialized !== unsignedTransaction
    )
      throw new TypeError(
        'Ledger signing requires canonical unsigned transaction bytes'
      );
    owner.assertCurrent();
    const signature = await signer.evm.signEVMTransaction(
      {
        accountIndex,
        expectedAddress,
        rawTx: unsignedTransaction.slice(2),
      },
      owner
    );
    owner.assertCurrent();
    transaction.signature = Signature.from({
      r: `0x${signature.r}`,
      s: `0x${signature.s}`,
      v: Number.parseInt(signature.v, 16),
    });
    const rawTransaction = transaction.serialized;
    if (transaction.from?.toLowerCase() !== expectedAddress.toLowerCase()) {
      throw Object.assign(
        new Error('Hardware signature does not match the approved account'),
        { code: 'HARDWARE_ACCOUNT_MISMATCH' }
      );
    }
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
