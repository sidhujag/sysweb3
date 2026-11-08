import { getAddress } from 'ethers/address';
import { keccak256 } from 'ethers/crypto';

import {
  prepareUnsignedEvmEnvelope,
  readEvmOwnData,
  snapshotPreparedEvmTransaction,
} from './evm-envelope';
import { signTransaction } from './evm-local-signer';
import { assertSignedEvmTransactionMatches } from './evm-submission';

import type { PreparedEvmTransaction } from './evm-envelope';

const invalid = () => new TypeError('Invalid prepared EVM signing request');

export type PreparedSoftwareEvmSigningRequest = Readonly<{
  account: Readonly<{
    id: number;
    type: 'HDAccount' | 'Imported';
    expectedAddress: string;
  }>;
  network: Readonly<{
    kind: 'ethereum';
    chainId: string;
    slip44: 60;
    /** Exact configured endpoint binding; signing does not contact or authenticate it. */
    url: string;
  }>;
  transaction: PreparedEvmTransaction;
}>;

export type PreparedEvmSigningOptions = Readonly<{
  /** Host-owned consent/session/review expiry check. Must return undefined. */
  assertCurrent(): void;
}>;

export type SignedPreparedEvmTransaction = Readonly<{
  rawTransaction: string;
  hash: string;
  unsignedHash: string;
  from: string;
  /** Canonical signed fields, checked against the requested envelope. */
  transaction: PreparedEvmTransaction;
}>;

export function snapshotPreparedEvmRequest(
  input: unknown
): PreparedSoftwareEvmSigningRequest {
  const root = readEvmOwnData(input, ['account', 'network', 'transaction']);
  const account = readEvmOwnData(root.account, [
    'id',
    'type',
    'expectedAddress',
  ]);
  if (
    !Number.isSafeInteger(account.id) ||
    (account.id as number) < 0 ||
    (account.id as number) > 0x7fffffff ||
    (account.type !== 'HDAccount' && account.type !== 'Imported')
  )
    throw invalid();
  const network = readEvmOwnData(root.network, [
    'kind',
    'chainId',
    'slip44',
    'url',
  ]);
  if (
    network.kind !== 'ethereum' ||
    network.slip44 !== 60 ||
    typeof network.url !== 'string' ||
    !network.url ||
    network.url.length > 4096 ||
    network.url.trim() !== network.url ||
    // eslint-disable-next-line no-control-regex -- Reject endpoint control characters and lone surrogates.
    /[\uD800-\uDFFF\u0000-\u001f\u007f]/u.test(network.url)
  )
    throw invalid();
  const transaction = snapshotPreparedEvmTransaction(root.transaction);
  if (
    typeof account.expectedAddress !== 'string' ||
    !/^0x[0-9a-fA-F]{40}$/.test(account.expectedAddress)
  )
    throw invalid();
  const expectedAddress = getAddress(account.expectedAddress);
  const chainId = transaction.chainId;
  if (transaction.from !== expectedAddress || network.chainId !== chainId)
    throw invalid();
  return Object.freeze({
    account: Object.freeze({
      id: account.id as number,
      type: account.type,
      expectedAddress,
    }),
    network: Object.freeze({
      kind: 'ethereum',
      chainId,
      slip44: 60,
      url: network.url,
    }),
    transaction,
  });
}

export function preparedEvmGuard(input: unknown): () => void {
  const options = readEvmOwnData(input, ['assertCurrent']);
  if (typeof options.assertCurrent !== 'function') throw invalid();
  const guard = options.assertCurrent;
  return () => {
    const result: unknown = guard();
    if (result !== undefined) {
      // Consume a rejected async guard without allowing it to authorize signing.
      if (
        result !== null &&
        (typeof result === 'object' || typeof result === 'function')
      )
        void Promise.resolve(result).catch(() => undefined);
      throw new TypeError(
        'Prepared EVM signing guard must return undefined synchronously'
      );
    }
  };
}

/** Internal, network-free signing. The key never becomes part of the result. */
export function signPreparedEvmEnvelope(
  input: PreparedEvmTransaction,
  privateKey: string
): Readonly<{
  signed: SignedPreparedEvmTransaction;
  expectedUnsigned: string;
}> {
  const { transaction, unsigned, expectedUnsigned } =
    prepareUnsignedEvmEnvelope(input);
  const rawTransaction = signTransaction(unsigned, privateKey);
  const signed = assertSignedEvmTransactionMatches(
    rawTransaction,
    expectedUnsigned,
    transaction.from
  );
  if (signed.hash !== keccak256(rawTransaction))
    throw new Error(
      'Prepared EVM signature does not match requested transaction'
    );
  return Object.freeze({
    expectedUnsigned,
    signed: Object.freeze({
      rawTransaction,
      hash: signed.hash!,
      unsignedHash: signed.unsignedHash,
      from: signed.from!,
      transaction,
    }),
  });
}
