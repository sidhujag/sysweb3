import { Transaction } from 'ethers/transaction';

import { readEvmOwnData } from './evm-envelope';
import { annotateEvmSubmissionFailure } from './evm-submission-failure';

export {
  copyEvmSubmissionFailure,
  evmSubmissionFailure,
} from './evm-submission-failure';

import type {
  EvmRetainedCancellationOrigin,
  EvmWalletNonce,
  KeyringAccountType,
} from '../types';

export type EvmSubmissionContext = Readonly<{
  account: Readonly<{ id: number; type: string; address: string }>;
  network: Readonly<{
    kind: string;
    chainId: number;
    slip44: number;
    url: string;
  }>;
  operation: 'send' | 'cancel' | 'speed-up' | 'erc20' | 'erc721' | 'erc1155';
  originalHash?: string;
  origin?: EvmRetainedCancellationOrigin;
  /** Transient identity of the live host fee review, bound to these signed bytes. */
  review?: Readonly<{ id: string; unsignedHash: string }>;
  walletNonce?: EvmWalletNonce;
}>;

/** Signed wire bytes only; never a key, password or mutable transaction request. */
export type EvmSignedSubmission = Readonly<{
  context: EvmSubmissionContext;
  rawTransaction: string;
  hash: string;
  from: string;
  chainId: string;
  nonce: number;
  type: number | null;
}>;

/** The transport calls this after preflight, immediately around synchronous wire initiation. */
export type AdmitEvmSignedDispatch<T> = (
  initiate: () => Promise<T>,
  preflight?: () => Promise<void>
) => Promise<T>;
export type EvmSignedBroadcast<T> = (
  request: Readonly<{
    rawTransaction: string;
    admit: AdmitEvmSignedDispatch<T>;
  }>
) => Promise<T>;

export type EvmSubmissionLifecycle = Readonly<{
  /** Synchronous host wallet/session/revision check, including A -> B -> A. */
  assertCurrent: () => void;
  /** Resolve only after durable acknowledgement. A rejection never dispatches. */
  persistSigned: (record: EvmSignedSubmission) => Promise<void>;
  /** Admit the exact retained record, releasing the owner before the remote response. */
  dispatchSigned: <T>(
    record: EvmSignedSubmission,
    initiate: () => Promise<T>,
    preflight: () => Promise<void>
  ) => Promise<T>;
}>;
export type CaptureEvmSubmission = (
  context: EvmSubmissionContext
) => EvmSubmissionLifecycle;

declare const evmSubmissionBrand: unique symbol;
export type EvmSubmissionBoundary = Readonly<{
  [evmSubmissionBrand]: true;
  context: EvmSubmissionContext;
  assertCurrent: () => void;
  persistSigned: (record: EvmSignedSubmission) => Promise<void>;
  dispatchSigned: EvmSubmissionLifecycle['dispatchSigned'];
}>;

const capturedBoundaries = new WeakSet<EvmSubmissionBoundary>();

function assertSynchronous(check: () => void): void {
  const result: unknown = check();
  if (result !== undefined) {
    if (
      result &&
      (typeof result === 'object' || typeof result === 'function')
    ) {
      void Promise.resolve(result).catch(() => undefined);
    }
    throw new Error('EVM submission guard must return undefined synchronously');
  }
}

/** Capture once, before RPC or device work. Never reread host capabilities later. */
export function captureEvmSubmission(
  input: EvmSubmissionContext,
  assertCurrent: () => void,
  capture: CaptureEvmSubmission
): EvmSubmissionBoundary {
  const { origin, walletNonce } = input;
  const inputReview = input.review;
  const review =
    inputReview === undefined
      ? undefined
      : readEvmOwnData(inputReview, ['id', 'unsignedHash']);
  if (
    review !== undefined &&
    (input.operation !== 'send' ||
      !walletNonce ||
      !review ||
      typeof review.id !== 'string' ||
      !/^[A-Za-z0-9_-]{1,128}$/.test(review.id) ||
      typeof review.unsignedHash !== 'string' ||
      !/^0x[0-9a-f]{64}$/.test(review.unsignedHash))
  )
    throw new TypeError('Invalid EVM fee review identity');
  let approvedWalletNonce: EvmWalletNonce | undefined;
  if (walletNonce !== undefined) {
    if (
      !walletNonce ||
      typeof walletNonce !== 'object' ||
      Array.isArray(walletNonce)
    )
      throw new TypeError('Invalid wallet EVM nonce approval');
    const { nonce, source } = walletNonce;
    if (
      !Number.isSafeInteger(nonce) ||
      nonce < 0 ||
      (source !== 'automatic' && source !== 'manual')
    )
      throw new TypeError('Invalid wallet EVM nonce approval');
    approvedWalletNonce = Object.freeze({ nonce, source });
  }
  const context: EvmSubmissionContext = Object.freeze({
    account: Object.freeze({ ...input.account }),
    network: Object.freeze({ ...input.network }),
    operation: input.operation,
    ...(review
      ? {
          review: Object.freeze({
            id: review.id as string,
            unsignedHash: review.unsignedHash as string,
          }),
        }
      : {}),
    ...(approvedWalletNonce ? { walletNonce: approvedWalletNonce } : {}),
    ...(input.originalHash !== undefined
      ? { originalHash: input.originalHash }
      : {}),
    ...(origin
      ? {
          origin: Object.freeze({
            ...origin,
            feeFloor: Object.freeze({ ...origin.feeFloor }),
          }),
        }
      : {}),
  });
  assertSynchronous(assertCurrent);
  if (typeof capture !== 'function')
    throw new TypeError('A durable EVM submission lifecycle is required');
  const lifecycle = capture(context);
  const hostGuard = lifecycle?.assertCurrent;
  const persistSigned = lifecycle?.persistSigned;
  const dispatchSigned = lifecycle?.dispatchSigned;
  if (
    !lifecycle ||
    typeof lifecycle !== 'object' ||
    typeof hostGuard !== 'function' ||
    typeof persistSigned !== 'function' ||
    typeof dispatchSigned !== 'function'
  ) {
    if (lifecycle && typeof (lifecycle as any).then === 'function') {
      void Promise.resolve(lifecycle).catch(() => undefined);
    }
    throw new TypeError(
      'EVM submission lifecycle must be captured synchronously'
    );
  }
  const guard = () => {
    assertSynchronous(assertCurrent);
    assertSynchronous(hostGuard);
  };
  guard();
  const boundary = Object.freeze({
    context,
    assertCurrent: guard,
    persistSigned: (record: EvmSignedSubmission) => {
      if (
        context.review &&
        Transaction.from(record.rawTransaction).unsignedHash !==
          context.review.unsignedHash
      )
        throw new Error('Signed EVM transaction does not match its fee review');
      return persistSigned(record);
    },
    dispatchSigned,
  }) as EvmSubmissionBoundary;
  capturedBoundaries.add(boundary);
  return boundary;
}

/** Refuse any new signature or dispatch without a captured durable port. */
export function assertDurableEvmSubmission(
  boundary: EvmSubmissionBoundary
): void {
  if (!capturedBoundaries.has(boundary))
    throw new TypeError('A captured durable EVM submission is required');
  boundary.assertCurrent();
}

/** Compare signed wire bytes with the complete envelope captured before signing. */
export function assertSignedEvmTransactionMatches(
  rawTransaction: string,
  expectedUnsignedTransaction: string,
  expectedFrom?: string
): Transaction {
  if (
    typeof rawTransaction !== 'string' ||
    typeof expectedUnsignedTransaction !== 'string'
  )
    throw new TypeError('EVM transaction bytes must be strings');
  const expected = Transaction.from(expectedUnsignedTransaction);
  const signed = Transaction.from(rawTransaction);
  if (
    expected.isSigned() ||
    expected.unsignedSerialized !== expectedUnsignedTransaction ||
    !signed.isSigned() ||
    signed.serialized !== rawTransaction ||
    signed.unsignedSerialized !== expectedUnsignedTransaction ||
    (expectedFrom !== undefined &&
      signed.from?.toLowerCase() !== expectedFrom.toLowerCase())
  )
    throw new Error(
      'Signed EVM transaction does not match expected unsigned envelope'
    );
  return signed;
}

/** Submit software-signed bytes through the captured durable boundary. */
export function submitSignedEvmTransaction<T>(
  rawTransaction: string,
  broadcast: EvmSignedBroadcast<T>,
  boundary: EvmSubmissionBoundary,
  beforeBroadcast: (() => void) | undefined,
  expectedUnsignedTransaction: string
): Promise<T> {
  return submit(
    rawTransaction,
    broadcast,
    boundary,
    beforeBroadcast,
    expectedUnsignedTransaction,
    { mode: 'software' }
  );
}

/** @internal Device signatures always require a fresh live chain probe after persistence. */
export function submitSignedHardwareEvmTransaction<T>(
  rawTransaction: string,
  broadcast: EvmSignedBroadcast<T>,
  boundary: EvmSubmissionBoundary,
  beforeBroadcast: (() => void) | undefined,
  expectedUnsignedTransaction: string,
  verifyCurrentChain: () => Promise<void>
): Promise<T> {
  return submit(
    rawTransaction,
    broadcast,
    boundary,
    beforeBroadcast,
    expectedUnsignedTransaction,
    { mode: 'hardware', verifyCurrentChain }
  );
}

const hardwareAccountTypes = ['Ledger', 'Trezor'] satisfies readonly `${
  | KeyringAccountType.Ledger
  | KeyringAccountType.Trezor}`[];

/** The common signed-byte dispatch boundary. No nonce/fee selection or retry. */
async function submit<T>(
  rawTransaction: string,
  broadcast: EvmSignedBroadcast<T>,
  boundary: EvmSubmissionBoundary,
  beforeBroadcast: (() => void) | undefined,
  expectedUnsignedTransaction: string,
  admission:
    | { mode: 'software' }
    | { mode: 'hardware'; verifyCurrentChain: () => Promise<void> }
): Promise<T> {
  let dispatched = false;
  let hash: string | undefined;
  try {
    const check = () => assertDurableEvmSubmission(boundary);
    check();
    const hardwareAccount = hardwareAccountTypes.some(
      (type) => type === boundary.context.account.type
    );
    if (
      hardwareAccount !== (admission.mode === 'hardware') ||
      (admission.mode === 'hardware' &&
        typeof admission.verifyCurrentChain !== 'function')
    )
      throw new TypeError('EVM submission does not match the signing mode');
    const tx = assertSignedEvmTransactionMatches(
      rawTransaction,
      expectedUnsignedTransaction,
      boundary.context.account.address
    );
    if (tx.chainId !== BigInt(boundary.context.network.chainId))
      throw new Error('Signed EVM submission does not match captured context');
    const approvedNonce = boundary.context.walletNonce?.nonce;
    if (approvedNonce !== undefined && tx.nonce !== approvedNonce)
      throw new Error('Signed EVM nonce does not match wallet approval');
    hash = tx.hash!;
    const record: EvmSignedSubmission = Object.freeze({
      context: boundary.context,
      rawTransaction,
      hash,
      from: tx.from!,
      chainId: tx.chainId.toString(),
      nonce: tx.nonce,
      type: tx.type,
    });
    const acknowledgement = boundary.persistSigned(record);
    if (!acknowledgement || typeof acknowledgement.then !== 'function')
      throw new TypeError(
        'EVM signed persistence must return an acknowledgement Promise'
      );
    await acknowledgement;
    check();
    let open = true;
    let requested = false;
    const assertDispatchOpen = () => {
      if (!open || dispatched)
        throw new Error('Invalid EVM dispatch admission');
      check();
    };
    try {
      const result = await broadcast(
        Object.freeze({
          rawTransaction,
          admit: (
            initiate: () => Promise<T>,
            preflight?: () => Promise<void>
          ) => {
            if (
              !open ||
              requested ||
              typeof initiate !== 'function' ||
              (preflight !== undefined && typeof preflight !== 'function')
            )
              throw new Error('Invalid EVM dispatch admission');
            requested = true;
            let preflightStarted = false;
            let preflightComplete = false;
            return boundary.dispatchSigned(
              record,
              () => {
                assertDispatchOpen();
                if (!preflightComplete)
                  throw new Error('EVM dispatch preflight was not completed');
                if (beforeBroadcast) assertSynchronous(beforeBroadcast);
                check();
                dispatched = true;
                return initiate();
              },
              async () => {
                assertDispatchOpen();
                if (preflightStarted)
                  throw new Error('EVM dispatch preflight already started');
                preflightStarted = true;
                if (admission.mode === 'hardware')
                  await admission.verifyCurrentChain();
                assertDispatchOpen();
                if (preflight) await preflight();
                assertDispatchOpen();
                preflightComplete = true;
              }
            );
          },
        })
      );
      if (!dispatched) throw new Error('EVM dispatch admission was not used');
      return result;
    } finally {
      open = false;
    }
  } catch (cause) {
    throw annotateEvmSubmissionFailure(cause, {
      transactionNotBroadcast: !dispatched,
      ...(hash ? { signedTransactionHash: hash } : {}),
    });
  }
}
