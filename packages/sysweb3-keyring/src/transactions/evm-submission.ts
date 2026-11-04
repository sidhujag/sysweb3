import { Transaction } from 'ethers/transaction';

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

export type EvmSubmissionLifecycle = Readonly<{
  /** Synchronous host wallet/session/revision check, including A -> B -> A. */
  assertCurrent: () => void;
  /** Resolve only after durable acknowledgement. A rejection never dispatches. */
  persistSigned: (record: EvmSignedSubmission) => Promise<void>;
}>;
export type CaptureEvmSubmission = (
  context: EvmSubmissionContext
) => EvmSubmissionLifecycle;

export type EvmSubmissionBoundary = Readonly<{
  context: EvmSubmissionContext;
  assertCurrent: () => void;
  persistSigned?: (record: EvmSignedSubmission) => Promise<void>;
}>;

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
  capture?: CaptureEvmSubmission
): EvmSubmissionBoundary {
  const context: EvmSubmissionContext = Object.freeze({
    account: Object.freeze({ ...input.account }),
    network: Object.freeze({ ...input.network }),
    operation: input.operation,
    ...(input.originalHash !== undefined
      ? { originalHash: input.originalHash }
      : {}),
  });
  assertSynchronous(assertCurrent);
  if (capture !== undefined && typeof capture !== 'function') {
    throw new TypeError('Invalid EVM submission lifecycle factory');
  }
  const lifecycle = capture?.(context);
  const hostGuard = lifecycle?.assertCurrent;
  const persistSigned = lifecycle?.persistSigned;
  if (
    capture &&
    (!lifecycle ||
      typeof lifecycle !== 'object' ||
      typeof hostGuard !== 'function' ||
      typeof persistSigned !== 'function')
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
    if (hostGuard) assertSynchronous(hostGuard);
  };
  guard();
  return Object.freeze({
    context,
    assertCurrent: guard,
    ...(persistSigned ? { persistSigned } : {}),
  });
}

const failures = new WeakMap<
  object,
  Readonly<{
    transactionNotBroadcast: boolean;
    signedTransactionHash?: string;
  }>
>();

/** Only local stage evidence can label an error as a possibly dispatched send. */
export function evmSubmissionFailure(error: unknown): Readonly<{
  transactionNotBroadcast: boolean;
  signedTransactionHash?: string;
}> {
  return (
    (error && (typeof error === 'object' || typeof error === 'function')
      ? failures.get(error as object)
      : undefined) ?? { transactionNotBroadcast: true }
  );
}

/** Preserve local evidence when an existing public API wraps its Error object. */
export function copyEvmSubmissionFailure(source: unknown, target: Error): void {
  if (source && (typeof source === 'object' || typeof source === 'function')) {
    const failure = failures.get(source as object);
    if (failure) failures.set(target, failure);
  }
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

/** The sole local-signature dispatch boundary. No nonce/fee selection or retry. */
export async function submitSignedEvmTransaction<T>(
  rawTransaction: string,
  broadcast: (rawTransaction: string) => Promise<T>,
  boundary?: EvmSubmissionBoundary,
  beforeBroadcast?: () => void,
  expectedUnsignedTransaction?: string
): Promise<T> {
  let dispatched = false;
  let hash: string | undefined;
  try {
    // Public callers may supply a boundary object. Detach its data and function
    // references before awaiting storage, just as captureEvmSubmission does.
    const captured =
      boundary &&
      Object.freeze({
        context: Object.freeze({
          ...boundary.context,
          account: Object.freeze({ ...boundary.context.account }),
          network: Object.freeze({ ...boundary.context.network }),
        }),
        assertCurrent: boundary.assertCurrent,
        persistSigned: boundary.persistSigned,
      });
    const guard = () => {
      if (captured) assertSynchronous(captured.assertCurrent);
    };
    guard();
    const verified =
      expectedUnsignedTransaction === undefined
        ? undefined
        : assertSignedEvmTransactionMatches(
            rawTransaction,
            expectedUnsignedTransaction,
            captured?.context.account.address
          );
    if (captured) {
      if (typeof rawTransaction !== 'string')
        throw new TypeError('Signed EVM bytes must be a string');
      const tx = verified ?? Transaction.from(rawTransaction);
      if (
        !tx.isSigned() ||
        tx.serialized !== rawTransaction ||
        tx.from?.toLowerCase() !==
          captured.context.account.address.toLowerCase() ||
        tx.chainId !== BigInt(captured.context.network.chainId)
      ) {
        throw new Error(
          'Signed EVM submission does not match captured context'
        );
      }
      hash = tx.hash!;
      const record: EvmSignedSubmission = Object.freeze({
        context: captured.context,
        rawTransaction,
        hash,
        from: tx.from!,
        chainId: tx.chainId.toString(),
        nonce: tx.nonce,
        type: tx.type,
      });
      if (captured.persistSigned) {
        const acknowledgement = captured.persistSigned(record);
        if (!acknowledgement || typeof acknowledgement.then !== 'function') {
          throw new TypeError(
            'EVM signed persistence must return an acknowledgement Promise'
          );
        }
        await acknowledgement;
        guard();
      }
    }
    if (beforeBroadcast) assertSynchronous(beforeBroadcast);
    guard();
    dispatched = true;
    return await broadcast(rawTransaction);
  } catch (cause) {
    const failure = Object.freeze({
      transactionNotBroadcast: !dispatched,
      ...(hash ? { signedTransactionHash: hash } : {}),
    });
    // Preserve provider Error identity/class and its data/shortMessage/reason/
    // cause contract. Only the locally owned submission fields are overwritten.
    let error =
      cause instanceof Error
        ? cause
        : new Error(
            typeof cause === 'string' ? cause : 'EVM submission failed'
          );
    if (!(cause instanceof Error) && cause && typeof cause === 'object') {
      // JSON-RPC adapters can reject with a plain error object. Copy data
      // descriptors without invoking accessors or accepting its stage claim.
      for (const [key, descriptor] of Object.entries(
        Object.getOwnPropertyDescriptors(cause)
      )) {
        if (
          key !== 'transactionNotBroadcast' &&
          key !== 'signedTransactionHash' &&
          'value' in descriptor
        ) {
          Object.defineProperty(error, key, descriptor);
        }
      }
    }
    const stageDescriptors = Object.fromEntries(
      Object.entries({ ...failure, signedTransactionHash: hash }).map(
        ([key, value]) => [
          key,
          { value, enumerable: true, configurable: true, writable: true },
        ]
      )
    );
    try {
      Object.defineProperties(error, stageDescriptors);
    } catch {
      // A frozen provider Error may have non-configurable forged stage fields.
      // Retain its original details/cause without allowing those fields to win.
      const wrapped = new Error(error.message);
      wrapped.name = error.name;
      const descriptors = Object.getOwnPropertyDescriptors(error);
      delete descriptors.transactionNotBroadcast;
      delete descriptors.signedTransactionHash;
      Object.defineProperties(wrapped, descriptors);
      if (!Object.prototype.hasOwnProperty.call(wrapped, 'cause'))
        Object.defineProperty(wrapped, 'cause', {
          value: error,
          configurable: true,
        });
      Object.defineProperties(wrapped, stageDescriptors);
      error = wrapped;
    }
    failures.set(error, failure);
    throw error;
  }
}
