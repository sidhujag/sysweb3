type EvmSubmissionFailure = Readonly<{
  transactionNotBroadcast: boolean;
  signedTransactionHash?: string;
}>;

const failures = new WeakMap<object, EvmSubmissionFailure>();

/** Return owned stage evidence only; unrecognized errors carry no classification. */
export function evmSubmissionFailure(
  error: unknown
): EvmSubmissionFailure | undefined {
  return error && (typeof error === 'object' || typeof error === 'function')
    ? failures.get(error as object)
    : undefined;
}

/** Preserve local evidence when an existing public API wraps its Error object. */
export function copyEvmSubmissionFailure(source: unknown, target: Error): void {
  if (source && (typeof source === 'object' || typeof source === 'function')) {
    const failure = failures.get(source as object);
    if (failure) failures.set(target, failure);
  }
}

/** Internal callers supply observed stage facts, never provider error fields. */
export function annotateEvmSubmissionFailure(
  cause: unknown,
  observed: EvmSubmissionFailure
): Error {
  const failure = Object.freeze({
    transactionNotBroadcast: observed.transactionNotBroadcast,
    ...(observed.signedTransactionHash
      ? { signedTransactionHash: observed.signedTransactionHash }
      : {}),
  });
  // Preserve provider Error identity/class and its data/shortMessage/reason/
  // cause contract. Only the locally owned submission fields are overwritten.
  let error =
    cause instanceof Error
      ? cause
      : new Error(typeof cause === 'string' ? cause : 'EVM submission failed');
  if (!(cause instanceof Error) && cause && typeof cause === 'object') {
    // Copy data descriptors without invoking accessors or accepting stage claims.
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
    Object.entries({
      ...failure,
      signedTransactionHash: failure.signedTransactionHash,
    }).map(([key, value]) => [
      key,
      { value, enumerable: true, configurable: true, writable: true },
    ])
  );
  try {
    Object.defineProperties(error, stageDescriptors);
  } catch {
    // A frozen provider Error can contain non-configurable forged stage fields.
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
  return error;
}
