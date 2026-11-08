export type HardwareTransactionAuthority = Readonly<{
  assertCurrent: () => void;
  signal: AbortSignal;
}>;

const retiredApproval = () =>
  Object.assign(new Error('Hardware signing approval is no longer current'), {
    name: 'AbortError',
    code: 'HARDWARE_REQUEST_CANCELLED',
    transactionNotBroadcast: true,
  });

export function assertHardwareOperationCurrent(check: () => void): void {
  let result: unknown;
  try {
    result = check();
  } catch {
    throw retiredApproval();
  }
  if (result !== undefined) {
    void Promise.resolve(result).catch(() => undefined);
    throw retiredApproval();
  }
}

export function captureHardwareTransactionAuthority(
  authority: HardwareTransactionAuthority
): HardwareTransactionAuthority {
  const { assertCurrent: check, signal } = authority ?? {};
  if (
    typeof check !== 'function' ||
    typeof signal?.aborted !== 'boolean' ||
    typeof signal.addEventListener !== 'function' ||
    typeof signal.removeEventListener !== 'function'
  )
    throw retiredApproval();

  const assertCurrent = () => {
    if (signal.aborted) throw retiredApproval();
    assertHardwareOperationCurrent(check);
    if (signal.aborted) throw retiredApproval();
  };
  assertCurrent();
  return Object.freeze({ assertCurrent, signal });
}
