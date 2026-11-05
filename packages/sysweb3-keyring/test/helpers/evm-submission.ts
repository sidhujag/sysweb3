import {
  captureEvmSubmission,
  type EvmSignedSubmission,
  type EvmSubmissionContext,
} from '../../src/transactions/evm-submission';

export function createTestSubmissionCapture() {
  const retained = new Map<string, EvmSignedSubmission>();
  return () => ({
    assertCurrent: () => undefined,
    async persistSigned(record: EvmSignedSubmission) {
      retained.set(record.hash, record);
    },
  });
}

export function testSubmissionBoundary(
  address: string,
  chainId: number,
  assertCurrent = () => undefined
) {
  const context: EvmSubmissionContext = {
    account: { id: 0, type: 'HDAccount', address },
    network: {
      kind: 'ethereum',
      chainId,
      slip44: 60,
      url: 'https://fixture.invalid',
    },
    operation: 'send',
  };
  return captureEvmSubmission(
    context,
    assertCurrent,
    createTestSubmissionCapture()
  );
}
