import type { EvmSigningIdentity } from '../../src/transactions/prepared-evm';

/** Bind unit-test sends to their fixture's selected account unless a test supplies explicit identities. */
export function withEvmSendIdentity<T>(
  sdk: unknown,
  options: T
): T & {
  selectedAccount: EvmSigningIdentity;
  targetAccount: EvmSigningIdentity;
} {
  const state = (sdk as { getState(): any }).getState();
  const selected = {
    id: state.activeAccountId,
    type: state.activeAccountType,
    expectedAddress:
      state.accounts[state.activeAccountType][state.activeAccountId].address,
  };
  return { selectedAccount: selected, targetAccount: selected, ...options };
}
