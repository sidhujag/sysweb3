import { KeyringAccountType } from '../types';
import { getAccountDerivationPath } from './derivation-paths';
import {
  createPsbtDerivationGuard,
  parsePsbtAccountXpub,
  type PsbtAccountScope,
} from './psbt-account-scope';

/** Current addresses, not a counter incremented by quotes or signing attempts. */
export type UtxoAddressDiscoveryState = Readonly<{
  receivingIndex: number;
  changeIndex: number;
}>;
export type UtxoIssuedAddress = Readonly<{
  branch: 0 | 1;
  index: number;
  address: string;
  path: string;
  script: string;
}>;
export type UtxoAddressSelection = Readonly<{
  state: UtxoAddressDiscoveryState;
  issued: UtxoIssuedAddress;
}>;
/** The wallet host commits public discovery metadata using its existing store. */
export type AllocateUtxoAddress = (
  select: (state: UtxoAddressDiscoveryState | undefined) => UtxoAddressSelection
) => Promise<UtxoIssuedAddress>;

const MAX_TOKENS = 4096;
const fail = (): never => {
  throw new Error('UTXO_ADDRESS_DISCOVERY_UNAVAILABLE');
};
const childIndex = (value: unknown): value is number =>
  Number.isSafeInteger(value) &&
  Number(value) >= 0 &&
  Number(value) < 0x80000000;

export function validUtxoAddressDiscoveryState(
  value: unknown
): value is UtxoAddressDiscoveryState {
  const state = value as UtxoAddressDiscoveryState | null;
  return Boolean(
    state &&
      Object.keys(state).length === 2 &&
      childIndex(state.receivingIndex) &&
      childIndex(state.changeIndex)
  );
}

/** Backend history cannot allocate an index. Older/seed-restored wallets reuse
 * child zero until locally retained signed history establishes an owned cursor.
 * Only deliberate receive rotation inspects usage of the current issued address;
 * that backend observation is not a proof of canonical confirmation.
 */
export function selectUtxoAddress(
  scope: PsbtAccountScope,
  tokens: unknown,
  branch: 0 | 1,
  derive: (index: number, branch: 0 | 1) => { address: string; script: string },
  state?: UtxoAddressDiscoveryState,
  rotateReceiving = false
): UtxoAddressSelection {
  if (state !== undefined && !validUtxoAddressDiscoveryState(state))
    return fail();
  const next = state ? { ...state } : { receivingIndex: 0, changeIndex: 0 };
  const node = parsePsbtAccountXpub(scope.account.xpub);
  const accountIndex =
    scope.accountType === KeyringAccountType.Imported && node.depth === 3
      ? node.index & 0x7fffffff
      : scope.accountId;
  const prefix = getAccountDerivationPath(
    scope.network.currency,
    scope.network.slip44,
    accountIndex
  );
  const guardPath = createPsbtDerivationGuard(scope);
  const issue = (index: number): UtxoIssuedAddress => {
    if (!childIndex(index)) return fail();
    const path = `${prefix}/${branch}/${index}`;
    if (guardPath(path) !== `${branch}/${index}`) return fail();
    return Object.freeze({ branch, index, path, ...derive(index, branch) });
  };
  let issued = issue(branch === 1 ? next.changeIndex : next.receivingIndex);
  if (state && rotateReceiving && branch === 0) {
    if (!Array.isArray(tokens) || tokens.length > MAX_TOKENS) return fail();
    let used = false;
    for (const token of tokens) {
      if (!token || token.name !== issued.address) continue;
      if (token.transfers === 0 || token.transfers === '0') continue;
      if (
        !['string', 'number'].includes(typeof token.transfers) ||
        !/^[1-9][0-9]{0,19}$/.test(String(token.transfers)) ||
        (typeof token.transfers === 'number' &&
          !Number.isSafeInteger(token.transfers)) ||
        typeof token.path !== 'string' ||
        guardPath(token.path) !== `0/${issued.index}`
      )
        return fail();
      used = true;
    }
    if (used) issued = issue(++next.receivingIndex);
  }
  return Object.freeze({ state: Object.freeze(next), issued });
}
