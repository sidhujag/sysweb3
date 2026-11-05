import * as syscoinjs from 'syscoinjs-lib';

import { fetchOwnedBlockbookAccount } from '../../../src/utils/owned-blockbook-account';
import { ownedUtxoTestRead } from '../../helpers/utxoAuthority';

const backend = 'https://blockbook.example';
const xpub = 'zpub-fixture';
const requestAccount = jest.mocked(syscoinjs.utils.fetchBackendAccount);

beforeEach(() => {
  requestAccount.mockClear();
});

it('rejects missing ownership before invoking SyscoinJS', () => {
  expect(() =>
    Reflect.apply(fetchOwnedBlockbookAccount, undefined, [backend, xpub])
  ).toThrow('Missing owned Blockbook account transport');
  expect(requestAccount).not.toHaveBeenCalled();
});

it('keeps identical account reads on independent host transports', async () => {
  const first = ownedUtxoTestRead();
  const second = ownedUtxoTestRead();
  await Promise.all([
    fetchOwnedBlockbookAccount(backend, xpub, first),
    fetchOwnedBlockbookAccount(backend, xpub, second),
  ]);
  expect(requestAccount.mock.calls).toEqual([
    [backend, xpub, 'tokens=used&details=tokens', true, undefined, first],
    [backend, xpub, 'tokens=used&details=tokens', true, undefined, second],
  ]);
});
