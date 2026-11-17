import * as ecc from '@bitcoinerlab/secp256k1';
import { BIP32Factory } from 'bip32';
import { networks, payments } from 'bitcoinjs-lib';

import { KeyringAccountType } from '../../../src/types';
import { selectUtxoAddress } from '../../../src/utils/utxo-address-discovery';

import type { PsbtAccountScope } from '../../../src/utils/psbt-account-scope';

const root = BIP32Factory(ecc).fromSeed(Buffer.alloc(32, 17));
const node = root.derivePath("m/84'/0'/0'").neutered();
const derive = (index: number, branch: 0 | 1) => {
  const payment = payments.p2wpkh({
    pubkey: node.derive(branch).derive(index).publicKey,
    network: networks.bitcoin,
  });
  return {
    address: payment.address!,
    script: Buffer.from(payment.output!).toString('hex'),
  };
};
const scope: PsbtAccountScope = {
  account: { address: derive(0, 0).address, xpub: node.toBase58() },
  accountId: 0,
  accountType: KeyringAccountType.HDAccount,
  network: {
    kind: 'syscoin' as any,
    chainId: 0,
    slip44: 0,
    currency: 'btc',
    label: 'Bitcoin',
    url: 'https://offline.invalid',
  },
};
const token = (branch: 0 | 1, index: number) => ({
  name: derive(index, branch).address,
  transfers: 1,
  path: `m/84'/0'/0'/${branch}/${index}`,
});

it.each([
  [token(1, 1_000_000_000)],
  [token(1, 0), token(1, 20)],
  Array.from({ length: 4097 }, () => ({
    transfers: 1,
    path: "m/84'/0'/0'/1/1000000000",
  })),
])(
  'ignores backend allocation claims and keeps a first restored change output discoverable (%#)',
  (...tokens) => {
    const derivation = jest.fn(derive);
    const first = selectUtxoAddress(scope, tokens, 1, derivation);
    expect(first.state).toEqual({ receivingIndex: 0, changeIndex: 0 });
    expect(first.issued).toMatchObject({
      index: 0,
      path: "m/84'/0'/0'/1/0",
      address: derive(0, 1).address,
    });
    expect(derivation.mock.calls).toEqual([[0, 1]]);
    expect(selectUtxoAddress(scope, tokens, 1, derive, first.state)).toEqual(
      first
    );
  }
);

it('keeps ordinary address, key and path reads stable across arbitrary backend used lists', () => {
  const state = Object.freeze({ receivingIndex: 7, changeIndex: 4 });
  const tokens = Array.from({ length: 25 }, (_, index) => token(0, index));
  for (let i = 0; i < 3; i++) {
    expect(
      selectUtxoAddress(scope, tokens, 0, derive, state).issued.index
    ).toBe(7);
    expect(
      selectUtxoAddress(scope, tokens, 1, derive, state).issued.index
    ).toBe(4);
  }
  expect(state).toEqual({ receivingIndex: 7, changeIndex: 4 });
});

it('rotates only the current explicitly issued receive address, never on first bootstrap', () => {
  const tokens = [token(0, 0), token(0, 20)];
  const first = selectUtxoAddress(scope, tokens, 0, derive, undefined, true);
  expect(first.issued.index).toBe(0);
  const rotated = selectUtxoAddress(
    scope,
    tokens,
    0,
    derive,
    first.state,
    true
  );
  expect(rotated.issued.index).toBe(1);
  expect(
    selectUtxoAddress(scope, tokens, 0, derive, rotated.state, true)
  ).toEqual(rotated);
  expect(rotated.state.changeIndex).toBe(0);
});

it.each([
  "m/84'/0'/1'/0/0",
  "m/84'/1'/0'/0/0",
  "m/84'/0'/0'/0/1",
  "m/84'/0'/0'/0/00",
  "m/84'/0'/0'/0/0junk",
  "m/84'/0'/0'/0/0/1",
])(
  'rejects a false path for the exact current receive address during explicit rotation: %s',
  (path) => {
    expect(() =>
      selectUtxoAddress(
        scope,
        [{ ...token(0, 0), path }],
        0,
        derive,
        { receivingIndex: 0, changeIndex: 0 },
        true
      )
    ).toThrow();
  }
);

it('bounds explicit observation work and rejects corrupt owned state rather than resetting it', () => {
  expect(() =>
    selectUtxoAddress(scope, [], 1, derive, {
      receivingIndex: 0,
      changeIndex: -1,
    })
  ).toThrow();
  expect(() =>
    selectUtxoAddress(
      scope,
      Array.from({ length: 4097 }, () => ({})),
      0,
      derive,
      { receivingIndex: 0, changeIndex: 0 },
      true
    )
  ).toThrow();
  expect(() =>
    selectUtxoAddress(
      scope,
      [{ ...token(0, 0), transfers: '1junk' }],
      0,
      derive,
      { receivingIndex: 0, changeIndex: 0 },
      true
    )
  ).toThrow();
  expect(
    selectUtxoAddress(
      scope,
      [{ ...token(0, 0), transfers: '0' }],
      0,
      derive,
      { receivingIndex: 0, changeIndex: 0 },
      true
    ).issued.index
  ).toBe(0);
});

it('uses an imported account node rather than the wallet list slot for its canonical issued path', () => {
  const imported = root.derivePath("m/84'/0'/17'").neutered();
  const relative = (index: number, branch: 0 | 1) => {
    const payment = payments.p2wpkh({
      pubkey: imported.derive(branch).derive(index).publicKey,
    });
    return {
      address: payment.address!,
      script: Buffer.from(payment.output!).toString('hex'),
    };
  };
  const result = selectUtxoAddress(
    {
      ...scope,
      accountType: KeyringAccountType.Imported,
      accountId: 2,
      account: { address: relative(0, 0).address, xpub: imported.toBase58() },
    },
    undefined,
    1,
    relative
  );
  expect(result.issued.path).toBe("m/84'/0'/17'/1/0");
});
