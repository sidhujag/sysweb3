import { getNetworkConfig, INetworkType } from '@sidhujag/sysweb3-network';
import { Psbt, Transaction, payments } from 'bitcoinjs-lib';
import CryptoJS from 'crypto-js';

import { KeyringManager } from '../../../src/keyring-manager';
import { SyscoinTransactions } from '../../../src/transactions/syscoin';
import { KeyringAccountType } from '../../../src/types';
import { PsbtUtils } from '../../../src/utils/psbt';
import { assertPsbtAccountScope } from '../../../src/utils/psbt-account-scope';

jest.mock('../../../src/utils/blockbook-cache', () => ({
  fetchBackendAccountCached: jest.fn().mockResolvedValue({ tokens: [] }),
}));

const network = {
  kind: INetworkType.Syscoin,
  chainId: 5700,
  slip44: 1,
  currency: 'tSYS',
  url: 'https://offline.invalid',
} as any;
const config = getNetworkConfig(1, 'tSYS');
const bitcoinNetwork = config.networks.testnet;
const fixture = () => {
  const syscoinjs = jest.requireActual('syscoinjs-lib');
  const hd = new syscoinjs.utils.HDSigner(
    'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
    null,
    true,
    config.networks,
    1,
    config.types.zPubType,
    84
  );
  hd.createAccountAtIndex(0, 84);
  const root = hd.getRootNode();
  const paths = ["m/84'/1'/0'/0/0", "m/84'/1'/1'/0/0"];
  const children = paths.map((path) => root.derivePath(path));
  const account = {
    id: 0,
    address: payments.p2wpkh({
      pubkey: children[0].publicKey,
      network: bitcoinNetwork,
    }).address!,
    xpub: hd.getAccountXpub(),
  };
  const state = {
    activeNetwork: network,
    activeAccountId: 0,
    activeAccountType: KeyringAccountType.HDAccount,
    accounts: {
      HDAccount: { 0: account },
      Imported: {},
      Ledger: {},
      Trezor: {},
    },
  };
  const makePsbt = (indices: number[], forgedAddress = false) => {
    const previous = new Transaction();
    previous.addInput(Buffer.alloc(32), 0xffffffff);
    children.forEach((child) =>
      previous.addOutput(
        payments.p2wpkh({ pubkey: child.publicKey, network: bitcoinNetwork })
          .output!,
        100000n
      )
    );
    const psbt = new Psbt({ network: bitcoinNetwork });
    indices.forEach((index) => {
      psbt.addInput({
        hash: previous.getId(),
        index,
        nonWitnessUtxo: previous.toBuffer(),
        bip32Derivation: [
          {
            masterFingerprint: root.fingerprint,
            path: paths[index],
            pubkey: children[index].publicKey,
          },
        ],
      });
      if (forgedAddress)
        psbt.addUnknownKeyValToInput(psbt.inputCount - 1, {
          key: Buffer.from('address'),
          value: Buffer.from(account.address),
        });
    });
    psbt.addOutput({
      address: account.address,
      value: BigInt(indices.length) * 100000n - 1000n,
    });
    return psbt;
  };
  const tx = new SyscoinTransactions(
    () => ({ hd, main: {} }),
    () => ({ main: {} }),
    () => state,
    jest.fn(),
    {} as any,
    {} as any
  );
  return { tx, hd, state, account, makePsbt, root, children, paths };
};

const multisigFixture = (type: string, sameWallet = false) => {
  const base = fixture();
  const actual = jest.requireActual('syscoinjs-lib');
  const external = new actual.utils.HDSigner(
    'legal winner thank year wave sausage worth useful legal winner thank yellow',
    null,
    true,
    config.networks,
    1,
    config.types.zPubType,
    84
  );
  const cosignerRoot = sameWallet ? base.root : external.getRootNode();
  const cosignerPath = sameWallet ? base.paths[1] : "m/84'/1'/3'/1/5";
  const cosigner = cosignerRoot.derivePath(cosignerPath);
  const multisig = payments.p2ms({
    m: 2,
    pubkeys: [base.children[0].publicKey, cosigner.publicKey],
    network: bitcoinNetwork,
  });
  const witness = payments.p2wsh({ redeem: multisig, network: bitcoinNetwork });
  const payment =
    type === 'p2wsh'
      ? witness
      : payments.p2sh({
          redeem: type === 'p2sh' ? multisig : witness,
          network: bitcoinNetwork,
        });
  const previous = new Transaction();
  previous.addInput(Buffer.alloc(32), 0xffffffff);
  previous.addOutput(payment.output!, 100000n);
  const psbt = new Psbt({ network: bitcoinNetwork });
  psbt.addInput({
    hash: previous.getId(),
    index: 0,
    nonWitnessUtxo: previous.toBuffer(),
    ...(type === 'p2sh'
      ? { redeemScript: multisig.output }
      : {
          witnessScript: multisig.output,
          ...(type === 'p2sh-p2wsh' ? { redeemScript: witness.output } : {}),
        }),
    bip32Derivation: [
      {
        masterFingerprint: base.root.fingerprint,
        path: base.paths[0],
        pubkey: base.children[0].publicKey,
      },
      {
        masterFingerprint: cosignerRoot.fingerprint,
        path: cosignerPath,
        pubkey: cosigner.publicKey,
      },
    ],
  });
  psbt.addOutput({ address: base.account.address, value: 99000n });
  return { ...base, psbt, cosigner, cosignerRoot };
};

describe('PSBT approved-account boundary with the real HD signer', () => {
  it.each(['p2wsh', 'p2sh-p2wsh', 'p2sh'])(
    'signs only the approved key in standard %s multisig',
    async (type) => {
      const { tx, psbt, children } = multisigFixture(type);
      const signed = PsbtUtils.fromPali(
        await tx.signPSBT({ psbt: PsbtUtils.toPali(psbt) }),
        network
      );
      expect(signed.data.inputs[0].partialSig).toHaveLength(1);
      expect(Buffer.from(signed.data.inputs[0].partialSig![0].pubkey)).toEqual(
        Buffer.from(children[0].publicKey)
      );
      expect(
        signed.validateSignaturesOfInput(0, (publicKey, hash, signature) =>
          require('@bitcoinerlab/secp256k1').verify(hash, publicKey, signature)
        )
      ).toBe(true);
      expect(signed.data.inputs[0].bip32Derivation).toHaveLength(2);
    }
  );

  it('never signs another account of the same wallet in a shared multisig input', async () => {
    const { tx, psbt, children, paths } = multisigFixture('p2wsh', true);
    const signed = PsbtUtils.fromPali(
      await tx.signPSBT({ psbt: PsbtUtils.toPali(psbt) }),
      network
    );
    expect(signed.data.inputs[0].partialSig).toHaveLength(1);
    expect(Buffer.from(signed.data.inputs[0].partialSig![0].pubkey)).toEqual(
      Buffer.from(children[0].publicKey)
    );
    expect(
      signed.data.inputs[0].bip32Derivation!.map((item) => item.path).sort()
    ).toEqual([...paths].sort());
  });

  it.each(['p2wsh', 'p2sh-p2wsh', 'p2sh'])(
    'preserves public metadata for a standard external %s cosigner',
    async (type) => {
      const { tx, psbt, cosignerRoot } = multisigFixture(type);
      const signed = PsbtUtils.fromPali(
        await tx.signPSBT({ psbt: PsbtUtils.toPali(psbt) }),
        network
      );
      signed.signInputHD(0, cosignerRoot);
      signed.finalizeAllInputs();
      expect(
        signed.data.inputs[0].finalScriptWitness ||
          signed.data.inputs[0].finalScriptSig
      ).toBeDefined();
    }
  );

  it.each(['p2wsh', 'p2sh-p2wsh', 'p2sh'])(
    'preserves an existing external signature in %s multisig',
    async (type) => {
      const { tx, psbt, cosigner } = multisigFixture(type);
      psbt.signInput(0, cosigner);
      const externalSignature = Buffer.from(
        psbt.data.inputs[0].partialSig![0].signature
      );
      const signed = PsbtUtils.fromPali(
        await tx.signPSBT({ psbt: PsbtUtils.toPali(psbt) }),
        network
      );
      const input = signed.data.inputs[0];
      expect(
        Buffer.from(input.finalScriptWitness || input.finalScriptSig!).includes(
          externalSignature
        )
      ).toBe(true);
    }
  );

  it('rejects a multisig derivation hint not actually committed by the spent script', async () => {
    const { tx, psbt, cosigner } = multisigFixture('p2wsh');
    psbt.data.inputs[0].witnessScript = payments.p2ms({
      m: 1,
      pubkeys: [cosigner.publicKey],
      network: bitcoinNetwork,
    }).output;
    await expect(tx.signPSBT({ psbt: PsbtUtils.toPali(psbt) })).rejects.toThrow(
      /approved account/
    );
  });

  it('rejects a distinct multisig input with no approved-account key', async () => {
    const { tx, psbt, cosigner, root } = multisigFixture('p2wsh');
    const other = root.derivePath("m/84'/1'/1'/0/0");
    const multisig = payments.p2ms({
      m: 2,
      pubkeys: [cosigner.publicKey, other.publicKey],
      network: bitcoinNetwork,
    });
    const witness = payments.p2wsh({
      redeem: multisig,
      network: bitcoinNetwork,
    });
    const previous = new Transaction();
    previous.addInput(Buffer.alloc(32), 0xffffffff);
    previous.addOutput(witness.output!, 100000n);
    psbt.addInput({
      hash: previous.getId(),
      index: 0,
      nonWitnessUtxo: previous.toBuffer(),
      witnessScript: multisig.output,
      bip32Derivation: [
        {
          masterFingerprint: root.fingerprint,
          path: "m/84'/1'/1'/0/0",
          pubkey: other.publicKey,
        },
      ],
    });
    await expect(tx.signPSBT({ psbt: PsbtUtils.toPali(psbt) })).rejects.toThrow(
      /approved account/
    );
  });

  it.each([
    ['another account without proprietary metadata', [1], false],
    ['another account claiming the approved address', [1], true],
    ['mixed account inputs', [0, 1], false],
  ])('rejects %s before any signature', async (_label, indices, forged) => {
    const { tx, hd, makePsbt } = fixture();
    const sign = jest.spyOn(hd, 'sign');
    await expect(
      tx.signPSBT({
        psbt: PsbtUtils.toPali(
          makePsbt(indices as number[], forged as boolean)
        ),
      })
    ).rejects.toThrow(/approved account/);
    expect(sign).not.toHaveBeenCalled();
  });

  it('still signs the approved account with the actual signer', async () => {
    const { tx, makePsbt } = fixture();
    const signed = await tx.signPSBT({ psbt: PsbtUtils.toPali(makePsbt([0])) });
    expect(
      PsbtUtils.fromPali(signed, network).data.inputs[0].finalScriptWitness
    ).toBeDefined();
  });

  it('does not trust a valid approved derivation paired with another input script', () => {
    const { makePsbt, account, root, paths, children } = fixture();
    const psbt = makePsbt([1]);
    psbt.data.inputs[0].bip32Derivation = [
      {
        masterFingerprint: root.fingerprint,
        path: paths[0],
        pubkey: children[0].publicKey,
      },
    ];
    expect(() =>
      assertPsbtAccountScope(psbt, {
        account,
        accountId: 0,
        accountType: KeyringAccountType.HDAccount,
        network,
      })
    ).toThrow(/approved account/);
  });

  it('bounds the actual keyring signer root as well as its sign method', async () => {
    const { hd, state, account, makePsbt, paths } = fixture();
    const keyring: any = new KeyringManager();
    keyring.sessionPassword = { isCleared: () => false };
    keyring.setVaultStateGetter(() => ({
      activeAccount: { id: 0, type: KeyringAccountType.HDAccount },
      accounts: state.accounts,
      activeNetwork: network,
    }));
    keyring.createOnDemandUTXOSigner = () => hd;
    const scoped = keyring.getSigner().hd;
    expect(() => scoped.getRootNode().derivePath(paths[1])).toThrow(
      /approved account/
    );
    await expect(scoped.sign(makePsbt([0, 1]))).rejects.toThrow(
      /approved account/
    );
    await expect(scoped.sign(makePsbt([0]))).resolves.toBeDefined();
    expect(account.address).toBeDefined();
    keyring.sessionPassword = null;
    await keyring.destroy();
  });

  it.each([KeyringAccountType.Ledger, KeyringAccountType.Trezor])(
    'accepts authenticated %s account paths and rejects another account',
    (accountType) => {
      const { makePsbt, account } = fixture();
      const scope = { account, accountId: 0, accountType, network };
      expect(() => assertPsbtAccountScope(makePsbt([0]), scope)).not.toThrow();
      expect(() => assertPsbtAccountScope(makePsbt([1], true), scope)).toThrow(
        /approved account/
      );
    }
  );

  it('uses the selected Trezor account even if caller flags request software signing', async () => {
    const { state, account, makePsbt } = fixture();
    state.activeAccountType = KeyringAccountType.Trezor;
    (state.accounts as any).Trezor[0] = { ...account, isTrezorWallet: true };
    const trezor = {
      convertToTrezorFormat: jest.fn(() => 'request'),
      signUtxoTransaction: jest.fn(async (_request, psbt) => psbt),
    };
    const getSigner = jest.fn();
    const tx = new SyscoinTransactions(
      getSigner,
      () => ({ main: {} }),
      () => state,
      jest.fn(),
      {} as any,
      trezor as any
    );
    await expect(
      tx.signPSBT({ psbt: PsbtUtils.toPali(makePsbt([0])), isTrezor: false })
    ).resolves.toBeDefined();
    expect(trezor.signUtxoTransaction).toHaveBeenCalledTimes(1);
    expect(getSigner).not.toHaveBeenCalled();
    await expect(
      tx.signPSBT({ psbt: PsbtUtils.toPali(makePsbt([1])), isTrezor: true })
    ).rejects.toThrow(/approved account/);
    expect(trezor.signUtxoTransaction).toHaveBeenCalledTimes(1);
  });

  it('accepts an imported account-level key and normalizes only authenticated relative paths', async () => {
    const { root, account, makePsbt } = fixture();
    const node = root.derivePath("m/84'/1'/0'");
    const psbt = makePsbt([0]);
    const scope = {
      account,
      accountId: 7,
      accountType: KeyringAccountType.Imported,
      network,
    };
    assertPsbtAccountScope(psbt, scope);
    expect(psbt.data.inputs[0].bip32Derivation![0].path).toBe('0/0');
    const actual = jest.requireActual('syscoinjs-lib');
    await actual.utils.signWithKeyPair(psbt, node, bitcoinNetwork);
    expect(psbt.data.inputs[0].finalScriptWitness).toBeDefined();
  });

  it('permits a single-address imported key only for its actual output script', async () => {
    const { account, makePsbt, children } = fixture();
    const imported = { ...account, xpub: account.address };
    const scope = {
      account: imported,
      accountId: 3,
      accountType: KeyringAccountType.Imported,
      network,
    };
    expect(() => assertPsbtAccountScope(makePsbt([0]), scope)).not.toThrow();
    expect(() => assertPsbtAccountScope(makePsbt([1], true), scope)).toThrow(
      /approved account/
    );
    const keyring: any = new KeyringManager();
    const password = 'disposable-public-test-password';
    keyring.sessionPassword = { isCleared: () => false };
    keyring.setVaultStateGetter(() => ({
      activeAccount: { id: 3, type: KeyringAccountType.Imported },
      accounts: {
        Imported: {
          3: {
            ...imported,
            xprv: CryptoJS.AES.encrypt(
              children[0].toWIF(),
              password
            ).toString(),
          },
        },
      },
      activeNetwork: network,
    }));
    keyring.withSecureData = (callback) => callback(password);
    const signer = keyring.getSigner().hd;
    await expect(signer.sign(makePsbt([1], true))).rejects.toThrow(
      /approved account/
    );
    const signed = await signer.sign(makePsbt([0]));
    expect(signed.data.inputs[0].finalScriptWitness).toBeDefined();
    keyring.sessionPassword = null;
    await keyring.destroy();
  });

  it.each([
    "m/84'/1'/1'/0/0",
    "m/44'/1'/0'/0/0",
    "m/84'/57'/0'/0/0",
    "m/84'/1'/0'/2/0",
    "m/84'/1'/0'/0/0'",
  ])(
    'rejects an unauthenticated proprietary path %s even alongside valid derivation data',
    (path) => {
      const { makePsbt, account } = fixture();
      const psbt = makePsbt([0]);
      psbt.addUnknownKeyValToInput(0, {
        key: Buffer.from('path'),
        value: Buffer.from(path),
      });
      expect(() =>
        assertPsbtAccountScope(psbt, {
          account,
          accountId: 0,
          accountType: KeyringAccountType.HDAccount,
          network,
        })
      ).toThrow(/approved account/);
    }
  );

  it('preserves finalized co-signer inputs without signing them again', async () => {
    const { tx, makePsbt, children } = fixture();
    const psbt = makePsbt([0, 1]);
    psbt.signInput(1, children[1]);
    psbt.finalizeInput(1);
    const witness = Buffer.from(psbt.data.inputs[1].finalScriptWitness!);
    // An attacker can reattach derivation hints to a finalized input.
    psbt.addUnknownKeyValToInput(1, {
      key: Buffer.from('path'),
      value: Buffer.from("m/84'/1'/1'/0/0"),
    });
    const signed = PsbtUtils.fromPali(
      await tx.signPSBT({ psbt: PsbtUtils.toPali(psbt) }),
      network
    );
    expect(Buffer.from(signed.data.inputs[1].finalScriptWitness)).toEqual(
      witness
    );
    expect(signed.data.inputs[1].partialSig).toBeUndefined();
    expect(signed.data.inputs[0].finalScriptWitness).toBeDefined();
  });

  it('validates 100 legitimate independent inputs within one bounded operation', () => {
    const { root, account } = fixture();
    const previous = new Transaction();
    previous.addInput(Buffer.alloc(32), 0xffffffff);
    const children = Array.from({ length: 100 }, (_, index) =>
      root.derivePath(`m/84'/1'/0'/0/${index}`)
    );
    children.forEach((child) =>
      previous.addOutput(
        payments.p2wpkh({ pubkey: child.publicKey, network: bitcoinNetwork })
          .output!,
        100000n
      )
    );
    const psbt = new Psbt({ network: bitcoinNetwork });
    children.forEach((child, index) =>
      psbt.addInput({
        hash: previous.getId(),
        index,
        nonWitnessUtxo: previous.toBuffer(),
        bip32Derivation: [
          {
            masterFingerprint: root.fingerprint,
            path: `m/84'/1'/0'/0/${index}`,
            pubkey: child.publicKey,
          },
        ],
      })
    );
    psbt.addOutput({ address: account.address, value: 9999000n });
    const start = performance.now();
    assertPsbtAccountScope(psbt, {
      account,
      accountId: 0,
      accountType: KeyringAccountType.HDAccount,
      network,
    });
    console.info(
      `PSBT scope validation: 100 independent inputs in ${(
        performance.now() - start
      ).toFixed(1)} ms`
    );
  });
});
