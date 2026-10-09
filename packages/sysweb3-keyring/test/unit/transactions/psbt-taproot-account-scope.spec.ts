import { signSchnorr, verifySchnorr } from '@bitcoinerlab/secp256k1';
import { getNetworkConfig, INetworkType } from '@sidhujag/sysweb3-network';
import { opcodes, payments, Psbt, script, Transaction } from 'bitcoinjs-lib';

import { SyscoinTransactions } from '../../../src/transactions/syscoin';
import { KeyringAccountType } from '../../../src/types';
import { PsbtUtils } from '../../../src/utils/psbt';

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
const approvedPath = "m/84'/1'/0'/0/0";
const otherAccountPath = "m/84'/1'/1'/0/0";
const merkleRoot = Buffer.alloc(32, 0x51);

type InputOptions = {
  bip371?: boolean;
  internal?: boolean;
  root?: Buffer;
  otherAccount?: boolean;
  forgedPath?: boolean;
};

const fixture = () => {
  // The suite-wide HDSigner mock does not sign. Explicitly load the actual
  // signer so these tests exercise the public API through real Schnorr signing.
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
  const approved = root.derivePath(approvedPath);
  const otherAccount = root.derivePath(otherAccountPath);
  const account = {
    id: 0,
    address: payments.p2wpkh({
      pubkey: approved.publicKey,
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
  const tx = new SyscoinTransactions(
    () => ({ hd, main: {} }),
    () => ({ main: {} }),
    () => state,
    jest.fn(),
    {} as any,
    {} as any
  );
  const makePsbt = (options: InputOptions[]) => {
    const spent = options.map((option) =>
      payments.p2tr({
        internalPubkey: (option.otherAccount
          ? otherAccount
          : approved
        ).publicKey.slice(1),
        hash: option.root,
        network: bitcoinNetwork,
      })
    );
    const previous = new Transaction();
    previous.addInput(Buffer.alloc(32), 0xffffffff);
    spent.forEach((payment) => previous.addOutput(payment.output!, 100000n));
    const psbt = new Psbt({ network: bitcoinNetwork });
    options.forEach((option, index) => {
      const key =
        option.otherAccount && !option.forgedPath ? otherAccount : approved;
      const path =
        option.otherAccount && !option.forgedPath
          ? otherAccountPath
          : approvedPath;
      psbt.addInput({
        hash: previous.getId(),
        index,
        witnessUtxo: { script: spent[index].output!, value: 100000n },
        ...(option.bip371
          ? {
              tapBip32Derivation: [
                {
                  masterFingerprint: root.fingerprint,
                  path,
                  pubkey: key.publicKey.slice(1),
                  leafHashes: [],
                },
              ],
            }
          : {}),
        ...(option.internal ? { tapInternalKey: key.publicKey.slice(1) } : {}),
        ...(option.root ? { tapMerkleRoot: option.root } : {}),
      });
      psbt.addUnknownKeyValToInput(index, {
        key: Buffer.from('path'),
        value: Buffer.from(path),
      });
    });
    psbt.addOutput({
      address: account.address,
      value: BigInt(options.length) * 100000n - 1000n,
    });
    return { psbt, spent };
  };
  const sign = async (psbt: Psbt) =>
    PsbtUtils.fromPali(
      await tx.signPSBT({ psbt: PsbtUtils.toPali(psbt) }),
      network
    );
  return { hd, sign, makePsbt, approved, otherAccount };
};

const expectValidKeyPathSignature = (
  signed: Psbt,
  spent: ReturnType<typeof payments.p2tr>[],
  index = 0
) => {
  const witness = Buffer.from(signed.data.inputs[index].finalScriptWitness!);
  // A default-sighash key-path spend has exactly one 64-byte witness item.
  expect(witness[0]).toBe(1);
  expect(witness[1]).toBe(64);
  expect(witness).toHaveLength(66);
  const transaction = Transaction.fromBuffer(
    signed.data.globalMap.unsignedTx.toBuffer()
  );
  const digest = transaction.hashForWitnessV1(
    index,
    spent.map((payment) => payment.output!),
    spent.map(() => 100000n),
    Transaction.SIGHASH_DEFAULT
  );
  expect(verifySchnorr(digest, spent[index].pubkey!, witness.subarray(2))).toBe(
    true
  );
};

describe('Taproot key-path PSBT approved-account boundary with the real HD signer', () => {
  it.each<[string, InputOptions]>([
    ['a proprietary path without Taproot metadata', {}],
    [
      'a proprietary path and BIP371 derivation without an internal key',
      { bip371: true },
    ],
    [
      'a known Merkle root without an internal key',
      { bip371: true, root: merkleRoot },
    ],
    ['an explicit internal key', { bip371: true, internal: true }],
    [
      'an explicit internal key and known Merkle root',
      { bip371: true, internal: true, root: merkleRoot },
    ],
  ])('signs %s', async (_label, options) => {
    const { sign, makePsbt } = fixture();
    const { psbt, spent } = makePsbt([options]);
    expect(Boolean(psbt.data.inputs[0].tapInternalKey)).toBe(
      Boolean(options.internal)
    );
    expect(psbt.data.inputs[0].tapLeafScript).toBeUndefined();
    expectValidKeyPathSignature(await sign(psbt), spent);
  });

  it.each([
    'conflicting internal key',
    'forged approved path',
    'foreign account path',
    'wrong Merkle root',
  ])('rejects a %s before invoking the private signer', async (kind) => {
    const { hd, sign, makePsbt, otherAccount } = fixture();
    const { psbt } = makePsbt([
      kind === 'forged approved path'
        ? { otherAccount: true, forgedPath: true, bip371: true }
        : kind === 'foreign account path'
        ? { otherAccount: true, bip371: true }
        : {
            bip371: true,
            ...(kind === 'wrong Merkle root' ? { root: merkleRoot } : {}),
          },
    ]);
    if (kind === 'conflicting internal key')
      psbt.data.inputs[0].tapInternalKey = otherAccount.publicKey.slice(1);
    if (kind === 'wrong Merkle root')
      psbt.data.inputs[0].tapMerkleRoot = Buffer.alloc(32, 0x52);
    const privateSign = jest.spyOn(hd, 'sign');
    await expect(sign(psbt)).rejects.toThrow(/approved account/);
    expect(privateSign).not.toHaveBeenCalled();
  });

  it('does not infer an internal key for a PSBT carrying leaf-script metadata', async () => {
    const { hd, sign, makePsbt, approved } = fixture();
    const leafScript = Buffer.from([0x51]);
    const payment = payments.p2tr({
      internalPubkey: approved.publicKey.slice(1),
      scriptTree: { output: leafScript },
      redeem: { output: leafScript, redeemVersion: 0xc0 },
      network: bitcoinNetwork,
    });
    const { psbt } = makePsbt([
      { bip371: true, root: Buffer.from(payment.hash!) },
    ]);
    psbt.data.inputs[0].tapLeafScript = [
      {
        leafVersion: 0xc0,
        script: leafScript,
        controlBlock: payment.witness![payment.witness!.length - 1],
      },
    ];
    expect(psbt.data.inputs[0].tapInternalKey).toBeUndefined();
    const privateSign = jest.spyOn(hd, 'sign');
    await expect(sign(psbt)).rejects.toThrow(/approved account/);
    expect(privateSign).not.toHaveBeenCalled();
  });

  it.each(['BIP371 leaf hashes', 'a script-path signature'])(
    'does not infer an internal key for a PSBT carrying %s without leaf scripts',
    async (metadata) => {
      const { hd, sign, makePsbt, approved } = fixture();
      const leafScript = script.compile([
        approved.publicKey.slice(1),
        opcodes.OP_CHECKSIG,
      ]);
      const payment = payments.p2tr({
        internalPubkey: approved.publicKey.slice(1),
        scriptTree: { output: leafScript },
        network: bitcoinNetwork,
      });
      // A single-leaf tree root is that leaf's actual BIP341 hash.
      const leafHash = Buffer.from(payment.hash!);
      const { psbt, spent } = makePsbt([{ bip371: true, root: leafHash }]);
      if (metadata === 'BIP371 leaf hashes') {
        psbt.data.inputs[0].tapBip32Derivation![0].leafHashes = [leafHash];
      } else {
        const transaction = Transaction.fromBuffer(
          psbt.data.globalMap.unsignedTx.toBuffer()
        );
        const digest = transaction.hashForWitnessV1(
          0,
          spent.map((output) => output.output!),
          [100000n],
          Transaction.SIGHASH_DEFAULT,
          leafHash
        );
        const signature = signSchnorr(digest, approved.privateKey);
        expect(
          verifySchnorr(digest, approved.publicKey.slice(1), signature)
        ).toBe(true);
        psbt.data.inputs[0].tapScriptSig = [
          { pubkey: approved.publicKey.slice(1), leafHash, signature },
        ];
      }
      expect(psbt.data.inputs[0].tapInternalKey).toBeUndefined();
      expect(psbt.data.inputs[0].tapLeafScript).toBeUndefined();
      const privateSign = jest.spyOn(hd, 'sign');
      await expect(sign(psbt)).rejects.toThrow(/approved account/);
      expect(privateSign).not.toHaveBeenCalled();
    }
  );

  it.each([false, true])(
    'leaves a joint foreign Taproot input unsigned (forged path: %s)',
    async (forgedPath) => {
      const { hd, sign, makePsbt } = fixture();
      const { psbt, spent } = makePsbt([
        {},
        { otherAccount: true, forgedPath, bip371: true },
      ]);
      const originalSign = hd.sign.bind(hd);
      let foreignHints: unknown;
      jest.spyOn(hd, 'sign').mockImplementation(async (input) => {
        foreignHints = {
          derivations: input.data.inputs[1].tapBip32Derivation,
          paths: (input.data.inputs[1].unknownKeyVals || []).filter(
            (field) => Buffer.from(field.key).toString() === 'path'
          ),
        };
        return originalSign(input);
      });
      const signed = await sign(psbt);
      expectValidKeyPathSignature(signed, spent);
      expect(foreignHints).toEqual({ derivations: undefined, paths: [] });
      expect(signed.data.inputs[1].tapKeySig).toBeUndefined();
      expect(signed.data.inputs[1].tapScriptSig).toBeUndefined();
      expect(signed.data.inputs[1].partialSig).toBeUndefined();
      expect(signed.data.inputs[1].finalScriptSig).toBeUndefined();
      expect(signed.data.inputs[1].finalScriptWitness).toBeUndefined();
      expect(signed.data.inputs[1].tapBip32Derivation).toHaveLength(1);
      expect(
        signed.data.inputs[1].unknownKeyVals?.some(
          (field) => Buffer.from(field.key).toString() === 'path'
        )
      ).toBe(true);
    }
  );
});
