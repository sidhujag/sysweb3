import * as syscoinjs from 'syscoinjs-lib';

import { PsbtV2 } from '../../../../src/ledger/bitcoin_client/lib/psbtv2';

describe('PsbtV2.fromBitcoinJS for P2WPKH', () => {
  it('converts a simple P2WPKH psbt without errors', () => {
    const bjs: any = (syscoinjs.utils as any).bitcoinjs;
    const psbt = new bjs.Psbt({ network: bjs.networks.bitcoin });

    // Build P2WPKH using a known 20-byte hash to guarantee a valid scriptPubKey
    const pubkey = Buffer.alloc(33, 3);
    const hash20 = Buffer.alloc(20, 2);
    const p2wpkh = bjs.payments.p2wpkh({
      hash: hash20,
      network: bjs.networks.bitcoin,
    });

    // Minimal input/output with witnessUtxo
    psbt.addInput({
      hash: Buffer.alloc(32, 1),
      index: 0,
      witnessUtxo: {
        script: p2wpkh.output as Buffer,
        value: BigInt(1500),
      },
      bip32Derivation: [
        {
          masterFingerprint: Buffer.from('deadbeef', 'hex'),
          path: "m/84'/0'/0'/0/0",
          pubkey,
        },
      ],
    });
    // Provide script directly to avoid address encoding differences
    psbt.addOutput({ script: p2wpkh.output as Buffer, value: BigInt(1000) });

    const psbtV2 = new PsbtV2().fromBitcoinJS(psbt);

    // Validate a few critical fields were set
    expect(psbtV2.getGlobalPsbtVersion()).toBe(2);
    expect(psbtV2.getGlobalInputCount()).toBe(1);
    expect(psbtV2.getGlobalOutputCount()).toBe(1);

    const utxo = psbtV2.getInputWitnessUtxo(0)!;
    expect(utxo.amount).toBe(1500);
    expect(Buffer.isBuffer(utxo.scriptPubKey)).toBe(true);

    const deriv = psbtV2.getInputBip32Derivation(0, pubkey)!;
    expect(Buffer.isBuffer(deriv.masterFingerprint)).toBe(true);
    expect(Array.isArray(deriv.path)).toBe(true);
  });
});
