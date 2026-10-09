import ecc from '@bitcoinerlab/secp256k1';
import TrezorConnect from '@trezor/connect-webextension';
import * as syscoinjs from 'syscoinjs-lib';

import { TrezorKeyring } from '../../../src/trezor';

const bitcoinjs: any = (syscoinjs.utils as any).bitcoinjs;
const privateKey = Buffer.alloc(32, 1);
const publicKey = Buffer.from(ecc.pointFromScalar(privateKey)!);
const signer = {
  publicKey,
  sign: (hash: Buffer) => Buffer.from(ecc.sign(hash, privateKey)),
};
const network = bitcoinjs.networks.testnet;
const payment = bitcoinjs.payments.p2wpkh({ pubkey: publicKey, network });

const fixture = (locktime = 12345, sequence = 0) => {
  const psbt = new bitcoinjs.Psbt({ network });
  psbt.setVersion(2);
  psbt.setLocktime(locktime);
  psbt.addInput({
    hash: Buffer.alloc(32, 2),
    index: 1,
    sequence,
    witnessUtxo: { script: payment.output, value: 100000n },
    bip32Derivation: [
      {
        masterFingerprint: Buffer.alloc(4),
        path: "m/84'/1'/0'/0/0",
        pubkey: publicKey,
      },
    ],
  });
  psbt.addOutput({ address: payment.address, value: 99000n });
  return psbt;
};
const signedTransaction = (psbt: any) => {
  const signed = psbt.clone();
  signed.signInput(0, signer);
  signed.finalizeAllInputs();
  return signed.extractTransaction().toHex();
};

describe('Trezor unsigned transaction integrity', () => {
  let receiver: TrezorKeyring;

  beforeEach(() => {
    receiver = Object.create(TrezorKeyring.prototype);
    (receiver as any).executeWithRetry = jest.fn((operation) => operation());
    jest.spyOn(console, 'log').mockImplementation(() => undefined);
  });
  afterEach(() => jest.restoreAllMocks());

  it.each([
    [0, 0xffffffff],
    [0, 0xfffffffd],
    [0, 0],
    [12345, 0xfffffffd],
    [12345, 0],
  ])(
    'preserves exact locktime %i and sequence %i in the device request',
    (locktime, sequence) => {
      const psbt = fixture(locktime, sequence);
      const before = psbt.toBase64();
      const request = receiver.convertToTrezorFormat({
        psbt,
        coin: 'testnet',
        network,
      });
      expect(request.version).toBe(2);
      expect(request.locktime).toBe(locktime);
      expect(request.inputs[0].sequence).toBe(sequence);
      expect(psbt.toBase64()).toBe(before);
    }
  );

  it('accepts a real SegWit signature for the exact approved transaction', async () => {
    const psbt = fixture();
    const serializedTx = signedTransaction(psbt);
    jest
      .spyOn(TrezorConnect, 'signTransaction')
      .mockResolvedValue({ success: true, payload: { serializedTx } } as any);
    const signed = await receiver.signUtxoTransaction({}, psbt);
    expect(signed.extractTransaction().toHex()).toBe(serializedTx);
  });

  it.each([
    'version',
    'locktime',
    'sequence',
    'outpoint',
    'inputIndex',
    'amount',
    'script',
    'inputCount',
    'outputCount',
  ])(
    'rejects a changed %s before importing any device signature',
    async (field) => {
      const psbt = fixture();
      const tx = bitcoinjs.Transaction.fromHex(signedTransaction(psbt));
      if (field === 'version') tx.version = 1;
      if (field === 'locktime') tx.locktime = 0;
      if (field === 'sequence') tx.ins[0].sequence = 0xffffffff;
      if (field === 'outpoint') tx.ins[0].hash = Buffer.alloc(32, 9);
      if (field === 'inputIndex') tx.ins[0].index = 2;
      if (field === 'amount') tx.outs[0].value = 98000n;
      if (field === 'script') tx.outs[0].script = Buffer.from([0x51]);
      if (field === 'inputCount') tx.addInput(Buffer.alloc(32, 3), 0);
      if (field === 'outputCount') tx.addOutput(Buffer.from([0x51]), 0n);
      jest.spyOn(TrezorConnect, 'signTransaction').mockResolvedValue({
        success: true,
        payload: { serializedTx: tx.toHex() },
      } as any);
      const update = jest.spyOn(psbt, 'updateInput');
      await expect(receiver.signUtxoTransaction({}, psbt)).rejects.toThrow(
        'different unsigned transaction'
      );
      expect(update).not.toHaveBeenCalled();
      expect(TrezorConnect.signTransaction).toHaveBeenCalledTimes(1);
    }
  );

  it('rejects even a valid signature over the device-default locktime and sequence', async () => {
    const approved = fixture(12345, 0);
    const deviceDefault = fixture(0, 0xffffffff);
    const serializedTx = signedTransaction(deviceDefault);
    jest
      .spyOn(TrezorConnect, 'signTransaction')
      .mockResolvedValue({ success: true, payload: { serializedTx } } as any);
    const update = jest.spyOn(approved, 'updateInput');
    await expect(receiver.signUtxoTransaction({}, approved)).rejects.toThrow(
      'different unsigned transaction'
    );
    expect(update).not.toHaveBeenCalled();
  });

  it.each(['inputs', 'outputs'])('rejects reordered %s', async (field) => {
    const psbt = fixture();
    psbt.addInput({
      hash: Buffer.alloc(32, 3),
      index: 0,
      sequence: 0,
      witnessUtxo: { script: payment.output, value: 100000n },
    });
    psbt.addOutput({ script: Buffer.from([0x51]), value: 99000n });
    const signed = psbt.clone();
    signed.signAllInputs(signer);
    signed.finalizeAllInputs();
    const tx = signed.extractTransaction();
    if (field === 'inputs') tx.ins.reverse();
    else tx.outs.reverse();
    jest.spyOn(TrezorConnect, 'signTransaction').mockResolvedValue({
      success: true,
      payload: { serializedTx: tx.toHex() },
    } as any);
    const update = jest.spyOn(psbt, 'updateInput');
    await expect(receiver.signUtxoTransaction({}, psbt)).rejects.toThrow(
      'different unsigned transaction'
    );
    expect(update).not.toHaveBeenCalled();
  });

  it('rejects a PSBT mutated while device approval was pending', async () => {
    const psbt = fixture();
    const serializedTx = signedTransaction(psbt);
    jest
      .spyOn(TrezorConnect, 'signTransaction')
      .mockImplementation(async () => {
        psbt.setLocktime(999);
        return { success: true, payload: { serializedTx } } as any;
      });
    const update = jest.spyOn(psbt, 'updateInput');
    await expect(receiver.signUtxoTransaction({}, psbt)).rejects.toThrow(
      'different unsigned transaction'
    );
    expect(update).not.toHaveBeenCalled();
  });
});
