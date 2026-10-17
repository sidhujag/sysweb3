import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildSentryServiceUpdate,
  decodeSentryTransaction,
  deriveSentryOperatorKey,
  importSentryOperatorKey,
  reviewSentryOperation,
  signSentryOperation,
  verifySentryOperation,
} from '../dist/index.js';
import { concat, hex, integerBytes } from '../dist/bytes.js';
import { locateServicePayload } from '../dist/codec.js';
import { serializePQRecord } from '../dist/review.js';
import {
  GENESIS,
  NEW_NEVM,
  OLD_NEVM,
  PAYOUT,
  PRO_TX,
  previousTransaction,
  replacePayload,
} from './fixture.mjs';

test(
  'PQ SHAKE-128s matches its full registered record and separates chain/context/NEVM',
  { timeout: 120_000 },
  async () => {
    const key = await deriveSentryOperatorKey(
      'slh-dsa-shake-128s',
      '01'.repeat(48)
    );
    assert.equal(key.secretKey.length, 128);
    assert.equal(key.publicKey.length, 64);
    assert.deepEqual(
      await importSentryOperatorKey(key.scheme, key.secretKey),
      key
    );
    const malformed =
      key.secretKey.slice(0, -2) +
      (key.secretKey.slice(-2) === '00' ? '01' : '00');
    await assert.rejects(
      importSentryOperatorKey(key.scheme, malformed),
      /Invalid Sentry operator/
    );
    const commitment = concat(
      integerBytes(1, 2),
      integerBytes(1, 2),
      integerBytes(235, 2),
      integerBytes(16, 2),
      integerBytes(1, 4),
      integerBytes(100, 4),
      new Uint8Array(32).fill(0x66),
      new Uint8Array(32).fill(0x77)
    );
    const pqRecord = {
      version: 1,
      profile: 1,
      keyVersion: 1,
      publicKey: key.publicKey,
      childKeyCommitmentHex: hex(commitment),
      activatedHeight: 1000,
    };
    assert.equal(serializePQRecord(pqRecord).length, 124);
    const previous = previousTransaction();
    const chain = { genesisHash: GENESIS, era: 'pq-v4' };
    const node = {
      proTxHash: PRO_TX,
      operatorPublicKey: key.publicKey,
      globalKeyVersion: 1,
      pqRecord,
      service: '127.0.0.1:18367',
      operatorPayoutScript: PAYOUT,
      nevmAddress: OLD_NEVM,
    };
    const request = buildSentryServiceUpdate({
      chain,
      node,
      nevmAddress: NEW_NEVM,
      inputs: [{ txid: decodeSentryTransaction(previous).txid, vout: 0 }],
      outputs: [{ valueSatoshis: '998000', scriptHex: PAYOUT }],
    });
    const context = {
      chain,
      node,
      previousTransactions: [previous],
      maxFeeSatoshis: '10000',
    };
    const review = reviewSentryOperation(request, context);
    assert.equal(review.scheme, 'slh-dsa-shake-128s');
    assert.equal(
      locateServicePayload(decodeSentryTransaction(request.transactionHex))
        .payload.signature.length,
      7856
    );
    const signed = await signSentryOperation(request, context, key);
    const signedRequest = { ...request, transactionHex: signed.transactionHex };
    assert.equal(await verifySentryOperation(signedRequest, context), true);
    // Full registered state participates in Core's signature digest.
    assert.equal(
      await verifySentryOperation(signedRequest, {
        ...context,
        node: { ...node, pqRecord: { ...pqRecord, activatedHeight: 1001 } },
      }),
      false
    );
    assert.equal(
      await verifySentryOperation(signedRequest, {
        ...context,
        node: {
          ...node,
          globalKeyVersion: 2,
          pqRecord: { ...pqRecord, keyVersion: 2 },
        },
      }),
      false
    );
    const otherChain = { ...chain, genesisHash: 'ee'.repeat(32) };
    assert.equal(
      await verifySentryOperation(
        { ...signedRequest, chain: otherChain },
        { ...context, chain: otherChain }
      ),
      false
    );
    const removal = await replacePayload(signedRequest, (payload) => {
      payload.nevmAddress = '';
    });
    assert.equal(await verifySentryOperation(removal, context), false);
    assert.throws(
      () =>
        reviewSentryOperation(request, {
          ...context,
          node: { ...node, pqRecord: undefined },
        }),
      /record/
    );
    assert.throws(
      () => serializePQRecord({ ...pqRecord, activatedHeight: 0 }),
      /not activated/
    );
    assert.throws(
      () => serializePQRecord({ ...pqRecord, profile: 2 }),
      /profile/
    );
  }
);

test('BLS import rejects zero/out-of-range keys and is distinct from SLH key imports', async () => {
  await assert.rejects(
    importSentryOperatorKey('bls-basic', '00'.repeat(32)),
    /Invalid/
  );
  await assert.rejects(
    importSentryOperatorKey('bls-basic', 'ff'.repeat(32)),
    /Invalid/
  );
  await assert.rejects(
    importSentryOperatorKey('slh-dsa-shake-128s', '01'.repeat(32)),
    /64 bytes/
  );
  await assert.rejects(
    importSentryOperatorKey('ecdsa', '01'.repeat(32)),
    /Unsupported/
  );
});
