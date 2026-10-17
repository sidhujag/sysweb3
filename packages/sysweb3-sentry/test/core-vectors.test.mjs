import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { bls12_381 } from '@noble/curves/bls12-381.js';
import { slh_dsa_shake_128s } from '@noble/post-quantum/slh-dsa.js';
import {
  buildSentryServiceUpdate,
  decodeSentryTransaction,
  deriveSentryOperatorKey,
  importSentryOperatorKey,
} from '../dist/index.js';
import { locateServicePayload, payloadBytes } from '../dist/codec.js';
import {
  PQ_SERVICE_DOMAIN,
  serializePQRecord,
  serviceAuthorizationDigest,
} from '../dist/review.js';
import { fromHex, hash256, hex } from '../dist/bytes.js';

const vectors = JSON.parse(
  readFileSync(new URL('./fixtures/core-vectors.json', import.meta.url), 'utf8')
);
const DST = 'BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_';
const base = {
  proTxHash: '11'.repeat(32),
  service: '127.0.0.1:18367',
  operatorPayoutScript: '0014' + '33'.repeat(20),
  nevmAddress: '0x' + '55'.repeat(20),
};
const funding = [{ txid: '22'.repeat(32), vout: 1 }];

test('exact Core BasicSchemeMPL public key, SerializeHash preimage and signature vector', async () => {
  const key = await importSentryOperatorKey(
    'bls-basic',
    '00'.repeat(31) + '01'
  );
  assert.equal(key.publicKey, vectors.legacy.publicKey);
  const chain = { genesisHash: '44'.repeat(32), era: 'legacy-v3' };
  const node = { ...base, operatorPublicKey: key.publicKey };
  const request = buildSentryServiceUpdate({
    chain,
    node,
    inputs: funding,
    outputs: [],
  });
  const { payload } = locateServicePayload(
    decodeSentryTransaction(request.transactionHex)
  );
  const preimage = payloadBytes(payload, true);
  assert.equal(hex(payload.inputsHash), vectors.legacy.inputsHash);
  assert.equal(hex(preimage), vectors.legacy.payloadPreimageHex);
  assert.equal(hex(hash256(preimage)), vectors.legacy.authorizationHash);
  const basic = bls12_381.longSignatures;
  const point = basic.hash(fromHex(vectors.legacy.authorizationHash), DST);
  assert.equal(
    hex(basic.sign(point, fromHex(key.secretKey)).toBytes()),
    vectors.legacy.signature
  );
  assert.equal(
    basic.verify(
      fromHex(vectors.legacy.signature),
      point,
      fromHex(key.publicKey)
    ),
    true
  );
});

test(
  'exact Core PQ key, record hash transcript, context and deterministic signature vector',
  { timeout: 120_000 },
  async () => {
    const key = await deriveSentryOperatorKey(
      'slh-dsa-shake-128s',
      vectors.pq.seed
    );
    assert.equal(key.secretKey, vectors.pq.secretKey);
    assert.equal(key.publicKey, vectors.pq.publicKey);
    const record = {
      version: 1,
      profile: 1,
      keyVersion: 1,
      publicKey: key.publicKey,
      childKeyCommitmentHex: vectors.pq.childKeyCommitmentHex,
      activatedHeight: 1440,
    };
    assert.equal(hex(serializePQRecord(record)), vectors.pq.globalRecordHex);
    const chain = { genesisHash: vectors.pq.genesisHash, era: 'pq-v4' };
    const node = {
      ...base,
      operatorPublicKey: key.publicKey,
      globalKeyVersion: 1,
      pqRecord: record,
    };
    const request = buildSentryServiceUpdate({
      chain,
      node,
      inputs: funding,
      outputs: [],
    });
    const { payload } = locateServicePayload(
      decodeSentryTransaction(request.transactionHex)
    );
    const context = {
      chain,
      node,
      previousTransactions: [],
      maxFeeSatoshis: '0',
    };
    const digest = serviceAuthorizationDigest(payload, context);
    assert.equal(hex(digest), vectors.pq.authorizationHash);
    const domain = new TextEncoder().encode(PQ_SERVICE_DOMAIN);
    assert.equal(hex(domain), vectors.pq.contextHex);
    const signature = slh_dsa_shake_128s.sign(digest, fromHex(key.secretKey), {
      context: domain,
      extraEntropy: false,
    });
    assert.equal(hex(signature), vectors.pq.signature);
    assert.equal(
      slh_dsa_shake_128s.verify(
        fromHex(vectors.pq.signature),
        digest,
        fromHex(key.publicKey),
        { context: domain }
      ),
      true
    );
    assert.equal(
      slh_dsa_shake_128s.verify(
        fromHex(vectors.pq.signature),
        digest,
        fromHex(key.publicKey)
      ),
      false
    );
  }
);
