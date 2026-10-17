import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  deriveSentryOperatorKey,
  importSentryOperatorKey,
} from '../dist/index.js';

const vectors = JSON.parse(
  readFileSync(
    new URL('./fixtures/bls-keygen-vectors.json', import.meta.url),
    'utf8'
  )
);

test('32-byte BLS generation matches exact Core private and public key vectors', async () => {
  for (const vector of vectors) {
    const key = await deriveSentryOperatorKey('bls-basic', vector.seed);
    assert.deepEqual(key, {
      scheme: 'bls-basic',
      secretKey: vector.secretKey,
      publicKey: vector.publicKey,
    });
    assert.deepEqual(await importSentryOperatorKey(key.scheme, key.secretKey), key);
    assert.deepEqual(
      await deriveSentryOperatorKey('bls-basic', vector.seed.toUpperCase()),
      key
    );
  }
});

test('BLS seed generation rejects wrong lengths and malformed inputs without echoing them', async () => {
  for (const seed of [
    '',
    '01'.repeat(31),
    '01'.repeat(33),
    '01'.repeat(48),
    'ab'.repeat(31) + 'zz',
    'ab'.repeat(32) + '0',
  ]) {
    await assert.rejects(deriveSentryOperatorKey('bls-basic', seed), (error) => {
      assert.equal(error.code, 'INVALID_HEX');
      assert.equal(
        error.message,
        'key generation seed must be canonical byte hex (32 bytes)'
      );
      return true;
    });
  }
  await assert.rejects(
    deriveSentryOperatorKey('other', '01'.repeat(32)),
    /Unsupported Sentry operator scheme/
  );
});
