import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { deriveSentryClassicalPublicKey } from '@sidhujag/sysweb3-sentry/classical-public-key';
import { importSentryAuthorityKey, importSentryOperatorKey } from '../dist/index.js';

const fixture = async (name) => JSON.parse(await readFile(new URL(`./fixtures/${name}`, import.meta.url)));
const key = (scalar) => Uint8Array.from(Buffer.from(scalar.toString(16).padStart(64, '0'), 'hex'));
const hex = (bytes) => Buffer.from(bytes).toString('hex');

test('classical public-key imports match Core BLS and compressed secp256k1 vectors', async () => {
  const { legacy } = await fixture('core-vectors.json');
  const derived = await deriveSentryClassicalPublicKey('bls-basic', key(1n));
  assert.equal(hex(derived), legacy.publicKey);
  assert.equal((await importSentryOperatorKey('bls-basic', hex(key(1n)))).publicKey, legacy.publicKey);
  const secp = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
  assert.equal(hex(await deriveSentryClassicalPublicKey('secp256k1', key(1n))), secp);
  assert.equal((await importSentryAuthorityKey('collateral', 'secp256k1', hex(key(1n)))).publicKey, secp);
});

test('an offset view can be wiped immediately after borrowing, before the first await', async () => {
  const allocation = new Uint8Array(40).fill(0xff);
  const secret = allocation.subarray(4, 36);
  secret.set(key(2n));
  const expected = '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5';
  const derivation = deriveSentryClassicalPublicKey('secp256k1', secret);
  secret.fill(0);
  assert.equal(hex(await derivation), expected);
  assert.equal(allocation[3], 0xff);
  assert.equal(allocation[36], 0xff);
});

test('classical import rejects invalid widths, fake bytes, unsupported schemes and out-of-range scalars', async () => {
  const invalid = { code: 'INVALID_SECRET_KEY' };
  const schemes = [
    ['bls-basic', 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n, 48],
    ['secp256k1', 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n, 33],
  ];
  for (const [scheme, order, width] of schemes) {
    for (const secret of [new Uint8Array(31), new Uint8Array(33), key(0n), key(order), key(order + 1n)]) {
      await assert.rejects(deriveSentryClassicalPublicKey(scheme, secret), invalid);
    }
    assert.equal((await deriveSentryClassicalPublicKey(scheme, key(order - 1n))).byteLength, width);
  }
  const forged = Object.create(Uint8Array.prototype);
  Object.defineProperties(forged, { byteLength: { value: 32 }, buffer: { value: new ArrayBuffer(32) } });
  await assert.rejects(deriveSentryClassicalPublicKey('bls-basic', forged), invalid);
  await assert.rejects(deriveSentryClassicalPublicKey('slh-dsa-shake-128s', key(1n)), { code: 'UNSUPPORTED_SCHEME' });
});
