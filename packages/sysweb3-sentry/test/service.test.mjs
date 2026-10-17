import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildSentryServiceUpdate,
  decodeSentryTransaction,
  estimateSentrySignedVBytes,
  getSentryCapabilities,
  inspectSentryOperation,
  matchesSentryTransactionIntent,
  reviewSentryOperation,
  signSentryOperation,
  validateSentryOperationRequest,
  verifySentryOperation,
} from '../dist/index.js';
import {
  encodeTransaction,
  locateServicePayload,
  opReturn,
  parseService,
  payloadBytes,
} from '../dist/codec.js';
import { concat, fromHex, hex } from '../dist/bytes.js';
import {
  legacyFixture,
  NEW_NEVM,
  OLD_NEVM,
  PAYOUT,
  replacePayload,
} from './fixture.mjs';

test('capabilities distinguish active legacy BLS v3 and PQ v4; no opaque hash API', () => {
  assert.deepEqual(getSentryCapabilities().operations, ['updateService']);
  assert.deepEqual(getSentryCapabilities().keyRoles, ['operator']);
  assert.deepEqual(getSentryCapabilities().eras, ['legacy-v3', 'pq-v4']);
});

test('unsigned legacy service request reviews exact NEVM change, funding and payload', async () => {
  const { request, context } = await legacyFixture();
  const review = reviewSentryOperation(request, context);
  assert.equal(review.feeSatoshis, '2000');
  assert.deepEqual(review.changes.nevmAddress, {
    previous: OLD_NEVM,
    next: NEW_NEVM,
  });
  assert.deepEqual(review.changes.service, {
    previous: '127.0.0.1:18367',
    next: '127.0.0.1:18367',
  });
  assert.equal(review.outputs.length, 2);
  assert.equal(review.outputs[1].isPayload, true);
  assert.equal(review.outputs[0].scriptHex, PAYOUT);
  const tx = decodeSentryTransaction(request.transactionHex);
  assert.equal(tx.version, 81);
  assert.equal(locateServicePayload(tx).payload.signature.length, 96);
  assert.equal(estimateSentrySignedVBytes(request), tx.virtualSize + 108);
  assert.deepEqual(inspectSentryOperation(request).inputTxids, [
    tx.inputs[0].txid,
  ]);
});

test('BLS signs real payload, changes only signature, verifies after separate fee signing', async () => {
  const { request, context, key } = await legacyFixture();
  const signed = await signSentryOperation(request, context, key);
  assert.equal(
    await verifySentryOperation(
      { ...request, transactionHex: signed.transactionHex },
      context
    ),
    true
  );
  const unsignedTx = decodeSentryTransaction(request.transactionHex);
  const tx = decodeSentryTransaction(signed.transactionHex);
  assert.deepEqual(tx.inputs, unsignedTx.inputs);
  assert.deepEqual(tx.outputs[0], unsignedTx.outputs[0]);
  assert.equal(tx.virtualSize, unsignedTx.virtualSize);
  assert.equal(
    reviewSentryOperation(
      { ...request, transactionHex: signed.transactionHex },
      context
    ).authorizationHash,
    signed.authorizationHash
  );
  // A fee-payer may add input signatures after operator authorization. The
  // inputsHash only commits to ordered prevouts, matching Core.
  tx.inputs[0].witness = ['11'.repeat(71), '02' + '22'.repeat(32)];
  const feeSigned = { ...request, transactionHex: hex(encodeTransaction(tx)) };
  assert.equal(matchesSentryTransactionIntent(request, feeSigned), true);
  assert.equal(await verifySentryOperation(feeSigned, context), true);
  assert.equal(reviewSentryOperation(feeSigned, context).feeSatoshis, '2000');
  await assert.rejects(
    signSentryOperation(feeSigned, context, key),
    /Fee inputs/
  );
  // Operator authorization deliberately does not cover fee outputs. The
  // full-intent comparison must catch substitutions even when Core auth verifies.
  tx.outputs[0].scriptHex = '0014' + 'ee'.repeat(20);
  const redirected = { ...request, transactionHex: hex(encodeTransaction(tx)) };
  assert.equal(await verifySentryOperation(redirected, context), true);
  assert.equal(matchesSentryTransactionIntent(request, redirected), false);
});

test('omitted NEVM preserves existing binding; explicit empty string removes it', async () => {
  const { request, context } = await legacyFixture();
  const tx = decodeSentryTransaction(request.transactionHex);
  const common = {
    chain: context.chain,
    node: context.node,
    inputs: tx.inputs,
    outputs: tx.outputs.filter((output) => output.scriptHex[0] !== '6'),
  };
  assert.equal(
    reviewSentryOperation(buildSentryServiceUpdate(common), context).changes
      .nevmAddress.next,
    OLD_NEVM
  );
  assert.equal(
    reviewSentryOperation(
      buildSentryServiceUpdate({ ...common, nevmAddress: '' }),
      context
    ).changes.nevmAddress.next,
    ''
  );
});

test('canonical services compare compressed IPv6 by bytes; reject DNS and invalid ports', () => {
  assert.deepEqual(
    parseService('[2001:db8::1]:18367').bytes,
    parseService('[2001:0db8:0:0:0:0:0:1]:18367').bytes
  );
  for (const service of [
    'rpc.example:123',
    '127.0.0.1:0',
    '127.0.0.1:65536',
    '127.0.0.01:123',
    '0.0.0.0:123',
    '[::]:123',
    '127.0.0.1:0123',
  ]) {
    assert.throws(() => parseService(service));
  }
});

test('rejects secret fields, opaque methods, unknown chain era, wrong node and excessive fees', async () => {
  const { request, context } = await legacyFixture();
  assert.throws(
    () =>
      validateSentryOperationRequest({
        ...request,
        operatorSecret: 'never-accepted',
      }),
    /Unsupported request field/
  );
  assert.throws(
    () => validateSentryOperationRequest({ ...request, operation: 'signHash' }),
    /Unsupported/
  );
  assert.throws(
    () =>
      validateSentryOperationRequest({
        ...request,
        chain: { ...request.chain, era: 'legacy-v1' },
      }),
    /Unsupported/
  );
  assert.throws(
    () =>
      reviewSentryOperation(request, {
        ...context,
        chain: { ...context.chain, genesisHash: 'ab'.repeat(32) },
      }),
    /chain/
  );
  assert.throws(
    () =>
      reviewSentryOperation(request, {
        ...context,
        node: { ...context.node, proTxHash: 'ab'.repeat(32) },
      }),
    /different registered node/
  );
  assert.throws(
    () =>
      reviewSentryOperation(request, { ...context, maxFeeSatoshis: '1000' }),
    /fee/
  );
  assert.throws(
    () =>
      reviewSentryOperation(request, { ...context, previousTransactions: [] }),
    /funding/
  );
});

test('rejects duplicated inputs, changed prevout identity and protected collateral spending', async () => {
  const { request, context } = await legacyFixture();
  const tx = decodeSentryTransaction(request.transactionHex);
  assert.throws(
    () =>
      reviewSentryOperation(request, {
        ...context,
        node: {
          ...context.node,
          collateralOutpoint: { txid: tx.inputs[0].txid, vout: 0 },
        },
      }),
    /collateral/
  );
  tx.inputs[0].vout = 1;
  assert.throws(
    () =>
      reviewSentryOperation(
        { ...request, transactionHex: hex(encodeTransaction(tx)) },
        context
      ),
    /inputsHash/
  );
  const duplicate = buildSentryServiceUpdate({
    chain: context.chain,
    node: context.node,
    inputs: [
      decodeSentryTransaction(request.transactionHex).inputs[0],
      decodeSentryTransaction(request.transactionHex).inputs[0],
    ],
    outputs: [{ valueSatoshis: '998000', scriptHex: PAYOUT }],
  });
  assert.throws(
    () => reviewSentryOperation(duplicate, context),
    /Duplicate transaction input/
  );
});

test('rejects trailing data, nonminimal OP_RETURN, duplicate payload and nonzero payload value', async () => {
  const { request, context } = await legacyFixture();
  assert.throws(
    () =>
      validateSentryOperationRequest({
        ...request,
        transactionHex: request.transactionHex + '00',
      }),
    /trailing/
  );
  const tx = decodeSentryTransaction(request.transactionHex);
  tx.outputs.push({ ...tx.outputs[1] });
  assert.throws(
    () =>
      validateSentryOperationRequest({
        ...request,
        transactionHex: hex(encodeTransaction(tx)),
      }),
    /Exactly one/
  );
  tx.outputs.pop();
  tx.outputs[1].valueSatoshis = '1';
  assert.throws(
    () =>
      reviewSentryOperation(
        { ...request, transactionHex: hex(encodeTransaction(tx)) },
        context
      ),
    /zero value/
  );
  tx.outputs[1].valueSatoshis = '0';
  const bytes = payloadBytes(locateServicePayload(tx).payload);
  // Payload < 256 bytes must use PUSHDATA1, not PUSHDATA2.
  tx.outputs[1].scriptHex = hex(
    concat(Uint8Array.of(0x6a, 0x4d, bytes.length, 0), bytes)
  );
  assert.throws(
    () =>
      validateSentryOperationRequest({
        ...request,
        transactionHex: hex(encodeTransaction(tx)),
      }),
    /Non-canonical/
  );
});

test('mutated NEVM/service/payout and version invalidate operator authorization', async () => {
  const { request, context, key } = await legacyFixture();
  const signed = await signSentryOperation(request, context, key);
  for (const mutate of [
    (p) => {
      p.nevmAddress = OLD_NEVM;
    },
    (p) => {
      p.service = parseService('127.0.0.2:18367');
    },
    (p) => {
      p.payoutScript = fromHex('0014' + '88'.repeat(20));
    },
  ]) {
    const altered = await replacePayload(
      { ...request, transactionHex: signed.transactionHex },
      mutate
    );
    assert.equal(await verifySentryOperation(altered, context), false);
  }
  assert.equal(
    await verifySentryOperation(
      { ...request, transactionHex: signed.transactionHex.slice(0, -2) },
      context
    ),
    false
  );
});

test('fee signing refuses replacing an existing operator signature', async () => {
  const { request, context, key } = await legacyFixture();
  const signed = await signSentryOperation(request, context, key);
  await assert.rejects(
    signSentryOperation(
      { ...request, transactionHex: signed.transactionHex },
      context,
      key
    ),
    /already contains/
  );
});
