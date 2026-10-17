import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  buildSentryRegistration,
  buildSentryRegistrarUpdate,
  buildSentryRevocation,
  buildSentryOperatorUpdate,
  decodeSentryTransaction,
  importSentryAuthorityKey,
  reviewSentryManagementOperation,
  signSentryManagementOperation,
  verifySentryManagementOperation,
  sentryKeyId,
  matchesSentryManagementIntent,
} from '../dist/index.js';
import { encodeTransaction } from '../dist/codec.js';
import {
  managementPayload,
  managementPayloadBytes,
} from '../dist/management-codec.js';
import { hex } from '../dist/bytes.js';
import {
  GENESIS,
  PRO_TX,
  OLD_NEVM,
  PAYOUT,
  previousTransaction,
} from './fixture.mjs';

const privateKey = (n) => n.toString(16).padStart(64, '0');
const network = { bech32Hrp: 'tsys', pubKeyHash: 65, scriptHash: 196 };
const funding = previousTransaction();
const inputs = [{ txid: decodeSentryTransaction(funding).txid, vout: 0 }];
const outputs = [{ valueSatoshis: '998000', scriptHex: PAYOUT }];

async function fixture() {
  const collateralKey = await importSentryAuthorityKey(
    'collateral',
    'secp256k1',
    privateKey(2)
  );
  const ownerKey = await importSentryAuthorityKey(
    'owner',
    'secp256k1',
    privateKey(3)
  );
  const votingKey = await importSentryAuthorityKey(
    'voting',
    'secp256k1',
    privateKey(4)
  );
  const operatorKey = await importSentryAuthorityKey(
    'operator',
    'bls-basic',
    privateKey(1)
  );
  const collateral = hex(
    encodeTransaction({
      version: 2,
      lockTime: 0,
      inputs: [
        {
          txid: '00'.repeat(32),
          vout: 0xffffffff,
          sequence: 0xffffffff,
          scriptHex: '0102',
          witness: [],
        },
      ],
      outputs: [
        {
          valueSatoshis: '10000000000000',
          scriptHex: '0014' + sentryKeyId(collateralKey.publicKey),
        },
      ],
    })
  );
  const chain = { genesisHash: GENESIS, era: 'legacy-v3' };
  const node = {
    proTxHash: PRO_TX,
    operatorPublicKey: operatorKey.publicKey,
    service: '127.0.0.1:18367',
    operatorPayoutScript: PAYOUT,
    nevmAddress: OLD_NEVM,
    ownerKeyId: sentryKeyId(ownerKey.publicKey),
    votingKeyId: sentryKeyId(votingKey.publicKey),
    payoutScript: PAYOUT,
    collateralOutpoint: {
      txid: decodeSentryTransaction(collateral).txid,
      vout: 0,
    },
  };
  const context = {
    chain,
    network,
    node,
    previousTransactions: [funding],
    maxFeeSatoshis: '10000',
    registration: {
      collateralTransactionHex: collateral,
      collateralVout: 0,
      requiredCollateralSatoshis: '10000000000000',
    },
  };
  return {
    collateralKey,
    ownerKey,
    votingKey,
    operatorKey,
    collateral,
    chain,
    node,
    context,
  };
}

test('legacy existing-collateral registration binds message to actual payload and never spends collateral', async () => {
  const f = await fixture();
  const req = buildSentryRegistration({
    chain: f.chain,
    inputs,
    outputs,
    collateralOutpoint: f.node.collateralOutpoint,
    service: f.node.service,
    ownerKeyId: f.node.ownerKeyId,
    votingKeyId: f.node.votingKeyId,
    operatorPublicKey: f.operatorKey.publicKey,
    payoutScript: PAYOUT,
    operatorRewardBasisPoints: 250,
  });
  const review = reviewSentryManagementOperation(req, f.context);
  assert.equal(review.authorizations[0].role, 'collateral');
  assert.equal(review.fields.collateralSatoshis, '10000000000000');
  assert.match(
    review.fields.collateralSigningMessage,
    /^tsys1.+\|250\|tsys1.+\|tsys1.+\|[0-9a-f]{64}$/
  );
  await assert.rejects(
    signSentryManagementOperation(req, f.context, f.ownerKey),
    /exact required/
  );
  const signed = await signSentryManagementOperation(
    req,
    f.context,
    f.collateralKey
  );
  assert.equal(signed.complete, true);
  const candidate = { ...req, transactionHex: signed.transactionHex };
  assert.equal(
    await verifySentryManagementOperation(candidate, f.context),
    true
  );
  assert.equal(matchesSentryManagementIntent(req, candidate), true);
  assert.throws(
    () =>
      reviewSentryManagementOperation(req, {
        ...f.context,
        registration: {
          ...f.context.registration,
          requiredCollateralSatoshis: '1',
        },
      }),
    /collateral amount/
  );
});

test('legacy registrar owner authorizes operator/voting/payout changes; operator cannot', async () => {
  const f = await fixture();
  const req = buildSentryRegistrarUpdate({
    chain: f.chain,
    node: f.node,
    inputs,
    outputs,
    operatorPublicKey: (
      await importSentryAuthorityKey('operator', 'bls-basic', privateKey(5))
    ).publicKey,
    votingKeyId: '56'.repeat(20),
    payoutScript: '0014' + '67'.repeat(20),
  });
  const review = reviewSentryManagementOperation(req, f.context);
  assert.equal(review.authorizations[0].role, 'owner');
  assert.equal(review.fields.votingKeyId, '56'.repeat(20));
  await assert.rejects(
    signSentryManagementOperation(req, f.context, f.operatorKey),
    /exact required/
  );
  const signed = await signSentryManagementOperation(
    req,
    f.context,
    f.ownerKey
  );
  assert.equal(signed.complete, true);
  const candidate = { ...req, transactionHex: signed.transactionHex };
  assert.equal(
    await verifySentryManagementOperation(candidate, f.context),
    true
  );
  const tx = decodeSentryTransaction(candidate.transactionHex);
  tx.outputs[0].scriptHex = '0014' + 'ab'.repeat(20);
  assert.equal(
    matchesSentryManagementIntent(req, {
      ...candidate,
      transactionHex: hex(encodeTransaction(tx)),
    }),
    false
  );
});

test('legacy revocation requires operator authority and constrains revocation reason', async () => {
  const f = await fixture();
  const req = buildSentryRevocation({
    chain: f.chain,
    node: f.node,
    inputs,
    outputs,
    reason: 2,
  });
  assert.equal(
    reviewSentryManagementOperation(req, f.context).fields.reason,
    '2'
  );
  await assert.rejects(
    signSentryManagementOperation(req, f.context, f.ownerKey),
    /exact required/
  );
  const signed = await signSentryManagementOperation(
    req,
    f.context,
    f.operatorKey
  );
  assert.equal(signed.complete, true);
  assert.equal(
    await verifySentryManagementOperation(
      { ...req, transactionHex: signed.transactionHex },
      f.context
    ),
    true
  );
  assert.throws(
    () =>
      buildSentryRevocation({
        chain: f.chain,
        node: f.node,
        inputs,
        outputs,
        reason: 4,
      }),
    /reason/
  );
});

test(
  'PQ registrar is current-owner plus new-owner proof; PQ revocation uses registered operator record',
  { timeout: 120_000 },
  async () => {
    const f = await fixture();
    const vector = JSON.parse(
      readFileSync(
        new URL('./fixtures/core-vectors.json', import.meta.url),
        'utf8'
      )
    ).pq;
    const owner = await importSentryAuthorityKey(
      'owner',
      'slh-dsa-shake-128s',
      vector.secretKey
    );
    const chain = { ...f.chain, era: 'pq-v4' };
    const pqRecord = {
      version: 1,
      profile: 1,
      keyVersion: 1,
      publicKey: owner.publicKey,
      childKeyCommitmentHex: vector.childKeyCommitmentHex,
      activatedHeight: 1440,
    };
    const node = {
      ...f.node,
      operatorPublicKey: owner.publicKey,
      globalKeyVersion: 1,
      pqRecord,
      pqOwnerRecord: {
        publicKey: owner.publicKey,
        keyVersion: 1,
        activatedHeight: 100,
      },
      pqVotingPublicKey: '67'.repeat(32),
    };
    const context = { ...f.context, chain, node };
    const req = buildSentryRegistrarUpdate({
      chain,
      node,
      inputs,
      outputs,
      pqOwnerPublicKey: owner.publicKey,
      pqVotingPublicKey: '78'.repeat(32),
    });
    const review = reviewSentryManagementOperation(req, context);
    assert.deepEqual(
      review.authorizations.map((a) => a.id),
      ['owner', 'newOwner']
    );
    assert.notEqual(
      review.authorizations[0].context,
      review.authorizations[1].context
    );
    const first = await signSentryManagementOperation(
      req,
      context,
      owner,
      'newOwner'
    );
    assert.equal(first.complete, false);
    const next = { ...req, transactionHex: first.transactionHex };
    const last = await signSentryManagementOperation(
      next,
      context,
      owner,
      'owner'
    );
    assert.equal(last.complete, true);
    assert.equal(
      await verifySentryManagementOperation(
        { ...req, transactionHex: last.transactionHex },
        context
      ),
      true
    );
    const wrongVersion = {
      ...context,
      node: {
        ...node,
        pqOwnerRecord: { ...node.pqOwnerRecord, keyVersion: 2 },
      },
    };
    assert.throws(
      () => reviewSentryManagementOperation(req, wrongVersion),
      /currently enrolled owner/
    );
    const revoke = buildSentryRevocation({
      chain,
      node,
      inputs,
      outputs,
      reason: 1,
    });
    const op = { ...owner, role: 'operator' };
    const revoked = await signSentryManagementOperation(revoke, context, op);
    assert.equal(revoked.complete, true);
    const p = managementPayload(revoked.transactionHex).payload;
    p.reason = 0;
    const tx = decodeSentryTransaction(revoked.transactionHex);
    const { opReturn } = await import('../dist/codec.js');
    tx.outputs[1].scriptHex = hex(opReturn(managementPayloadBytes(p)));
    assert.equal(
      await verifySentryManagementOperation(
        { ...revoke, transactionHex: hex(encodeTransaction(tx)) },
        context
      ),
      false
    );
  }
);

test('key roles and algorithm imports are not interchangeable', async () => {
  await assert.rejects(
    importSentryAuthorityKey('owner', 'bls-basic', privateKey(1)),
    /role/
  );
  await assert.rejects(
    importSentryAuthorityKey(
      'collateral',
      'slh-dsa-shake-128s',
      '00'.repeat(64)
    ),
    /role/
  );
  await assert.rejects(
    importSentryAuthorityKey('operator', 'secp256k1', privateKey(1)),
    /role/
  );
});

test(
  'PQ operator enrollment is owner plus new-key proof and validates child commitment',
  { timeout: 120_000 },
  async () => {
    const f = await fixture();
    const vector = JSON.parse(
      readFileSync(
        new URL('./fixtures/core-vectors.json', import.meta.url),
        'utf8'
      )
    ).pq;
    const operator = await importSentryAuthorityKey(
      'operator',
      'slh-dsa-shake-128s',
      vector.secretKey
    );
    const chain = { ...f.chain, era: 'pq-v4' };
    const candidate = {
      version: 1,
      profile: 1,
      keyVersion: 1,
      publicKey: operator.publicKey,
      childKeyCommitmentHex: vector.childKeyCommitmentHex,
      activatedHeight: 0,
    };
    const context = { ...f.context, chain };
    const req = buildSentryOperatorUpdate({
      chain,
      node: f.node,
      inputs,
      outputs,
      mode: 'initial',
      candidate,
    });
    assert.deepEqual(
      reviewSentryManagementOperation(req, context).authorizations.map(
        (a) => a.id
      ),
      ['owner', 'newOperator']
    );
    const ownerSigned = await signSentryManagementOperation(
      req,
      context,
      f.ownerKey
    );
    assert.equal(ownerSigned.complete, false);
    const opSigned = await signSentryManagementOperation(
      { ...req, transactionHex: ownerSigned.transactionHex },
      context,
      operator
    );
    assert.equal(opSigned.complete, true);
    assert.equal(
      await verifySentryManagementOperation(
        { ...req, transactionHex: opSigned.transactionHex },
        context
      ),
      true
    );
    assert.equal(
      matchesSentryManagementIntent(req, {
        ...req,
        transactionHex: opSigned.transactionHex,
      }),
      true
    );
    const premature = { ...req, chain: f.chain };
    assert.throws(
      () => reviewSentryManagementOperation(premature, f.context),
      /preparation/
    );
    assert.equal(
      reviewSentryManagementOperation(premature, {
        ...f.context,
        allowOperatorPreparation: true,
      }).authorizations.length,
      2
    );
    const bad = buildSentryOperatorUpdate({
      chain,
      node: f.node,
      inputs,
      outputs,
      mode: 'initial',
      candidate: { ...candidate, keyVersion: 2 },
    });
    assert.throws(
      () => reviewSentryManagementOperation(bad, context),
      /version and generation one/
    );
    const activeNode = {
      ...f.node,
      operatorPublicKey: operator.publicKey,
      globalKeyVersion: 1,
      pqRecord: { ...candidate, activatedHeight: 1440 },
    };
    const nextCandidate = {
      ...candidate,
      keyVersion: 2,
      publicKey: '89'.repeat(32),
    };
    const rotatedRequest = buildSentryOperatorUpdate({
      chain,
      node: activeNode,
      inputs,
      outputs,
      mode: 'rotate',
      candidate: nextCandidate,
    });
    const rotateContext = { ...context, node: activeNode };
    assert.deepEqual(
      reviewSentryManagementOperation(
        rotatedRequest,
        rotateContext
      ).authorizations.map((a) => a.id),
      ['operator']
    );
    const rotated = await signSentryManagementOperation(
      rotatedRequest,
      rotateContext,
      operator
    );
    assert.equal(rotated.complete, true);
    assert.throws(
      () =>
        reviewSentryManagementOperation(rotatedRequest, {
          ...rotateContext,
          node: { ...activeNode, operatorRevoked: true },
        }),
      /active keys use rotation/
    );
  }
);

test('owner enrollment preparation cannot change payout, voting or operator before activation', async () => {
  const f = await fixture();
  const ownerPublicKey = 'aa'.repeat(32);
  const request = buildSentryRegistrarUpdate({
    chain: f.chain,
    node: f.node,
    inputs,
    outputs,
    ownerPreparation: true,
    pqOwnerPublicKey: ownerPublicKey,
  });
  assert.throws(
    () => reviewSentryManagementOperation(request, f.context),
    /preparation/
  );
  const context = { ...f.context, allowOwnerPreparation: true };
  assert.deepEqual(
    reviewSentryManagementOperation(request, context).authorizations.map(
      (a) => a.id
    ),
    ['owner', 'newOwner']
  );
  const bad = buildSentryRegistrarUpdate({
    chain: f.chain,
    node: f.node,
    inputs,
    outputs,
    ownerPreparation: true,
    pqOwnerPublicKey: ownerPublicKey,
    payoutScript: '0014' + 'af'.repeat(20),
  });
  assert.throws(
    () => reviewSentryManagementOperation(bad, context),
    /preparation fields/
  );
});
