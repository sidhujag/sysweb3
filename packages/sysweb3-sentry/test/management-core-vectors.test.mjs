import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import {
  buildSentryRegistration,
  buildSentryRegistrarUpdate,
  buildSentryRevocation,
  buildSentryOperatorUpdate,
  decodeSentryTransaction,
  importSentryAuthorityKey,
  sentryKeyId,
  reviewSentryManagementOperation,
  signSentryManagementOperation,
  verifySentryManagementOperation,
  matchesSentryManagementIntent,
} from '../dist/index.js';
import {
  managementPayload,
  managementPayloadBytes,
  registrationMessage,
  registrationMessageDigest,
} from '../dist/management-codec.js';
import { ownerDigest } from '../dist/management.js';
import { fromHex, hash256, hex } from '../dist/bytes.js';

const vectors = JSON.parse(
  readFileSync(
    new URL('./fixtures/management-core-vectors.json', import.meta.url),
    'utf8'
  )
);
const pq = JSON.parse(
  readFileSync(new URL('./fixtures/core-vectors.json', import.meta.url), 'utf8')
).pq;
const chain = { genesisHash: '44'.repeat(32), era: 'legacy-v3' };
const network = { bech32Hrp: 'tsys', pubKeyHash: 65, scriptHash: 196 };
const funding = [
  { txid: decodeSentryTransaction(vectors.fundingTransaction).txid, vout: 0 },
];
const payout = '0014' + '88'.repeat(20);
const outputs = [{ valueSatoshis: '998000', scriptHex: payout }];

test('Core registration preimage, Bech32 signing message and libsecp compact signature match', async () => {
  const operator = await importSentryAuthorityKey(
    'operator',
    'bls-basic',
    '00'.repeat(31) + '01'
  );
  const req = buildSentryRegistration({
    chain,
    inputs: funding,
    outputs,
    collateralOutpoint: { txid: '33'.repeat(32), vout: 2 },
    service: '127.0.0.1:18367',
    ownerKeyId: '66'.repeat(20),
    votingKeyId: '77'.repeat(20),
    operatorPublicKey: operator.publicKey,
    operatorRewardBasisPoints: 250,
    payoutScript: payout,
  });
  const { payload } = managementPayload(req.transactionHex);
  assert.equal(
    hex(managementPayloadBytes(payload, true)),
    vectors.legacyRegistration.preimage
  );
  assert.equal(
    hex(hash256(managementPayloadBytes(payload, true))),
    vectors.legacyRegistration.payloadHash
  );
  assert.equal(
    registrationMessage(payload, network),
    vectors.legacyRegistration.message
  );
  const digest = registrationMessageDigest(payload, network);
  assert.equal(hex(digest), vectors.legacyRegistration.digest);
  const signature = secp256k1.sign(digest, fromHex('00'.repeat(31) + '03'), {
    prehash: false,
    format: 'recovered',
    lowS: true,
  });
  signature[0] += 31;
  assert.equal(hex(signature), vectors.legacyRegistration.signature);
});

test('Core registrar ECDSA and revocation BLS exact bytes verify through complete SDK flow', async () => {
  const owner = await importSentryAuthorityKey(
    'owner',
    'secp256k1',
    '00'.repeat(31) + '03'
  );
  const operator = await importSentryAuthorityKey(
    'operator',
    'bls-basic',
    '00'.repeat(31) + '01'
  );
  const node = {
    proTxHash: '11'.repeat(32),
    operatorPublicKey: operator.publicKey,
    ownerKeyId: sentryKeyId(owner.publicKey),
    votingKeyId: '77'.repeat(20),
    service: '127.0.0.1:18367',
    operatorPayoutScript: payout,
    payoutScript: payout,
    nevmAddress: '',
  };
  const context = {
    chain,
    network,
    node,
    previousTransactions: [vectors.fundingTransaction],
    maxFeeSatoshis: '10000',
  };
  for (const [request, key, expected] of [
    [
      buildSentryRegistrarUpdate({ chain, node, inputs: funding, outputs }),
      owner,
      vectors.legacyRegistrar,
    ],
    [
      buildSentryRevocation({
        chain,
        node,
        inputs: funding,
        outputs,
        reason: 2,
      }),
      operator,
      vectors.legacyRevoke,
    ],
  ]) {
    const { payload } = managementPayload(request.transactionHex);
    assert.equal(hex(managementPayloadBytes(payload, true)), expected.preimage);
    assert.equal(
      reviewSentryManagementOperation(request, context).authorizations[0]
        .digest,
      expected.digest
    );
    const signed = await signSentryManagementOperation(request, context, key);
    assert.equal(signed.complete, true);
    assert.equal(
      hex(managementPayload(signed.transactionHex).payload.primarySignature),
      expected.signature
    );
  }
});

test(
  'Core PQ revocation and initial operator owner/PoP signatures match exactly',
  { timeout: 120_000 },
  async () => {
    const owner = await importSentryAuthorityKey(
      'owner',
      'secp256k1',
      '00'.repeat(31) + '03'
    );
    const operator = await importSentryAuthorityKey(
      'operator',
      'slh-dsa-shake-128s',
      pq.secretKey
    );
    const activeChain = { ...chain, era: 'pq-v4' };
    const record = {
      version: 1,
      profile: 1,
      keyVersion: 1,
      publicKey: operator.publicKey,
      childKeyCommitmentHex: pq.childKeyCommitmentHex,
      activatedHeight: 1440,
    };
    const node = {
      proTxHash: '11'.repeat(32),
      operatorPublicKey: operator.publicKey,
      globalKeyVersion: 1,
      pqRecord: record,
      ownerKeyId: sentryKeyId(owner.publicKey),
      votingKeyId: '77'.repeat(20),
      service: '127.0.0.1:18367',
      operatorPayoutScript: payout,
      payoutScript: payout,
      nevmAddress: '',
    };
    const context = {
      chain: activeChain,
      network,
      node,
      previousTransactions: [vectors.fundingTransaction],
      maxFeeSatoshis: '10000',
    };
    const revoke = buildSentryRevocation({
      chain: activeChain,
      node,
      inputs: funding,
      outputs,
      reason: 2,
    });
    assert.equal(
      reviewSentryManagementOperation(revoke, context).authorizations[0].digest,
      vectors.pqRevoke.digest
    );
    const signedRevoke = await signSentryManagementOperation(
      revoke,
      context,
      operator
    );
    assert.equal(
      hex(
        managementPayload(signedRevoke.transactionHex).payload.primarySignature
      ),
      vectors.pqRevoke.signature
    );
    const initialNode = {
      ...node,
      pqRecord: undefined,
      globalKeyVersion: undefined,
    };
    const initial = buildSentryOperatorUpdate({
      chain: activeChain,
      node: initialNode,
      inputs: funding,
      outputs,
      mode: 'initial',
      candidate: { ...record, activatedHeight: 0 },
    });
    const initialContext = { ...context, node: initialNode };
    const review = reviewSentryManagementOperation(initial, initialContext);
    assert.equal(
      review.authorizations[0].digest,
      vectors.globalInitial.ownerDigest
    );
    assert.equal(
      review.authorizations[1].digest,
      vectors.globalInitial.operatorDigest
    );
    const signedOwner = await signSentryManagementOperation(
      initial,
      initialContext,
      owner
    );
    assert.equal(
      hex(managementPayload(signedOwner.transactionHex).payload.ownerProof),
      vectors.globalInitial.ownerSignature
    );
    const signedOperator = await signSentryManagementOperation(
      { ...initial, transactionHex: signedOwner.transactionHex },
      initialContext,
      operator
    );
    assert.equal(signedOperator.complete, true);
    assert.equal(
      hex(
        managementPayload(signedOperator.transactionHex).payload
          .primarySignature
      ),
      vectors.globalInitial.operatorSignature
    );
  }
);

test(
  'Core PQ owner proofs, dual-owner registrar and global rotation domains match',
  { timeout: 120_000 },
  async () => {
    const owner = await importSentryAuthorityKey(
      'owner',
      'slh-dsa-shake-128s',
      pq.secretKey
    );
    const operator = { ...owner, role: 'operator' };
    const activeChain = { ...chain, era: 'pq-v4' };
    const record = {
      version: 1,
      profile: 1,
      keyVersion: 1,
      publicKey: owner.publicKey,
      childKeyCommitmentHex: pq.childKeyCommitmentHex,
      activatedHeight: 1440,
    };
    const node = {
      proTxHash: '11'.repeat(32),
      operatorPublicKey: owner.publicKey,
      globalKeyVersion: 1,
      pqRecord: record,
      ownerKeyId: '66'.repeat(20),
      votingKeyId: '77'.repeat(20),
      service: '127.0.0.1:18367',
      operatorPayoutScript: payout,
      payoutScript: payout,
      nevmAddress: '',
      pqVotingPublicKey: '99'.repeat(32),
      pqOwnerRecord: {
        publicKey: owner.publicKey,
        keyVersion: 1,
        activatedHeight: 100,
      },
    };
    const context = {
      chain: activeChain,
      network,
      node,
      previousTransactions: [vectors.fundingTransaction],
      maxFeeSatoshis: '10000',
    };
    const registration = buildSentryRegistration({
      chain: activeChain,
      inputs: funding,
      outputs,
      collateralOutpoint: { txid: '33'.repeat(32), vout: 2 },
      service: node.service,
      ownerKeyId: node.ownerKeyId,
      votingKeyId: node.votingKeyId,
      pqOwnerPublicKey: owner.publicKey,
      pqVotingPublicKey: node.pqVotingPublicKey,
      operatorRewardBasisPoints: 250,
      payoutScript: payout,
    });
    const regPayload = managementPayload(registration.transactionHex).payload;
    assert.equal(
      hex(managementPayloadBytes(regPayload, true)),
      vectors.pqOwnerRegistration.preimage
    );
    const digest = ownerDigest(regPayload, context);
    assert.equal(hex(digest), vectors.pqOwnerRegistration.digest);
    const { slh_dsa_shake_128s } = await import(
      '@noble/post-quantum/slh-dsa.js'
    );
    assert.equal(
      hex(
        hash256(
          slh_dsa_shake_128s.sign(digest, fromHex(owner.secretKey), {
            context: new TextEncoder().encode('SYS_PQ_OWNER_PROOF_V1'),
            extraEntropy: false,
          })
        )
      ),
      vectors.pqOwnerRegistration.proofHash
    );
    const update = buildSentryRegistrarUpdate({
      chain: activeChain,
      node,
      inputs: funding,
      outputs,
      pqOwnerPublicKey: owner.publicKey,
    });
    assert.equal(
      hex(
        managementPayloadBytes(
          managementPayload(update.transactionHex).payload,
          true
        )
      ),
      vectors.pqRegistrar.preimage
    );
    assert.equal(
      reviewSentryManagementOperation(update, context).authorizations[0].digest,
      vectors.pqRegistrar.digest
    );
    const first = await signSentryManagementOperation(
      update,
      context,
      owner,
      'owner'
    );
    assert.equal(
      hex(
        hash256(
          managementPayload(first.transactionHex).payload.primarySignature
        )
      ),
      vectors.pqRegistrar.updateSignatureHash
    );
    const second = await signSentryManagementOperation(
      { ...update, transactionHex: first.transactionHex },
      context,
      owner,
      'newOwner'
    );
    assert.equal(
      hex(hash256(managementPayload(second.transactionHex).payload.ownerProof)),
      vectors.pqRegistrar.proofHash
    );
    assert.equal(second.complete, true);
    const initialNode = {
      ...node,
      pqRecord: undefined,
      globalKeyVersion: undefined,
    };
    const initial = buildSentryOperatorUpdate({
      chain: activeChain,
      node: initialNode,
      inputs: funding,
      outputs,
      mode: 'initial',
      candidate: { ...record, activatedHeight: 0 },
    });
    const initialContext = { ...context, node: initialNode };
    assert.equal(
      reviewSentryManagementOperation(initial, initialContext).authorizations[0]
        .digest,
      vectors.globalPQOwner.digest
    );
    const signed = await signSentryManagementOperation(
      initial,
      initialContext,
      owner,
      'owner'
    );
    assert.equal(
      hex(hash256(managementPayload(signed.transactionHex).payload.ownerProof)),
      vectors.globalPQOwner.signatureHash
    );
    assert.equal(signed.complete, false);
    const completedInitial = await signSentryManagementOperation(
      { ...initial, transactionHex: signed.transactionHex },
      initialContext,
      operator,
      'newOperator'
    );
    assert.equal(completedInitial.complete, true);
    const completedRequest = {
      ...initial,
      transactionHex: completedInitial.transactionHex,
    };
    assert.equal(
      await verifySentryManagementOperation(completedRequest, initialContext),
      true
    );
    assert.equal(matchesSentryManagementIntent(initial, completedRequest), true);
    const completedTransaction = decodeSentryTransaction(
      completedInitial.transactionHex
    );
    const dataOutput = completedTransaction.outputs.find((output) =>
      output.scriptHex.startsWith('6a')
    );
    // Core's PQ-owner exception permits two SLH signatures in these exact
    // canonical special payload versions, without raising ordinary limits.
    assert.ok(dataOutput.scriptHex.length / 2 > 10_000);
    assert.ok(dataOutput.scriptHex.length / 2 <= 2 * 7856 + 1024);
    const rotate = buildSentryOperatorUpdate({
      chain: activeChain,
      node,
      inputs: funding,
      outputs,
      mode: 'rotate',
      candidate: {
        ...record,
        keyVersion: 2,
        publicKey: vectors.globalRotation.candidatePublicKey,
        activatedHeight: 0,
      },
    });
    assert.equal(
      reviewSentryManagementOperation(rotate, context).authorizations[0].digest,
      vectors.globalRotation.digest
    );
    const rotated = await signSentryManagementOperation(
      rotate,
      context,
      operator
    );
    assert.equal(rotated.complete, true);
    assert.equal(
      hex(
        hash256(
          managementPayload(rotated.transactionHex).payload.primarySignature
        )
      ),
      vectors.globalRotation.signatureHash
    );
  }
);
