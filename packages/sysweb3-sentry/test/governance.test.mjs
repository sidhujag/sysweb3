import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  governanceVoteDigest,
  governanceVoteHash,
  governanceVotingKeyIds,
  importSentryAuthorityKey,
  reviewSentryGovernanceVote,
  sentryKeyId,
  signSentryGovernanceVote,
  validateSentryGovernanceVoteRequest,
  verifySentryGovernanceVote,
} from '../dist/index.js';

const key = await importSentryAuthorityKey(
  'voting',
  'secp256k1',
  '00'.repeat(31) + '01'
);
const chain = { genesisHash: '11'.repeat(32), era: 'legacy-v3' };
const request = {
  version: 1,
  chain,
  proposalHash: '22'.repeat(32),
  signal: 'funding',
  outcome: 'yes',
  timestamp: 1700000000,
  nodes: [
    {
      proTxHash: '33'.repeat(32),
      collateralOutpoint: { txid: '44'.repeat(32), vout: 1 },
    },
  ],
};
const context = {
  chain,
  now: request.timestamp,
  proposalHash: request.proposalHash,
  proposal: { name: 'Public proposal', url: 'https://example.com/proposal' },
  nodes: [
    {
      ...request.nodes[0],
      votingKeyId: sentryKeyId(key.publicKey),
      valid: true,
    },
  ],
};
const copy = (value) => structuredClone(value);

test('supports legacy uncompressed voting identity without changing stored public key encoding', async () => {
  const ids = await governanceVotingKeyIds(key.publicKey);
  assert.notEqual(ids.compressed, ids.uncompressed);
  assert.equal(ids.compressed, sentryKeyId(key.publicKey));
  const c = copy(context);
  c.nodes[0].votingKeyId = ids.uncompressed;
  const response = await signSentryGovernanceVote(
    request,
    c,
    request.nodes[0].proTxHash,
    key
  );
  const sig = Buffer.from(response.voteSig, 'base64');
  assert(sig[0] >= 27 && sig[0] <= 30);
  assert.equal(await verifySentryGovernanceVote(request, c, response), true);
  assert.equal(
    await verifySentryGovernanceVote(request, context, response),
    false
  );
  sig[0] += 4;
  assert.equal(
    await verifySentryGovernanceVote(request, c, {
      ...response,
      voteSig: sig.toString('base64'),
    }),
    false
  );
  c.nodes[0].votingKeyId = '88'.repeat(20);
  await assert.rejects(
    signSentryGovernanceVote(request, c, request.nodes[0].proTxHash, key)
  );
  await assert.rejects(governanceVotingKeyIds('04' + '00'.repeat(64)));
  await assert.rejects(governanceVotingKeyIds('02' + 'ff'.repeat(32)));
});

test('bounds complete batch review to twenty distinct verified nodes', () => {
  const r = copy(request);
  r.nodes = Array.from({ length: 20 }, (_, i) => ({
    proTxHash: (i + 1).toString(16).padStart(64, '0'),
    collateralOutpoint: { txid: '44'.repeat(32), vout: i },
  }));
  const c = copy(context);
  c.nodes = r.nodes.map((n) => ({
    ...n,
    votingKeyId: context.nodes[0].votingKeyId,
    valid: true,
  }));
  assert.equal(reviewSentryGovernanceVote(r, c).nodes.length, 20);
  c.nodes[1].proTxHash = c.nodes[0].proTxHash;
  assert.throws(() => reviewSentryGovernanceVote(r, c));
});

test('signs only the independently verified voting authority and returns no key', async () => {
  const response = await signSentryGovernanceVote(
    request,
    context,
    request.nodes[0].proTxHash,
    key
  );
  assert.equal(
    await verifySentryGovernanceVote(request, context, response),
    true
  );
  assert.equal(Buffer.from(response.voteSig, 'base64').length, 65);
  assert.deepEqual(Object.keys(response).sort(), [
    'collateralOutpoint',
    'proTxHash',
    'signatureHash',
    'voteHash',
    'voteSig',
  ]);
  assert.equal(JSON.stringify(response).includes(key.secretKey), false);
  const review = reviewSentryGovernanceVote(request, context);
  assert.deepEqual(review.proposal, context.proposal);
  assert.equal(review.nodes[0].votingKeyId, context.nodes[0].votingKeyId);
  const wrongKey = await importSentryAuthorityKey(
    'voting',
    'secp256k1',
    '00'.repeat(31) + '02'
  );
  await assert.rejects(
    signSentryGovernanceVote(
      request,
      context,
      request.nodes[0].proTxHash,
      wrongKey
    )
  );
  await assert.rejects(
    signSentryGovernanceVote(request, context, request.nodes[0].proTxHash, {
      ...key,
      role: 'owner',
    })
  );
  await assert.rejects(
    signSentryGovernanceVote(request, context, request.nodes[0].proTxHash, {
      ...key,
      scheme: 'slh-dsa-shake-128s',
    })
  );
  await assert.rejects(
    signSentryGovernanceVote(request, context, request.nodes[0].proTxHash, {
      ...key,
      secretKey: wrongKey.secretKey,
    })
  );
});

test('binds chain, proposal, every node, current voting identity and fresh timestamp', () => {
  for (const mutate of [
    (c) => (c.chain.genesisHash = '55'.repeat(32)),
    (c) => (c.chain.era = 'pq-v4'),
    (c) => (c.proposalHash = '55'.repeat(32)),
    (c) => (c.nodes[0].proTxHash = '55'.repeat(32)),
    (c) => (c.nodes[0].collateralOutpoint.txid = '55'.repeat(32)),
    (c) => c.nodes[0].collateralOutpoint.vout++,
    (c) => (c.nodes[0].valid = false),
    (c) => (c.nodes = []),
    (c) => (c.now += 3601),
    (c) => (c.now -= 3601),
  ]) {
    const c = copy(context);
    mutate(c);
    assert.throws(() => reviewSentryGovernanceVote(request, c));
  }
  for (const offset of [-3600, 3600]) {
    const c = copy(context);
    c.now += offset;
    assert.doesNotThrow(() => reviewSentryGovernanceVote(request, c));
  }
  const c = copy(context);
  c.proposal.name = 'Changed display name';
  assert.equal(
    reviewSentryGovernanceVote(request, c).nodes[0].digest,
    reviewSentryGovernanceVote(request, context).nodes[0].digest
  );
});

test('rejects malformed, noncanonical, unsupported and oversized requests', () => {
  for (const mutate of [
    (r) => (r.extra = true),
    (r) => (r.version = 2),
    (r) => (r.chain.era = 'pq-v4'),
    (r) => (r.chain.genesisHash = '0'.repeat(64)),
    (r) => (r.proposalHash = 'AA'.repeat(32)),
    (r) => (r.proposalHash = '0x' + '22'.repeat(32)),
    (r) => (r.signal = 'valid'),
    (r) => (r.outcome = 'none'),
    (r) => (r.outcome = 'constructor'),
    (r) => (r.timestamp = -1),
    (r) => (r.timestamp = -0),
    (r) => (r.timestamp = 1.5),
    (r) => (r.timestamp = Number.MAX_SAFE_INTEGER + 1),
    (r) => (r.timestamp = '1700000000'),
    (r) => (r.nodes = []),
    (r) => r.nodes.push(copy(r.nodes[0])),
    (r) => (r.nodes[0].collateralOutpoint.vout = 2147483648),
    (r) => (r.nodes[0].collateralOutpoint.vout = -0),
    (r) => (r.nodes[0].collateralOutpoint.vout = -1),
    (r) => (r.nodes[0].collateralOutpoint.vout = 0.5),
    (r) => (r.nodes[0].collateralOutpoint.extra = true),
    (r) => (r.nodes[0].extra = true),
    (r) =>
      (r.nodes = Array.from({ length: 21 }, (_, i) => ({
        proTxHash: (i + 1).toString(16).padStart(64, '0'),
        collateralOutpoint: { txid: '44'.repeat(32), vout: i },
      }))),
  ]) {
    const r = copy(request);
    mutate(r);
    assert.throws(() => validateSentryGovernanceVoteRequest(r));
  }
  assert.throws(() => validateSentryGovernanceVoteRequest(null));
  assert.throws(() =>
    validateSentryGovernanceVoteRequest(
      Object.assign(Object.create({ injected: true }), request)
    )
  );
});

test('rejects mutated or noncanonical signatures and swapped node identity', async () => {
  const response = await signSentryGovernanceVote(
    request,
    context,
    request.nodes[0].proTxHash,
    key
  );
  for (const mutate of [
    (r) => (r.proTxHash = '55'.repeat(32)),
    (r) => (r.signatureHash = '55'.repeat(32)),
    (r) => (r.voteHash = '55'.repeat(32)),
    (r) => r.collateralOutpoint.vout++,
    (r) => (r.voteSig += '\n'),
    (r) => (r.voteSig = r.voteSig.slice(0, -1)),
    (r) => (r.voteSig = Buffer.alloc(65).toString('base64')),
    (r) => (r.extra = true),
  ]) {
    const r = copy(response);
    mutate(r);
    assert.equal(await verifySentryGovernanceVote(request, context, r), false);
  }
  for (const property of ['outcome', 'timestamp', 'proposalHash']) {
    const r = copy(request);
    r[property] =
      property === 'outcome'
        ? 'no'
        : property === 'timestamp'
        ? request.timestamp + 1
        : '55'.repeat(32);
    const c = copy(context);
    c.proposalHash = r.proposalHash;
    assert.equal(await verifySentryGovernanceVote(r, c, response), false);
  }
  const highS = Buffer.from(response.voteSig, 'base64');
  const order = BigInt(
    '0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'
  );
  const s = BigInt('0x' + highS.subarray(33).toString('hex'));
  Buffer.from((order - s).toString(16).padStart(64, '0'), 'hex').copy(
    highS,
    33
  );
  highS[0] = 31 + ((highS[0] - 31) ^ 1);
  assert.equal(
    await verifySentryGovernanceVote(request, context, {
      ...response,
      voteSig: highS.toString('base64'),
    }),
    false
  );
});

test('matches native Core GetSignatureHash, GetHash and deterministic compact signatures', async () => {
  const vectors = JSON.parse(
    readFileSync(
      new URL('./fixtures/governance-core-vectors.json', import.meta.url),
      'utf8'
    )
  );
  for (const v of vectors) {
    const r = copy(request);
    Object.assign(r, {
      proposalHash: v.proposalHash,
      outcome: ['none', 'yes', 'no', 'abstain'][v.outcome],
      timestamp: v.timestamp,
    });
    r.nodes[0].collateralOutpoint = {
      txid: v.collateralHash,
      vout: v.collateralIndex,
    };
    const c = copy(context);
    Object.assign(c, { now: v.timestamp, proposalHash: v.proposalHash });
    c.nodes[0] = {
      ...r.nodes[0],
      votingKeyId: sentryKeyId(v.publicKey),
      valid: true,
    };
    const f = {
      proposalHash: r.proposalHash,
      signal: r.signal,
      outcome: r.outcome,
      timestamp: r.timestamp,
      collateralOutpoint: r.nodes[0].collateralOutpoint,
    };
    assert.equal(governanceVoteDigest(f), v.digest);
    assert.equal(governanceVoteHash(f), v.voteHash);
    assert.equal(
      v.compressed === false
        ? (await governanceVotingKeyIds(key.publicKey)).uncompressed
        : sentryKeyId(key.publicKey),
      sentryKeyId(v.publicKey)
    );
    const signed = await signSentryGovernanceVote(
      r,
      c,
      r.nodes[0].proTxHash,
      key
    );
    assert.equal(signed.signatureHash, v.signatureHash);
    assert.equal(signed.voteSig, v.voteSig);
    assert.equal(await verifySentryGovernanceVote(r, c, signed), true);
  }
});
