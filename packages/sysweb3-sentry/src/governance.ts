import { base64 } from '@scure/base';

import {
  concat,
  displayHash,
  fail,
  fromHex,
  hash256,
  hashBytes,
  hex,
  integerBytes,
  object,
  uint,
} from './bytes.js';
import { sentryKeyId } from './management.js';

import type { SentryAuthorityKey } from './management-types.js';

export const MAX_GOVERNANCE_VOTE_NODES = 20;
export interface SentryGovernanceOutpoint {
  txid: string;
  vout: number;
}
export interface SentryGovernanceVoteNode {
  proTxHash: string;
  collateralOutpoint: SentryGovernanceOutpoint;
}
export interface SentryGovernanceVoteFields {
  proposalHash: string;
  signal: 'funding';
  outcome: 'yes' | 'no' | 'abstain';
  timestamp: number;
  collateralOutpoint: SentryGovernanceOutpoint;
}
export interface SentryGovernanceVoteRequest
  extends Omit<SentryGovernanceVoteFields, 'collateralOutpoint'> {
  version: 1;
  chain: { genesisHash: string; era: 'legacy-v3' };
  nodes: SentryGovernanceVoteNode[];
}
export interface SentryGovernanceVotingNode extends SentryGovernanceVoteNode {
  /** Current voting Hash160 from independently resolved node registration. */
  votingKeyId: string;
  valid: true;
}
export interface SentryGovernanceVoteContext {
  chain: { genesisHash: string; era: 'legacy-v3' | 'pq-v4' };
  /** Independently resolved proposal and current time, not caller assertions. */
  proposalHash: string;
  /** Presentation metadata from the independently resolved proposal; not signed. */
  proposal?: { name: string; url?: string };
  now: number;
  nodes: SentryGovernanceVotingNode[];
}
export interface SentryGovernanceVoteReview {
  request: SentryGovernanceVoteRequest;
  proposal?: { name: string; url?: string };
  nodes: Array<
    SentryGovernanceVotingNode & { digest: string; voteHash: string }
  >;
}
export interface SentryGovernanceVoteResponse extends SentryGovernanceVoteNode {
  /** Canonical base64 of Core's 65-byte recoverable ECDSA signature. */
  voteSig: string;
  /** Core uint256 display order; digest() returns the raw signing bytes instead. */
  signatureHash: string;
  voteHash: string;
}

function canonicalHash(value: unknown, name: string, size = 32): string {
  if (
    typeof value !== 'string' ||
    !new RegExp(`^[0-9a-f]{${size * 2}}$`).test(value) ||
    /^0+$/.test(value)
  )
    fail('INVALID_HASH', `${name} must be nonzero lowercase ${size}-byte hex`);
  return value;
}
function safeTime(value: unknown, name: string): number {
  if (
    typeof value !== 'number' ||
    !Number.isSafeInteger(value) ||
    value < 0 ||
    Object.is(value, -0)
  )
    fail(
      'INVALID_TIME',
      `${name} must be a nonnegative safe integer of Unix seconds`
    );
  return value;
}
function outpoint(value: unknown): SentryGovernanceOutpoint {
  const p = object(value, ['txid', 'vout'], 'collateral outpoint');
  const vout = uint(p.vout, 32, 'collateral output index');
  // voteraw parses this RPC parameter as a signed C++ int before constructing COutPoint.
  if (vout > 0x7fffffff || Object.is(vout, -0))
    fail('INVALID_OUTPOINT', 'Collateral index exceeds voteraw range');
  return { txid: canonicalHash(p.txid, 'collateral txid'), vout };
}
function node(
  value: unknown,
  trusted = false
): SentryGovernanceVotingNode | SentryGovernanceVoteNode {
  const n = object(
    value,
    trusted
      ? ['proTxHash', 'collateralOutpoint', 'votingKeyId', 'valid']
      : ['proTxHash', 'collateralOutpoint'],
    'voting node'
  );
  const result = {
    proTxHash: canonicalHash(n.proTxHash, 'proTxHash'),
    collateralOutpoint: outpoint(n.collateralOutpoint),
  };
  if (!trusted) return result;
  if (n.valid !== true)
    fail('INVALID_NODE', 'Voting node is not currently valid');
  return {
    ...result,
    votingKeyId: canonicalHash(n.votingKeyId, 'voting key ID', 20),
    valid: true,
  };
}
function chain(value: unknown, legacyOnly = true) {
  const c = object(value, ['genesisHash', 'era'], 'chain');
  if (c.era !== 'legacy-v3' && (legacyOnly || c.era !== 'pq-v4'))
    fail(
      'UNSUPPORTED_ERA',
      'Pali governance voting currently supports legacy secp256k1 only'
    );
  return {
    genesisHash: canonicalHash(c.genesisHash, 'genesis hash'),
    era: c.era as 'legacy-v3' | 'pq-v4',
  };
}
function fields(value: unknown): SentryGovernanceVoteFields {
  const f = object(
    value,
    ['proposalHash', 'signal', 'outcome', 'timestamp', 'collateralOutpoint'],
    'vote fields'
  );
  if (f.signal !== 'funding')
    fail(
      'UNSUPPORTED_SIGNAL',
      'Only proposal funding votes use the voting key'
    );
  if (f.outcome !== 'yes' && f.outcome !== 'no' && f.outcome !== 'abstain')
    fail('INVALID_OUTCOME', 'Unsupported vote outcome');
  return {
    proposalHash: canonicalHash(f.proposalHash, 'proposal hash'),
    signal: 'funding',
    outcome: f.outcome,
    timestamp: safeTime(f.timestamp, 'timestamp'),
    collateralOutpoint: outpoint(f.collateralOutpoint),
  };
}
export function validateSentryGovernanceVoteRequest(
  value: unknown
): SentryGovernanceVoteRequest {
  const r = object(
    value,
    [
      'version',
      'chain',
      'proposalHash',
      'signal',
      'outcome',
      'timestamp',
      'nodes',
    ],
    'governance vote'
  );
  if (r.version !== 1)
    fail('UNSUPPORTED_VERSION', 'Unsupported governance vote request');
  const c = chain(r.chain);
  if (
    !Array.isArray(r.nodes) ||
    r.nodes.length < 1 ||
    r.nodes.length > MAX_GOVERNANCE_VOTE_NODES
  )
    fail('INVALID_BATCH', 'Select between 1 and 20 voting nodes');
  const nodes = r.nodes.map((n) => node(n) as SentryGovernanceVoteNode);
  const ids = new Set(nodes.map((n) => n.proTxHash));
  const outputs = new Set(
    nodes.map(
      (n) => `${n.collateralOutpoint.txid}:${n.collateralOutpoint.vout}`
    )
  );
  if (ids.size !== nodes.length || outputs.size !== nodes.length)
    fail('DUPLICATE_NODE', 'Duplicate voting node or collateral');
  const f = fields({
    proposalHash: r.proposalHash,
    signal: r.signal,
    outcome: r.outcome,
    timestamp: r.timestamp,
    collateralOutpoint: nodes[0].collateralOutpoint,
  });
  return {
    version: 1,
    chain: { ...c, era: 'legacy-v3' },
    proposalHash: f.proposalHash,
    signal: f.signal,
    outcome: f.outcome,
    timestamp: f.timestamp,
    nodes,
  };
}
function preimage(value: unknown, identity = false): Uint8Array {
  const f = fields(value);
  const outcome = { yes: 1, no: 2, abstain: 3 }[f.outcome];
  return concat(
    hashBytes(f.collateralOutpoint.txid),
    integerBytes(f.collateralOutpoint.vout, 4),
    hashBytes(f.proposalHash),
    integerBytes(identity ? 1 : outcome, 4),
    integerBytes(identity ? outcome : 1, 4),
    integerBytes(f.timestamp, 8)
  );
}
/** Raw digest bytes for GetSignatureHash: outcome then signal, unlike GetHash. */
export function governanceVoteDigest(
  value: SentryGovernanceVoteFields
): string {
  return hex(hash256(preimage(value)));
}
/** Core's vote identity uses signal then outcome, in uint256 display order. */
export function governanceVoteHash(value: SentryGovernanceVoteFields): string {
  return displayHash(hash256(preimage(value, true)));
}
/** Legacy funding votes support either registered public-key encoding. */
export async function governanceVotingKeyIds(
  compressedPublicKey: string
): Promise<{ compressed: string; uncompressed: string }> {
  if (!/^(02|03)[0-9a-f]{64}$/.test(compressedPublicKey))
    fail('INVALID_KEY', 'Expected a canonical compressed voting public key');
  const { secp256k1 } = await import('@noble/curves/secp256k1.js');
  const point = secp256k1.Point.fromBytes(fromHex(compressedPublicKey));
  return {
    compressed: sentryKeyId(compressedPublicKey),
    uncompressed: sentryKeyId(hex(point.toBytes(false))),
  };
}
export function reviewSentryGovernanceVote(
  value: unknown,
  context: SentryGovernanceVoteContext
): SentryGovernanceVoteReview {
  const request = validateSentryGovernanceVoteRequest(value);
  const c = chain(context.chain, false);
  if (
    c.era !== request.chain.era ||
    c.genesisHash !== request.chain.genesisHash
  )
    fail('CHAIN_MISMATCH', 'Voting network or protocol changed');
  if (
    canonicalHash(context.proposalHash, 'verified proposal hash') !==
    request.proposalHash
  )
    fail('PROPOSAL_MISMATCH', 'Verified proposal differs');
  const now = safeTime(context.now, 'current time');
  // Core rejects only future votes; new wallet approvals deliberately also
  // refuse stale timestamps rather than authorizing replayable old drafts.
  if (Math.abs(request.timestamp - now) > 3600)
    fail(
      'STALE_VOTE',
      'New vote approval must be within one hour of current time'
    );
  let proposal: SentryGovernanceVoteContext['proposal'];
  if (context.proposal !== undefined) {
    const p = object(context.proposal, ['name', 'url'], 'proposal metadata');
    if (typeof p.name !== 'string' || p.name.length < 1 || p.name.length > 256)
      fail('INVALID_PROPOSAL', 'Invalid proposal name');
    if (p.url !== undefined) {
      if (typeof p.url !== 'string' || p.url.length > 2048)
        fail('INVALID_PROPOSAL', 'Invalid proposal URL');
      try {
        if (!['https:', 'http:'].includes(new URL(p.url).protocol))
          throw new Error();
      } catch {
        fail('INVALID_PROPOSAL', 'Invalid proposal URL');
      }
    }
    proposal = {
      name: p.name,
      ...(p.url === undefined ? {} : { url: p.url as string }),
    };
  }
  if (
    !Array.isArray(context.nodes) ||
    context.nodes.length !== request.nodes.length
  )
    fail('NODE_MISMATCH', 'Every voting node requires verified context');
  const verified = context.nodes.map(
    (n) => node(n, true) as SentryGovernanceVotingNode
  );
  if (new Set(verified.map((n) => n.proTxHash)).size !== verified.length)
    fail('DUPLICATE_NODE', 'Duplicate verified voting node');
  const nodes = request.nodes.map((n) => {
    const v = verified.find((v) => v.proTxHash === n.proTxHash);
    if (
      !v ||
      v.collateralOutpoint.txid !== n.collateralOutpoint.txid ||
      v.collateralOutpoint.vout !== n.collateralOutpoint.vout
    )
      fail(
        'NODE_MISMATCH',
        'Voting collateral differs from current registration'
      );
    const f = {
      proposalHash: request.proposalHash,
      signal: request.signal,
      outcome: request.outcome,
      timestamp: request.timestamp,
      collateralOutpoint: n.collateralOutpoint,
    };
    return {
      ...v,
      digest: governanceVoteDigest(f),
      voteHash: governanceVoteHash(f),
    };
  });
  return { request, ...(proposal ? { proposal } : {}), nodes };
}
export async function signSentryGovernanceVote(
  value: unknown,
  context: SentryGovernanceVoteContext,
  proTxHash: string,
  key: SentryAuthorityKey
): Promise<SentryGovernanceVoteResponse> {
  const review = reviewSentryGovernanceVote(value, context);
  const n = review.nodes.find((n) => n.proTxHash === proTxHash);
  if (!n) fail('NODE_MISMATCH', 'Selected voting node was not approved');
  if (key.role !== 'voting' || key.scheme !== 'secp256k1')
    fail(
      'INVALID_KEY_ROLE',
      'Legacy governance requires a secp256k1 voting key'
    );
  const secret = fromHex(key.secretKey, 'voting secret', 32);
  try {
    const { secp256k1 } = await import('@noble/curves/secp256k1.js');
    const publicKey = hex(secp256k1.getPublicKey(secret, true));
    const ids = await governanceVotingKeyIds(publicKey);
    if (
      publicKey !== key.publicKey ||
      (ids.compressed !== n.votingKeyId && ids.uncompressed !== n.votingKeyId)
    )
      fail('WRONG_KEY', 'Key does not match the verified voting registration');
    const signature = secp256k1.sign(fromHex(n.digest), secret, {
      prehash: false,
      format: 'recovered',
      lowS: true,
    });
    signature[0] += ids.compressed === n.votingKeyId ? 31 : 27;
    return {
      proTxHash: n.proTxHash,
      collateralOutpoint: n.collateralOutpoint,
      voteSig: base64.encode(signature),
      signatureHash: displayHash(fromHex(n.digest)),
      voteHash: n.voteHash,
    };
  } finally {
    secret.fill(0);
  }
}
export async function verifySentryGovernanceVote(
  value: unknown,
  context: SentryGovernanceVoteContext,
  response: SentryGovernanceVoteResponse
): Promise<boolean> {
  try {
    const review = reviewSentryGovernanceVote(value, context);
    const r = object(
      response,
      [
        'proTxHash',
        'collateralOutpoint',
        'voteSig',
        'signatureHash',
        'voteHash',
      ],
      'vote signature'
    );
    const n = review.nodes.find((n) => n.proTxHash === r.proTxHash);
    const p = outpoint(r.collateralOutpoint);
    if (
      !n ||
      p.txid !== n.collateralOutpoint.txid ||
      p.vout !== n.collateralOutpoint.vout ||
      r.signatureHash !== displayHash(fromHex(n.digest)) ||
      r.voteHash !== n.voteHash ||
      typeof r.voteSig !== 'string'
    )
      return false;
    const signature = base64.decode(r.voteSig);
    if (
      base64.encode(signature) !== r.voteSig ||
      signature.length !== 65 ||
      signature[0] < 27 ||
      signature[0] > 34
    )
      return false;
    const { secp256k1 } = await import('@noble/curves/secp256k1.js');
    if (secp256k1.Signature.fromBytes(signature.slice(1), 'compact').hasHighS())
      return false;
    const compressed = signature[0] >= 31;
    signature[0] -= compressed ? 31 : 27;
    const recovered = secp256k1.recoverPublicKey(signature, fromHex(n.digest), {
      prehash: false,
    });
    return (
      sentryKeyId(
        hex(secp256k1.Point.fromBytes(recovered).toBytes(compressed))
      ) === n.votingKeyId
    );
  } catch {
    return false;
  }
}
