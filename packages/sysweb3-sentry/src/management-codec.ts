import { bech32, bech32m, base58check } from '@scure/base';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  Reader,
  amount,
  concat,
  displayHash,
  fail,
  fromHex,
  hash256,
  hashBytes,
  hex,
  integerBytes,
  nonzero,
  object,
  uint,
  vector,
} from './bytes.js';
import {
  BLS_SIGNATURE_SIZE,
  PQ_SIGNATURE_SIZE,
  type ServiceAddress,
  decodeSentryTransaction,
  encodeTransaction,
  extractOpReturn,
  opReturn,
  parseService,
  serviceFromBytes,
} from './codec.js';
import type {
  SentryChain,
  SentryPQRecord,
  SentryTxInput,
  SentryTxOutput,
} from './types.js';
import { serializePQRecord } from './review.js';
import type {
  BuildSentryRegistration,
  BuildSentryRegistrarUpdate,
  BuildSentryRevocation,
  BuildSentryOperatorUpdate,
  SentryManagementRequest,
  SentryNetworkEncoding,
} from './management-types.js';

interface BasePayload {
  kind: SentryManagementRequest['operation'];
  version: 1 | 2 | 3;
  inputsHash: Uint8Array;
  primarySignature: Uint8Array;
  ownerProof: Uint8Array;
}
export interface RegistrationPayload extends BasePayload {
  kind: 'register';
  collateralTxid: string;
  collateralVout: number;
  service: ServiceAddress;
  ownerKeyId: Uint8Array;
  votingKeyId: Uint8Array;
  operatorPublicKey: Uint8Array;
  reward: number;
  payoutScript: Uint8Array;
  pqVotingPublicKey: Uint8Array;
  pqOwnerPublicKey: Uint8Array;
}
export interface RegistrarPayload extends BasePayload {
  kind: 'updateRegistrar';
  proTxHash: string;
  votingKeyId: Uint8Array;
  operatorPublicKey: Uint8Array;
  payoutScript: Uint8Array;
  pqVotingPublicKey: Uint8Array;
  pqOwnerPublicKey: Uint8Array;
  ownerKeyVersion: number;
}
export interface RevokePayload extends BasePayload {
  kind: 'revoke';
  proTxHash: string;
  reason: number;
  globalKeyVersion: number;
}
export interface OperatorPayload extends BasePayload {
  kind: 'registerOperator' | 'rotateOperator';
  proTxHash: string;
  candidate: SentryPQRecord;
  ownerKeyVersion: number;
}
export type ManagementPayload =
  | RegistrationPayload
  | RegistrarPayload
  | RevokePayload
  | OperatorPayload;
export const MANAGEMENT_TX_VERSION = {
  register: 80,
  updateRegistrar: 82,
  revoke: 83,
  registerOperator: 86,
  rotateOperator: 86,
} as const;

export function managementPayloadBytes(
  p: ManagementPayload,
  hashing = false
): Uint8Array {
  const version = integerBytes(p.version, 2);
  if (p.kind === 'registerOperator' || p.kind === 'rotateOperator')
    return concat(
      version,
      Uint8Array.of(p.kind === 'registerOperator' ? 1 : 2),
      hashBytes(p.proTxHash),
      serializePQRecord(p.candidate, true),
      p.inputsHash,
      ...(p.version === 2 ? [integerBytes(p.ownerKeyVersion, 4)] : []),
      ...(hashing ? [] : [p.ownerProof, p.primarySignature])
    );
  const signatures = hashing
    ? new Uint8Array()
    : p.kind === 'revoke'
    ? p.primarySignature
    : concat(
        vector(p.primarySignature),
        ...(p.version === 3 ? [p.ownerProof] : [])
      );
  if (p.kind === 'register')
    return concat(
      version,
      integerBytes(0, 2),
      integerBytes(0, 2),
      hashBytes(p.collateralTxid, 'collateral txid'),
      integerBytes(p.collateralVout, 4),
      p.service.bytes,
      p.ownerKeyId,
      ...(p.version === 2 ? [p.operatorPublicKey] : []),
      p.votingKeyId,
      integerBytes(p.reward, 2),
      vector(p.payoutScript),
      p.inputsHash,
      ...(p.version === 3 ? [p.pqVotingPublicKey, p.pqOwnerPublicKey] : []),
      signatures
    );
  if (p.kind === 'updateRegistrar')
    return concat(
      version,
      hashBytes(p.proTxHash, 'proTxHash'),
      integerBytes(0, 2),
      ...(p.version === 2 ? [p.operatorPublicKey] : []),
      p.votingKeyId,
      vector(p.payoutScript),
      p.inputsHash,
      ...(p.version === 3
        ? [
            p.pqVotingPublicKey,
            p.pqOwnerPublicKey,
            integerBytes(p.ownerKeyVersion, 4),
          ]
        : []),
      signatures
    );
  if (p.kind !== 'revoke')
    fail('UNSUPPORTED_OPERATION', 'Unknown node payload');
  return concat(
    version,
    hashBytes(p.proTxHash, 'proTxHash'),
    integerBytes(p.reason, 2),
    p.inputsHash,
    ...(p.version === 3 ? [integerBytes(p.globalKeyVersion, 4)] : []),
    signatures
  );
}

export function managementPayload(
  txHex: string,
  expected?: SentryManagementRequest['operation']
): { payload: ManagementPayload; outputIndex: number } {
  const tx = decodeSentryTransaction(txHex);
  let kind = (
    Object.keys(MANAGEMENT_TX_VERSION) as Array<
      SentryManagementRequest['operation']
    >
  ).find((k) => MANAGEMENT_TX_VERSION[k] === tx.version);
  if (!kind)
    fail(
      'UNSUPPORTED_OPERATION',
      'Unexpected node management transaction type'
    );
  const positions = tx.outputs.flatMap((o, i) =>
    o.scriptHex.startsWith('6a') ? [i] : []
  );
  if (positions.length !== 1 || tx.outputs[positions[0]].valueSatoshis !== '0')
    fail('INVALID_PAYLOAD', 'A single zero-value node payload is required');
  const outputIndex = positions[0];
  const bytes = extractOpReturn(fromHex(tx.outputs[outputIndex].scriptHex));
  const r = new Reader(bytes),
    version = r.number(2);
  if (tx.version === 86) {
    const operation = r.number(1);
    kind =
      operation === 1
        ? 'registerOperator'
        : operation === 2
        ? 'rotateOperator'
        : undefined;
    if (!kind || (version !== 1 && version !== 2))
      fail('UNSUPPORTED_ERA', 'Unknown global-operator payload');
  } else if (version !== 2 && version !== 3)
    fail(
      'UNSUPPORTED_ERA',
      'Only current legacy and PQ payloads are supported'
    );
  if (expected && kind !== expected)
    fail(
      'UNSUPPORTED_OPERATION',
      'Unexpected node management transaction type'
    );
  const empty = new Uint8Array();
  let payload: ManagementPayload;
  if (kind === 'registerOperator' || kind === 'rotateOperator') {
    const proTxHash = displayHash(r.read(32));
    hashBytes(proTxHash);
    const candidate = {
      version: r.number(2),
      profile: r.number(2),
      keyVersion: r.number(4),
      publicKey: hex(r.read(32)),
      childKeyCommitmentHex: hex(r.read(80)),
      activatedHeight: r.number(4),
    };
    if (candidate.activatedHeight !== 0)
      fail(
        'INVALID_CANDIDATE',
        'Operator candidate activation height must be zero'
      );
    serializePQRecord(candidate, true);
    const inputsHash = r.read(32),
      ownerKeyVersion = version === 2 ? r.number(4) : 0;
    const ownerProof = r.read(version === 2 ? PQ_SIGNATURE_SIZE : 65),
      primarySignature = r.read(PQ_SIGNATURE_SIZE);
    if (
      (kind === 'rotateOperator' && (version !== 1 || nonzero(ownerProof))) ||
      (version === 2 && ownerKeyVersion === 0)
    )
      fail('INVALID_CANDIDATE', 'Invalid global-operator owner authorization');
    payload = {
      kind,
      version,
      proTxHash,
      candidate,
      inputsHash,
      ownerKeyVersion,
      ownerProof,
      primarySignature,
    };
  } else if (kind === 'register') {
    if (r.number(2) !== 0 || r.number(2) !== 0)
      fail('INVALID_PAYLOAD', 'Unknown node type or mode');
    const collateralTxid = displayHash(r.read(32));
    hashBytes(collateralTxid, 'external collateral txid');
    const collateralVout = r.number(4),
      service = serviceFromBytes(r.read(18));
    if (service.network !== 1)
      fail('UNSUPPORTED_SERVICE', 'Current Core requires IPv4');
    const ownerKeyId = r.read(20),
      operatorPublicKey = version === 2 ? r.read(48) : empty,
      votingKeyId = r.read(20);
    const reward = r.number(2),
      payoutScript = r.vector(10000),
      inputsHash = r.read(32);
    const pqVotingPublicKey = version === 3 ? r.read(32) : empty,
      pqOwnerPublicKey = version === 3 ? r.read(32) : empty;
    const primarySignature = r.vector(65),
      ownerProof = version === 3 ? r.read(PQ_SIGNATURE_SIZE) : empty;
    if (
      reward > 10000 ||
      !nonzero(ownerKeyId) ||
      !nonzero(votingKeyId) ||
      primarySignature.length !== 65 ||
      (version === 2 && !nonzero(operatorPublicKey)) ||
      (version === 3 &&
        (!nonzero(pqVotingPublicKey) || !nonzero(pqOwnerPublicKey)))
    )
      fail('INVALID_PAYLOAD', 'Invalid registration keys or reward');
    payload = {
      kind,
      version,
      collateralTxid,
      collateralVout,
      service,
      ownerKeyId,
      operatorPublicKey,
      votingKeyId,
      reward,
      payoutScript,
      inputsHash,
      pqVotingPublicKey,
      pqOwnerPublicKey,
      primarySignature,
      ownerProof,
    };
  } else if (kind === 'updateRegistrar') {
    const proTxHash = displayHash(r.read(32));
    hashBytes(proTxHash, 'proTxHash');
    if (r.number(2) !== 0) fail('INVALID_PAYLOAD', 'Unknown registrar mode');
    const operatorPublicKey = version === 2 ? r.read(48) : empty,
      votingKeyId = r.read(20),
      payoutScript = r.vector(10000),
      inputsHash = r.read(32);
    const pqVotingPublicKey = version === 3 ? r.read(32) : empty,
      pqOwnerPublicKey = version === 3 ? r.read(32) : empty;
    const ownerKeyVersion = version === 3 ? r.number(4) : 0;
    const primarySignature = r.vector(PQ_SIGNATURE_SIZE),
      ownerProof = version === 3 ? r.read(PQ_SIGNATURE_SIZE) : empty;
    if (
      (primarySignature.length !== 65 &&
        !(version === 3 && primarySignature.length === PQ_SIGNATURE_SIZE)) ||
      (version === 2 && (!nonzero(operatorPublicKey) || !nonzero(votingKeyId)))
    )
      fail('INVALID_PAYLOAD', 'Invalid registrar key or signature size');
    payload = {
      kind,
      version,
      proTxHash,
      operatorPublicKey,
      votingKeyId,
      payoutScript,
      inputsHash,
      pqVotingPublicKey,
      pqOwnerPublicKey,
      ownerKeyVersion,
      primarySignature,
      ownerProof,
    };
  } else {
    const proTxHash = displayHash(r.read(32));
    hashBytes(proTxHash, 'proTxHash');
    const reason = r.number(2),
      inputsHash = r.read(32),
      globalKeyVersion = version === 3 ? r.number(4) : 0;
    if (reason > 3 || (version === 3 && !globalKeyVersion))
      fail('INVALID_PAYLOAD', 'Invalid revocation reason/key version');
    payload = {
      kind,
      version,
      proTxHash,
      reason,
      inputsHash,
      globalKeyVersion,
      primarySignature: r.read(
        version === 3 ? PQ_SIGNATURE_SIZE : BLS_SIGNATURE_SIZE
      ),
      ownerProof: empty,
    };
  }
  r.end();
  const actualInputs = hash256(
    concat(
      ...tx.inputs.map((i) =>
        concat(hashBytes(i.txid), integerBytes(i.vout, 4))
      )
    )
  );
  if (hex(actualInputs) !== hex(payload.inputsHash))
    fail(
      'INPUTS_MISMATCH',
      'Management payload does not bind these exact ordered inputs'
    );
  if (hex(managementPayloadBytes(payload)) !== hex(bytes))
    fail('NON_CANONICAL', 'Management payload is not canonical');
  return { payload, outputIndex };
}

export function validateSentryManagementRequest(
  value: unknown
): SentryManagementRequest {
  const v = object(
    value,
    ['version', 'operation', 'chain', 'transactionHex'],
    'management request'
  );
  if (
    v.version !== 1 ||
    ![
      'register',
      'updateRegistrar',
      'revoke',
      'registerOperator',
      'rotateOperator',
    ].includes(String(v.operation))
  )
    fail('UNSUPPORTED_OPERATION', 'Unknown management operation');
  const c = object(v.chain, ['genesisHash', 'era'], 'chain');
  if (c.era !== 'legacy-v3' && c.era !== 'pq-v4')
    fail('UNSUPPORTED_ERA', 'Unknown management era');
  const chain = {
    genesisHash: displayHash(hashBytes(c.genesisHash)),
    era: c.era,
  } as SentryChain;
  const operation = v.operation as SentryManagementRequest['operation'],
    transactionHex = hex(fromHex(v.transactionHex));
  const { payload } = managementPayload(transactionHex, operation);
  const isGlobal =
    operation === 'registerOperator' || operation === 'rotateOperator';
  if (
    !isGlobal &&
    payload.version !== (chain.era === 'pq-v4' ? 3 : 2) &&
    !(
      operation === 'updateRegistrar' &&
      payload.version === 3 &&
      chain.era === 'legacy-v3'
    )
  )
    fail('ERA_MISMATCH', 'Payload does not match the active management era');
  return { version: 1, operation, chain, transactionHex };
}

function fund(
  p: ManagementPayload,
  chain: SentryChain,
  inputs: SentryTxInput[],
  outputs: SentryTxOutput[],
  lockTime = 0
): SentryManagementRequest {
  if (!inputs.length || inputs.length > 256 || outputs.length > 255)
    fail('LIMIT', 'Invalid funding size');
  const txInputs = inputs.map((i) => ({
    txid: displayHash(hashBytes(i.txid)),
    vout: uint(i.vout, 32, 'vout'),
    sequence: uint(i.sequence ?? 0xfffffffe, 32, 'sequence'),
    scriptHex: '',
    witness: [],
  }));
  p.inputsHash = hash256(
    concat(
      ...txInputs.map((i) => concat(hashBytes(i.txid), integerBytes(i.vout, 4)))
    )
  );
  const txOutputs = outputs.map((o) => {
    const script = fromHex(o.scriptHex);
    if (script[0] === 0x6a)
      fail('INVALID_OUTPUT', 'Only one node payload is permitted');
    return {
      valueSatoshis: amount(o.valueSatoshis, 'output').toString(),
      scriptHex: hex(script),
    };
  });
  txOutputs.push({
    valueSatoshis: '0',
    scriptHex: hex(opReturn(managementPayloadBytes(p))),
  });
  return validateSentryManagementRequest({
    version: 1,
    operation: p.kind,
    chain,
    transactionHex: hex(
      encodeTransaction({
        version: MANAGEMENT_TX_VERSION[p.kind],
        inputs: txInputs,
        outputs: txOutputs,
        lockTime: uint(lockTime, 32, 'locktime'),
      })
    ),
  });
}

export function buildSentryRegistration(
  o: BuildSentryRegistration
): SentryManagementRequest {
  const pq = o.chain.era === 'pq-v4';
  return fund(
    {
      kind: 'register',
      version: pq ? 3 : 2,
      inputsHash: new Uint8Array(32),
      collateralTxid: displayHash(hashBytes(o.collateralOutpoint.txid)),
      collateralVout: uint(o.collateralOutpoint.vout, 32, 'collateralVout'),
      service: parseService(o.service),
      ownerKeyId: fromHex(o.ownerKeyId, 'owner key id', 20),
      votingKeyId: fromHex(o.votingKeyId, 'voting key id', 20),
      operatorPublicKey: pq
        ? new Uint8Array()
        : fromHex(o.operatorPublicKey, 'operator key', 48),
      pqOwnerPublicKey: pq
        ? fromHex(o.pqOwnerPublicKey, 'PQ owner key', 32)
        : new Uint8Array(),
      pqVotingPublicKey: pq
        ? fromHex(o.pqVotingPublicKey, 'PQ voting key', 32)
        : new Uint8Array(),
      reward: uint(o.operatorRewardBasisPoints, 16, 'operator reward'),
      payoutScript: fromHex(o.payoutScript),
      primarySignature: new Uint8Array(65),
      ownerProof: new Uint8Array(pq ? PQ_SIGNATURE_SIZE : 0),
    },
    o.chain,
    o.inputs,
    o.outputs,
    o.lockTime
  );
}

export function buildSentryRegistrarUpdate(
  o: BuildSentryRegistrarUpdate
): SentryManagementRequest {
  const pq = o.chain.era === 'pq-v4' || o.ownerPreparation === true;
  if (pq && o.operatorPublicKey !== undefined)
    fail(
      'UNSUPPORTED_OPERATION',
      'PQ operator rotation uses a separate global-key operation'
    );
  return fund(
    {
      kind: 'updateRegistrar',
      version: pq ? 3 : 2,
      proTxHash: o.node.proTxHash,
      inputsHash: new Uint8Array(32),
      votingKeyId: fromHex(
        o.votingKeyId ?? o.node.votingKeyId,
        'voting key id',
        20
      ),
      operatorPublicKey: pq
        ? new Uint8Array()
        : fromHex(
            o.operatorPublicKey ?? o.node.operatorPublicKey,
            'operator key',
            48
          ),
      payoutScript: fromHex(o.payoutScript ?? o.node.payoutScript),
      pqVotingPublicKey: pq
        ? fromHex(
            o.pqVotingPublicKey ?? o.node.pqVotingPublicKey ?? '00'.repeat(32),
            'PQ voting key',
            32
          )
        : new Uint8Array(),
      pqOwnerPublicKey: pq
        ? fromHex(o.pqOwnerPublicKey ?? '00'.repeat(32), 'PQ owner key', 32)
        : new Uint8Array(),
      ownerKeyVersion: pq ? o.node.pqOwnerRecord?.keyVersion ?? 0 : 0,
      primarySignature: new Uint8Array(
        pq && o.node.pqOwnerRecord ? PQ_SIGNATURE_SIZE : 65
      ),
      ownerProof: new Uint8Array(pq ? PQ_SIGNATURE_SIZE : 0),
    },
    o.chain,
    o.inputs,
    o.outputs,
    o.lockTime
  );
}

export function buildSentryOperatorUpdate(
  o: BuildSentryOperatorUpdate
): SentryManagementRequest {
  if (o.mode !== 'initial' && o.mode !== 'rotate')
    fail('UNSUPPORTED_OPERATION', 'Unknown operator update mode');
  const pqOwner = o.mode === 'initial' && !!o.node.pqOwnerRecord;
  return fund(
    {
      kind: o.mode === 'initial' ? 'registerOperator' : 'rotateOperator',
      version: pqOwner ? 2 : 1,
      proTxHash: o.node.proTxHash,
      candidate: { ...o.candidate },
      inputsHash: new Uint8Array(32),
      ownerKeyVersion: pqOwner ? o.node.pqOwnerRecord!.keyVersion : 0,
      primarySignature: new Uint8Array(PQ_SIGNATURE_SIZE),
      ownerProof: new Uint8Array(pqOwner ? PQ_SIGNATURE_SIZE : 65),
    },
    o.chain,
    o.inputs,
    o.outputs,
    o.lockTime
  );
}

export function buildSentryRevocation(
  o: BuildSentryRevocation
): SentryManagementRequest {
  const pq = o.chain.era === 'pq-v4';
  return fund(
    {
      kind: 'revoke',
      version: pq ? 3 : 2,
      proTxHash: o.node.proTxHash,
      inputsHash: new Uint8Array(32),
      reason: uint(o.reason, 16, 'reason'),
      globalKeyVersion: pq
        ? uint(o.node.globalKeyVersion, 32, 'global key version')
        : 0,
      primarySignature: new Uint8Array(
        pq ? PQ_SIGNATURE_SIZE : BLS_SIGNATURE_SIZE
      ),
      ownerProof: new Uint8Array(),
    },
    o.chain,
    o.inputs,
    o.outputs,
    o.lockTime
  );
}

export function scriptAddress(
  script: Uint8Array,
  network: SentryNetworkEncoding
): string {
  if (!/^[a-z0-9]{1,20}$/.test(network.bech32Hrp))
    fail('INVALID_NETWORK', 'Invalid configured address prefix');
  const h = hex(script);
  if (/^76a914[0-9a-f]{40}88ac$/.test(h))
    return base58check(sha256).encode(
      concat(
        integerBytes(uint(network.pubKeyHash, 8, 'pubkey prefix'), 1),
        script.slice(3, 23)
      )
    );
  if (/^a914[0-9a-f]{40}87$/.test(h))
    return base58check(sha256).encode(
      concat(
        integerBytes(uint(network.scriptHash, 8, 'script prefix'), 1),
        script.slice(2, 22)
      )
    );
  const version =
    script[0] === 0
      ? 0
      : script[0] >= 0x51 && script[0] <= 0x60
      ? script[0] - 0x50
      : -1;
  if (
    version >= 0 &&
    script.length >= 4 &&
    script[1] === script.length - 2 &&
    script[1] <= 40 &&
    (version !== 0 || script[1] === 20 || script[1] === 32)
  ) {
    const coder = version === 0 ? bech32 : bech32m;
    return coder.encode(network.bech32Hrp, [
      version,
      ...coder.toWords(script.slice(2)),
    ]);
  }
  fail('INVALID_PAYOUT', 'Node payout must be a standard destination script');
}

export function registrationMessage(
  p: RegistrationPayload,
  network: SentryNetworkEncoding
): string {
  const owner = scriptAddress(
    concat(Uint8Array.of(0, 20), p.ownerKeyId),
    network
  );
  const voting = scriptAddress(
    concat(Uint8Array.of(0, 20), p.votingKeyId),
    network
  );
  return `${scriptAddress(p.payoutScript, network)}|${
    p.reward
  }|${owner}|${voting}|${displayHash(
    hash256(managementPayloadBytes(p, true))
  )}`;
}

export function registrationMessageDigest(
  p: RegistrationPayload,
  network: SentryNetworkEncoding
): Uint8Array {
  return hash256(
    concat(
      vector(new TextEncoder().encode('Syscoin Signed Message:\n')),
      vector(new TextEncoder().encode(registrationMessage(p, network)))
    )
  );
}

/** Convert trusted Core owner/voting address fields into their signed key ID. */
export function sentryKeyIdFromAddress(
  value: string,
  network: SentryNetworkEncoding
): string {
  if (typeof value !== 'string' || value.length > 128)
    fail('INVALID_ADDRESS', 'Invalid node authority address');
  try {
    const decoded = bech32.decode(value as `${string}1${string}`);
    const bytes = bech32.fromWords(decoded.words.slice(1));
    if (
      decoded.prefix !== network.bech32Hrp ||
      decoded.words[0] !== 0 ||
      bytes.length !== 20
    )
      fail(
        'INVALID_ADDRESS',
        'Owner/voting address must be this network single-key address'
      );
    return hex(Uint8Array.from(bytes));
  } catch {
    try {
      const bytes = base58check(sha256).decode(value);
      if (bytes.length !== 21 || bytes[0] !== network.pubKeyHash)
        fail('INVALID_ADDRESS', 'Wrong node address network/type');
      return hex(bytes.slice(1));
    } catch {
      return fail(
        'INVALID_ADDRESS',
        'Owner/voting address must be this network single-key address'
      );
    }
  }
}
