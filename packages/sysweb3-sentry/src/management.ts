import { ripemd160 } from '@noble/hashes/legacy.js';
import { sha256 } from '@noble/hashes/sha2.js';

import {
  concat,
  fail,
  fromHex,
  hash256,
  hashBytes,
  hex,
  integerBytes,
  nonzero,
  uint,
  vector,
} from './bytes.js';
import {
  decodeSentryTransaction,
  encodeTransaction,
  opReturn,
} from './codec.js';
import {
  MANAGEMENT_TX_VERSION,
  managementPayload,
  managementPayloadBytes,
  registrationMessage,
  registrationMessageDigest,
  scriptAddress,
  validateSentryManagementRequest,
  type ManagementPayload,
} from './management-codec.js';
import { reviewFunding, serializePQRecord } from './review.js';
import { importSentryOperatorKey } from './signing.js';

import type {
  SentryAuthorityKey,
  SentryAuthorityRole,
  SentryAuthorityScheme,
  SentryManagementContext,
  SentryManagementRequest,
  SentryManagementResponse,
  SentryManagementReview,
  SentryRequiredAuthorization,
} from './management-types.js';

export function sentryKeyId(publicKeyHex: string): string {
  return hex(ripemd160(sha256(fromHex(publicKeyHex, 'public key'))));
}

export async function importSentryAuthorityKey(
  role: SentryAuthorityRole,
  scheme: SentryAuthorityScheme,
  secretKeyHex: string
): Promise<SentryAuthorityKey> {
  if (
    !['owner', 'operator', 'collateral', 'voting'].includes(role) ||
    (role === 'collateral' && scheme !== 'secp256k1') ||
    (role === 'operator' && scheme === 'secp256k1') ||
    (role !== 'operator' && scheme === 'bls-basic')
  )
    fail('INVALID_KEY_ROLE', 'Key scheme cannot authorize this node role');
  if (scheme !== 'secp256k1')
    return { ...(await importSentryOperatorKey(scheme, secretKeyHex)), role };
  const secret = fromHex(secretKeyHex, 'secp256k1 key', 32);
  try {
    const { secp256k1 } = await import('@noble/curves/secp256k1.js');
    const publicKey = secp256k1.getPublicKey(secret, true);
    return { role, scheme, publicKey: hex(publicKey), secretKey: hex(secret) };
  } catch {
    return fail('INVALID_SECRET_KEY', 'Invalid node authority key');
  } finally {
    secret.fill(0);
  }
}

export function ownerDigest(
  p: ManagementPayload,
  context: SentryManagementContext
): Uint8Array {
  const domain =
    p.kind === 'register'
      ? 'SYS_PQ_OWNER_PROREG_V1'
      : 'SYS_PQ_OWNER_REGISTRAR_V1';
  return hash256(
    concat(
      vector(new TextEncoder().encode(domain)),
      hashBytes(context.chain.genesisHash),
      integerBytes(MANAGEMENT_TX_VERSION[p.kind], 4),
      hash256(managementPayloadBytes(p, true))
    )
  );
}

function addAuth(
  list: SentryRequiredAuthorization[],
  id: SentryRequiredAuthorization['id'],
  role: SentryAuthorityRole,
  scheme: SentryAuthorityScheme,
  keyIdentity: string,
  digest: Uint8Array,
  signature: Uint8Array,
  context?: string
): void {
  fromHex(
    keyIdentity,
    'authorization key identity',
    scheme === 'secp256k1' ? 20 : scheme === 'bls-basic' ? 48 : 32
  );
  if (!nonzero(fromHex(keyIdentity)))
    fail('INVALID_KEY', 'Authorization key cannot be empty');
  list.push({
    id,
    role,
    scheme,
    keyIdentity: keyIdentity.toLowerCase(),
    digest: hex(digest),
    context,
    signed: nonzero(signature),
  });
}

export function reviewSentryManagementOperation(
  value: unknown,
  context: SentryManagementContext
): SentryManagementReview {
  const request = validateSentryManagementRequest(value);
  if (
    request.chain.genesisHash !== context.chain.genesisHash.toLowerCase() ||
    request.chain.era !== context.chain.era
  )
    fail(
      'CHAIN_MISMATCH',
      'Wallet chain/activation state differs from request'
    );
  const owner = context.node?.pqOwnerRecord;
  if (
    owner &&
    (uint(owner.keyVersion, 32, 'owner key version') === 0 ||
      !Number.isSafeInteger(owner.activatedHeight) ||
      owner.activatedHeight < 0 ||
      !nonzero(fromHex(owner.publicKey, 'owner public key', 32)))
  )
    fail('INVALID_OWNER', 'Invalid current owner key record');
  const tx = decodeSentryTransaction(request.transactionHex);
  const { payload: p, outputIndex } = managementPayload(request.transactionHex);
  const fee = reviewFunding(request, context);
  const authorizations: SentryRequiredAuthorization[] = [],
    fields: Record<string, string> = {};
  let proTxHash: string | undefined;
  if (p.kind === 'registerOperator' || p.kind === 'rotateOperator') {
    const node = context.node;
    if (!node || node.proTxHash.toLowerCase() !== p.proTxHash)
      fail('NODE_MISMATCH', 'Wallet must fetch the registered operator target');
    if (
      context.chain.era !== 'pq-v4' &&
      (p.kind !== 'registerOperator' || !context.allowOperatorPreparation)
    )
      fail('ERA_MISMATCH', 'Core has not enabled operator preparation');
    proTxHash = p.proTxHash;
    const candidate = p.candidate;
    const recordBytes = serializePQRecord(candidate, true);
    const prior = node.pqRecord;
    const candidateChild = fromHex(candidate.childKeyCommitmentHex);
    const candidateGeneration = new DataView(
      candidateChild.buffer,
      candidateChild.byteOffset
    ).getUint32(8, true);
    if (candidate.activatedHeight !== 0)
      fail('INVALID_CANDIDATE', 'Activation height is assigned by consensus');
    if (!prior) {
      if (
        p.kind !== 'registerOperator' ||
        candidate.keyVersion !== 1 ||
        candidateGeneration !== 1
      )
        fail(
          'INVALID_CANDIDATE',
          'Initial operator key must start at version and generation one'
        );
    } else {
      serializePQRecord(prior);
      if (
        candidate.keyVersion !== prior.keyVersion + 1 ||
        candidate.publicKey.toLowerCase() === prior.publicKey.toLowerCase()
      )
        fail(
          'INVALID_CANDIDATE',
          'Operator update requires next version and a different public key'
        );
      if ((p.kind === 'registerOperator') !== !!node.operatorRevoked)
        fail(
          'INVALID_CANDIDATE',
          'Recovery requires a revoked operator; active keys use rotation'
        );
      const previousChild = fromHex(prior.childKeyCommitmentHex);
      const previousGeneration = new DataView(
        previousChild.buffer,
        previousChild.byteOffset
      ).getUint32(8, true);
      const same =
        candidate.childKeyCommitmentHex.toLowerCase() ===
        prior.childKeyCommitmentHex.toLowerCase();
      const successor =
        candidateGeneration === previousGeneration + 1 &&
        hex(candidateChild.slice(16, 48)) !==
          hex(previousChild.slice(16, 48)) &&
        hex(candidateChild.slice(48)) !== hex(previousChild.slice(48));
      if ((!same && !successor) || (p.kind === 'registerOperator' && same))
        fail('INVALID_CANDIDATE', 'Invalid operator child-tree successor');
    }
    fields.previousOperatorPublicKey =
      prior?.publicKey ?? node.operatorPublicKey;
    fields.operatorPublicKey = candidate.publicKey;
    fields.globalKeyVersion = String(candidate.keyVersion);
    fields.childKeyCommitment = candidate.childKeyCommitmentHex;
    fields.action =
      p.kind === 'rotateOperator'
        ? 'Rotate active operator key'
        : prior
        ? 'Recover revoked operator'
        : 'Enroll initial PQ operator';
    if (p.kind === 'registerOperator') {
      const owner = node.pqOwnerRecord;
      if (
        (p.version === 2) !== !!owner ||
        p.ownerKeyVersion !== (owner?.keyVersion ?? 0)
      )
        fail(
          'OWNER_DOWNGRADE',
          'Operator enrollment must use the current owner authority'
        );
      const domain = owner
        ? 'SYS_PQ_GLOBAL_OWNER_REGISTER_V2'
        : 'SYS_PQ_GLOBAL_OWNER_REGISTER_V1';
      const ownerHash = hash256(
        concat(
          new TextEncoder().encode(domain),
          hashBytes(context.chain.genesisHash),
          integerBytes(86, 4),
          integerBytes(p.version, 2),
          Uint8Array.of(1),
          hashBytes(p.proTxHash),
          recordBytes,
          p.inputsHash,
          ...(owner ? [integerBytes(p.ownerKeyVersion, 4)] : [])
        )
      );
      addAuth(
        authorizations,
        'owner',
        'owner',
        owner ? 'slh-dsa-shake-128s' : 'secp256k1',
        owner?.publicKey ?? node.ownerKeyId,
        ownerHash,
        p.ownerProof,
        owner ? domain : undefined
      );
      const registrationHash = hash256(
        concat(
          new TextEncoder().encode('SYS_PQ_GLOBAL_REGISTER_V1'),
          hashBytes(context.chain.genesisHash),
          hashBytes(p.proTxHash),
          recordBytes.slice(0, -4),
          p.inputsHash
        )
      );
      addAuth(
        authorizations,
        'newOperator',
        'operator',
        'slh-dsa-shake-128s',
        candidate.publicKey,
        registrationHash,
        p.primarySignature,
        'SYS_PQ_GLOBAL_REGISTER_V1'
      );
    } else {
      if (!prior) fail('INVALID_CANDIDATE', 'No active operator to rotate');
      const rotationHash = hash256(
        concat(
          new TextEncoder().encode('SYS_PQ_GLOBAL_ROTATE_V1'),
          hashBytes(context.chain.genesisHash),
          hashBytes(p.proTxHash),
          serializePQRecord(prior).slice(0, -4),
          recordBytes.slice(0, -4),
          p.inputsHash
        )
      );
      addAuth(
        authorizations,
        'operator',
        'operator',
        'slh-dsa-shake-128s',
        prior.publicKey,
        rotationHash,
        p.primarySignature,
        'SYS_PQ_GLOBAL_ROTATE_V1'
      );
    }
  } else if (p.kind === 'register') {
    const c = context.registration;
    if (!c)
      fail(
        'MISSING_COLLATERAL',
        'Wallet must independently fetch registration collateral'
      );
    const collateralTx = decodeSentryTransaction(c.collateralTransactionHex);
    if (
      collateralTx.txid !== p.collateralTxid ||
      c.collateralVout !== p.collateralVout
    )
      fail(
        'COLLATERAL_MISMATCH',
        'Registration points to another collateral output'
      );
    const collateral = collateralTx.outputs[p.collateralVout];
    if (
      !collateral ||
      collateral.valueSatoshis !== c.requiredCollateralSatoshis
    )
      fail('COLLATERAL_AMOUNT', 'Registration collateral amount is incorrect');
    if (
      tx.inputs.some(
        (input) =>
          input.txid === p.collateralTxid && input.vout === p.collateralVout
      )
    )
      fail('COLLATERAL_SPEND', 'Registration must not spend its collateral');
    const script = collateral.scriptHex;
    const collateralKeyId = /^0014[0-9a-f]{40}$/.test(script)
      ? script.slice(4)
      : /^76a914[0-9a-f]{40}88ac$/.test(script)
      ? script.slice(6, -4)
      : undefined;
    if (!collateralKeyId)
      fail(
        'UNSUPPORTED_COLLATERAL',
        'External collateral must use a single-key P2PKH/P2WPKH output'
      );
    if (
      collateralKeyId === hex(p.ownerKeyId) ||
      collateralKeyId === hex(p.votingKeyId)
    )
      fail('KEY_REUSE', 'Collateral cannot reuse owner/voting authority');
    fields.collateral = `${p.collateralTxid}:${p.collateralVout}`;
    fields.collateralSatoshis = collateral.valueSatoshis;
    fields.service = p.service.text;
    fields.ownerKeyId = hex(p.ownerKeyId);
    fields.votingKeyId = hex(p.votingKeyId);
    fields.payoutAddress = scriptAddress(p.payoutScript, context.network);
    fields.operatorRewardBasisPoints = String(p.reward);
    fields.operatorPublicKey = hex(p.operatorPublicKey);
    fields.pqVotingPublicKey = hex(p.pqVotingPublicKey);
    fields.pqOwnerPublicKey = hex(p.pqOwnerPublicKey);
    fields.collateralSigningMessage = registrationMessage(p, context.network);
    addAuth(
      authorizations,
      'collateral',
      'collateral',
      'secp256k1',
      collateralKeyId,
      registrationMessageDigest(p, context.network),
      p.primarySignature
    );
    if (p.version === 3)
      addAuth(
        authorizations,
        'newOwner',
        'owner',
        'slh-dsa-shake-128s',
        hex(p.pqOwnerPublicKey),
        ownerDigest(p, context),
        p.ownerProof,
        'SYS_PQ_OWNER_PROOF_V1'
      );
  } else {
    const node = context.node;
    if (!node || p.proTxHash !== node.proTxHash.toLowerCase())
      fail('NODE_MISMATCH', 'Wallet must fetch the registered target node');
    proTxHash = p.proTxHash;
    if (p.kind === 'updateRegistrar') {
      if (request.chain.era === 'legacy-v3' && p.version === 3) {
        if (
          !context.allowOwnerPreparation ||
          !nonzero(p.pqOwnerPublicKey) ||
          hex(p.votingKeyId) !== node.votingKeyId.toLowerCase() ||
          hex(p.payoutScript) !== node.payoutScript.toLowerCase() ||
          hex(p.pqVotingPublicKey) !==
            hex(
              fromHex(
                node.pqVotingPublicKey ?? '00'.repeat(32),
                'current PQ voting key',
                32
              )
            )
        ) {
          fail(
            'ERA_MISMATCH',
            'Only authorized owner-preparation fields may change before activation'
          );
        }
      }
      scriptAddress(p.payoutScript, context.network);
      fields.previousPayoutAddress = scriptAddress(
        fromHex(node.payoutScript),
        context.network
      );
      fields.payoutAddress = scriptAddress(p.payoutScript, context.network);
      fields.previousVotingKeyId = node.votingKeyId;
      fields.votingKeyId = hex(p.votingKeyId);
      fields.previousOperatorPublicKey = node.operatorPublicKey;
      fields.operatorPublicKey =
        p.version === 2 ? hex(p.operatorPublicKey) : node.operatorPublicKey;
      fields.previousPQVotingPublicKey = node.pqVotingPublicKey ?? '';
      fields.pqVotingPublicKey = hex(p.pqVotingPublicKey);
      fields.previousPQOwnerPublicKey = node.pqOwnerRecord?.publicKey ?? '';
      fields.pqOwnerPublicKey = nonzero(p.pqOwnerPublicKey)
        ? hex(p.pqOwnerPublicKey)
        : node.pqOwnerRecord?.publicKey ?? '';
      if (p.version === 2) {
        if (node.pqOwnerRecord)
          fail(
            'OWNER_DOWNGRADE',
            'Enrolled PQ owner cannot fall back to ECDSA'
          );
        addAuth(
          authorizations,
          'owner',
          'owner',
          'secp256k1',
          node.ownerKeyId,
          hash256(managementPayloadBytes(p, true)),
          p.primarySignature
        );
      } else {
        const replaces = nonzero(p.pqOwnerPublicKey),
          owner = node.pqOwnerRecord;
        if (p.ownerKeyVersion !== (owner?.keyVersion ?? 0))
          fail(
            'KEY_VERSION',
            'Registrar must use the currently enrolled owner version'
          );
        const digest = ownerDigest(p, context);
        if (owner) {
          if (
            owner.keyVersion < 1 ||
            owner.activatedHeight < 0 ||
            p.primarySignature.length !== 7856
          )
            fail('INVALID_OWNER', 'Invalid current PQ owner record/signature');
          addAuth(
            authorizations,
            'owner',
            'owner',
            'slh-dsa-shake-128s',
            owner.publicKey,
            digest,
            p.primarySignature,
            'SYS_PQ_OWNER_UPDATE_V1'
          );
        } else {
          if (p.primarySignature.length !== 65)
            fail(
              'INVALID_OWNER',
              'Legacy owner requires compact ECDSA authorization'
            );
          addAuth(
            authorizations,
            'owner',
            'owner',
            'secp256k1',
            node.ownerKeyId,
            replaces ? digest : hash256(managementPayloadBytes(p, true)),
            p.primarySignature
          );
        }
        if (replaces)
          addAuth(
            authorizations,
            'newOwner',
            'owner',
            'slh-dsa-shake-128s',
            hex(p.pqOwnerPublicKey),
            digest,
            p.ownerProof,
            'SYS_PQ_OWNER_PROOF_V1'
          );
        else if (nonzero(p.ownerProof))
          fail(
            'UNEXPECTED_PROOF',
            'Unchanged owner must not carry an unrelated proof'
          );
      }
    } else {
      if (p.kind !== 'revoke')
        fail('UNSUPPORTED_OPERATION', 'Unknown node management operation');
      fields.reason = String(p.reason);
      if (p.version === 2)
        addAuth(
          authorizations,
          'operator',
          'operator',
          'bls-basic',
          node.operatorPublicKey,
          hash256(managementPayloadBytes(p, true)),
          p.primarySignature
        );
      else {
        const record = node.pqRecord;
        if (
          !record ||
          record.keyVersion !== p.globalKeyVersion ||
          node.globalKeyVersion !== p.globalKeyVersion ||
          record.publicKey.toLowerCase() !==
            node.operatorPublicKey.toLowerCase()
        )
          fail(
            'KEY_VERSION',
            'Revocation requires current registered PQ operator'
          );
        const digest = hash256(
          concat(
            new TextEncoder().encode('SYS_PQ_PROVIDER_REVOKE_V1'),
            hashBytes(context.chain.genesisHash),
            integerBytes(1, 2),
            integerBytes(p.version, 2),
            hashBytes(p.proTxHash),
            integerBytes(p.globalKeyVersion, 4),
            integerBytes(record.version, 2),
            integerBytes(record.profile, 2),
            hash256(serializePQRecord(record)),
            integerBytes(p.reason, 2),
            p.inputsHash
          )
        );
        addAuth(
          authorizations,
          'operator',
          'operator',
          'slh-dsa-shake-128s',
          node.operatorPublicKey,
          digest,
          p.primarySignature,
          'SYS_PQ_PROVIDER_REVOKE_V1'
        );
      }
    }
  }
  return {
    operation: p.kind,
    chain: { ...request.chain },
    proTxHash,
    fields,
    authorizations,
    feeSatoshis: fee.toString(),
    outputs: tx.outputs.map((o, i) => ({ ...o, isPayload: i === outputIndex })),
  };
}

function signatureFor(
  p: ManagementPayload,
  auth: SentryRequiredAuthorization
): Uint8Array {
  if (
    (p.kind === 'registerOperator' || p.kind === 'rotateOperator') &&
    auth.id === 'owner'
  )
    return p.ownerProof;
  return auth.id === 'newOwner' ? p.ownerProof : p.primarySignature;
}

async function verifyAuthority(
  signature: Uint8Array,
  auth: SentryRequiredAuthorization
): Promise<boolean> {
  if (!nonzero(signature)) return false;
  const digest = fromHex(auth.digest);
  try {
    if (auth.scheme === 'secp256k1') {
      if (signature.length !== 65 || signature[0] < 31 || signature[0] > 34)
        return false;
      const recovered = signature.slice();
      recovered[0] -= 31;
      const { secp256k1 } = await import('@noble/curves/secp256k1.js');
      if (
        secp256k1.Signature.fromBytes(signature.slice(1), 'compact').hasHighS()
      )
        return false;
      return (
        sentryKeyId(
          hex(secp256k1.recoverPublicKey(recovered, digest, { prehash: false }))
        ) === auth.keyIdentity
      );
    }
    if (auth.scheme === 'bls-basic') {
      const { bls12_381 } = await import('@noble/curves/bls12-381.js');
      return bls12_381.longSignatures.verify(
        signature,
        bls12_381.longSignatures.hash(
          digest,
          'BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_'
        ),
        fromHex(auth.keyIdentity)
      );
    }
    const { slh_dsa_shake_128s } = await import(
      '@noble/post-quantum/slh-dsa.js'
    );
    return slh_dsa_shake_128s.verify(
      signature,
      digest,
      fromHex(auth.keyIdentity),
      { context: new TextEncoder().encode(auth.context!) }
    );
  } catch {
    return false;
  }
}

export async function verifySentryManagementOperation(
  value: unknown,
  context: SentryManagementContext
): Promise<boolean> {
  try {
    const request = validateSentryManagementRequest(value),
      review = reviewSentryManagementOperation(request, context);
    const { payload } = managementPayload(request.transactionHex);
    for (const auth of review.authorizations)
      if (!(await verifyAuthority(signatureFor(payload, auth), auth)))
        return false;
    return true;
  } catch {
    return false;
  }
}

export async function signSentryManagementOperation(
  value: unknown,
  context: SentryManagementContext,
  importedKey: SentryAuthorityKey,
  authorizationId?: SentryRequiredAuthorization['id']
): Promise<SentryManagementResponse> {
  context = {
    ...context,
    chain: { ...context.chain },
    network: { ...context.network },
    previousTransactions: [...context.previousTransactions],
    registration: context.registration
      ? { ...context.registration }
      : undefined,
    node: context.node
      ? {
          ...context.node,
          pqOwnerRecord: context.node.pqOwnerRecord
            ? { ...context.node.pqOwnerRecord }
            : undefined,
          pqRecord: context.node.pqRecord
            ? { ...context.node.pqRecord }
            : undefined,
          collateralOutpoint: context.node.collateralOutpoint
            ? { ...context.node.collateralOutpoint }
            : undefined,
        }
      : undefined,
  };
  importedKey = { ...importedKey };
  const request = validateSentryManagementRequest(value),
    review = reviewSentryManagementOperation(request, context);
  const tx = decodeSentryTransaction(request.transactionHex),
    { payload, outputIndex } = managementPayload(request.transactionHex);
  if (tx.inputs.some((i) => i.scriptHex !== '' || i.witness.length))
    fail(
      'SIGNED_FUNDING',
      'Fee signatures must follow all node authorizations'
    );
  const key = await importSentryAuthorityKey(
    importedKey.role,
    importedKey.scheme,
    importedKey.secretKey
  );
  if (key.publicKey !== importedKey.publicKey.toLowerCase())
    fail('KEY_MISMATCH', 'Imported authority key identity changed');
  const identity =
    key.scheme === 'secp256k1' ? sentryKeyId(key.publicKey) : key.publicKey;
  const candidates = review.authorizations.filter(
    (a) =>
      a.role === key.role &&
      a.scheme === key.scheme &&
      a.keyIdentity === identity &&
      (!authorizationId || a.id === authorizationId)
  );
  if (candidates.length !== 1)
    fail(
      'KEY_MISMATCH',
      'Select the exact required authority slot for this key'
    );
  const auth = candidates[0];
  if (auth.signed)
    fail('ALREADY_AUTHORIZED', 'This authority signature already exists');
  for (const existing of review.authorizations)
    if (
      existing.signed &&
      !(await verifyAuthority(signatureFor(payload, existing), existing))
    )
      fail('INVALID_SIGNATURE', 'Another authority signature is invalid');
  const secret = fromHex(key.secretKey),
    digest = fromHex(auth.digest);
  let signature: Uint8Array;
  try {
    if (key.scheme === 'secp256k1') {
      const { secp256k1 } = await import('@noble/curves/secp256k1.js');
      signature = secp256k1.sign(digest, secret, {
        prehash: false,
        format: 'recovered',
        lowS: true,
      });
      signature[0] += 31;
    } else if (key.scheme === 'bls-basic') {
      const { bls12_381 } = await import('@noble/curves/bls12-381.js');
      signature = bls12_381.longSignatures
        .sign(
          bls12_381.longSignatures.hash(
            digest,
            'BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_'
          ),
          secret
        )
        .toBytes();
    } else {
      const { slh_dsa_shake_128s } = await import(
        '@noble/post-quantum/slh-dsa.js'
      );
      signature = slh_dsa_shake_128s.sign(digest, secret, {
        context: new TextEncoder().encode(auth.context!),
        extraEntropy: false,
      });
    }
  } finally {
    secret.fill(0);
    digest.fill(0);
  }
  if (!(await verifyAuthority(signature!, auth)))
    fail('SIGNATURE_FAILED', 'Authority signature did not verify');
  if (
    auth.id === 'newOwner' ||
    ((payload.kind === 'registerOperator' ||
      payload.kind === 'rotateOperator') &&
      auth.id === 'owner')
  )
    payload.ownerProof = signature!;
  else payload.primarySignature = signature!;
  tx.outputs[outputIndex].scriptHex = hex(
    opReturn(managementPayloadBytes(payload))
  );
  const next = { ...request, transactionHex: hex(encodeTransaction(tx)) };
  return {
    version: 1,
    operation: request.operation,
    transactionHex: next.transactionHex,
    signedAuthorization: auth.id,
    complete: await verifySentryManagementOperation(next, context),
  };
}

export function matchesSentryManagementIntent(
  prepared: unknown,
  signed: unknown
): boolean {
  try {
    const a = validateSentryManagementRequest(prepared),
      b = validateSentryManagementRequest(signed);
    if (
      a.operation !== b.operation ||
      a.chain.genesisHash !== b.chain.genesisHash ||
      a.chain.era !== b.chain.era
    )
      return false;
    const clean = (req: SentryManagementRequest): string => {
      const tx = decodeSentryTransaction(req.transactionHex),
        { payload, outputIndex } = managementPayload(req.transactionHex);
      payload.primarySignature.fill(0);
      payload.ownerProof.fill(0);
      tx.outputs[outputIndex].scriptHex = hex(
        opReturn(managementPayloadBytes(payload))
      );
      for (const input of tx.inputs) {
        input.scriptHex = '';
        input.witness = [];
      }
      return hex(encodeTransaction(tx));
    };
    return clean(a) === clean(b);
  } catch {
    return false;
  }
}

export function inspectSentryManagementOperation(value: unknown) {
  const request = validateSentryManagementRequest(value),
    { payload } = managementPayload(request.transactionHex);
  const tx = decodeSentryTransaction(request.transactionHex);
  return {
    operation: request.operation,
    proTxHash: payload.kind === 'register' ? undefined : payload.proTxHash,
    collateral:
      payload.kind === 'register'
        ? { txid: payload.collateralTxid, vout: payload.collateralVout }
        : undefined,
    inputTxids: [...new Set(tx.inputs.map((i) => i.txid))],
  };
}

export function getSentryManagementCapabilities() {
  return {
    version: 1 as const,
    operations: [
      'register',
      'updateRegistrar',
      'revoke',
      'registerOperator',
      'rotateOperator',
    ] as const,
    roles: ['collateral', 'owner', 'operator', 'voting'] as const,
    schemes: ['secp256k1', 'bls-basic', 'slh-dsa-shake-128s'] as const,
    externalCollateralOnly: true,
    precomputedOperatorChildCommitmentRequired: true,
  };
}
