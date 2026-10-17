import {
  MAX_MONEY,
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
  type ServicePayload,
  decodeSentryTransaction,
  encodeTransaction,
  locateServicePayload,
  normalizeNEVM,
  currentServiceText,
  opReturn,
  payloadBytes,
  validateNode,
} from './codec.js';

import type {
  SentryChain,
  SentryOperationRequest,
  SentryOperationReview,
  SentryPQRecord,
  SentryReviewContext,
} from './types.js';

export const PQ_SERVICE_DOMAIN = 'SYS_PQ_PROVIDER_SERVICE_V1';

function validateChain(value: unknown): SentryChain {
  const chain = object(value, ['genesisHash', 'era'], 'chain');
  const genesisHash = displayHash(hashBytes(chain.genesisHash, 'genesisHash'));
  if (chain.era !== 'legacy-v3' && chain.era !== 'pq-v4')
    fail('UNSUPPORTED_ERA', 'Unsupported Sentry era');
  return { genesisHash, era: chain.era };
}

export function validateSentryOperationRequest(
  value: unknown
): SentryOperationRequest {
  const request = object(
    value,
    ['version', 'operation', 'chain', 'transactionHex'],
    'request'
  );
  if (request.version !== 1 || request.operation !== 'updateService')
    fail('UNSUPPORTED_OPERATION', 'Unsupported Sentry request');
  const chain = validateChain(request.chain);
  const transactionHex = hex(fromHex(request.transactionHex, 'transaction'));
  const tx = decodeSentryTransaction(transactionHex);
  const { payload } = locateServicePayload(tx);
  if (payload.version !== (chain.era === 'pq-v4' ? 4 : 3))
    fail('ERA_MISMATCH', 'Payload version does not match requested era');
  return { version: 1, operation: 'updateService', chain, transactionHex };
}

/** Syntactic discovery only. No authorization should rely on this without review. */
export function inspectSentryOperation(value: unknown): {
  proTxHash: string;
  inputTxids: string[];
  globalKeyVersion?: number;
} {
  const request = validateSentryOperationRequest(value);
  const tx = decodeSentryTransaction(request.transactionHex);
  const { payload } = locateServicePayload(tx);
  return {
    proTxHash: payload.proTxHash,
    inputTxids: [...new Set(tx.inputs.map((input) => input.txid))],
    globalKeyVersion: payload.globalKeyVersion,
  };
}

/**
 * The Core operator signature does not bind fee outputs. Relays must compare
 * this as well as verifying authorization before forwarding a prepared intent.
 * Only operator signature bytes and fee-input script/witness may change.
 */
export function matchesSentryTransactionIntent(
  prepared: unknown,
  signed: unknown
): boolean {
  try {
    const first = validateSentryOperationRequest(prepared);
    const second = validateSentryOperationRequest(signed);
    if (
      first.chain.genesisHash !== second.chain.genesisHash ||
      first.chain.era !== second.chain.era
    )
      return false;
    const unsignedForm = (request: SentryOperationRequest): string => {
      const tx = decodeSentryTransaction(request.transactionHex);
      const { payload, outputIndex } = locateServicePayload(tx);
      payload.signature.fill(0);
      tx.outputs[outputIndex].scriptHex = hex(opReturn(payloadBytes(payload)));
      for (const input of tx.inputs) {
        input.scriptHex = '';
        input.witness = [];
      }
      return hex(encodeTransaction(tx));
    };
    return unsignedForm(first) === unsignedForm(second);
  } catch {
    return false;
  }
}

export function serializePQRecord(
  record: SentryPQRecord,
  allowUnactivated = false
): Uint8Array {
  if (
    record.version !== 1 ||
    record.profile !== 1 ||
    uint(record.keyVersion, 32, 'keyVersion') === 0
  ) {
    fail(
      'INVALID_PQ_RECORD',
      'Unsupported PQ global key record version/profile'
    );
  }
  const publicKey = fromHex(record.publicKey, 'PQ public key', 32);
  if (!nonzero(publicKey))
    fail('INVALID_PQ_RECORD', 'PQ public key cannot be zero');
  const child = fromHex(record.childKeyCommitmentHex, 'child commitment', 80);
  const reader = new Reader(child);
  const version = reader.number(2),
    profile = reader.number(2),
    usage = reader.number(2),
    depth = reader.number(2);
  const generation = reader.number(4);
  const firstEpoch = reader.number(4);
  if (
    version !== 1 ||
    profile !== 1 ||
    usage !== 235 ||
    depth !== 16 ||
    generation < 1 ||
    generation > 16 ||
    firstEpoch > 0xffffffff - 65535 ||
    !nonzero(reader.read(32)) ||
    !nonzero(reader.read(32))
  ) {
    fail('INVALID_PQ_RECORD', 'Invalid registered child commitment');
  }
  reader.end();
  if (
    uint(record.activatedHeight, 32, 'activatedHeight') === 0 &&
    !allowUnactivated
  )
    fail('INVALID_PQ_RECORD', 'Operator key has not activated');
  return concat(
    integerBytes(record.version, 2),
    integerBytes(record.profile, 2),
    integerBytes(record.keyVersion, 4),
    publicKey,
    child,
    integerBytes(uint(record.activatedHeight, 32, 'activatedHeight'), 4)
  );
}

/** Exact Core transcript; it is intentionally not the PQ payload serialization. */
export function serviceAuthorizationDigest(
  payload: ServicePayload,
  context: SentryReviewContext
): Uint8Array {
  if (payload.version === 3) return hash256(payloadBytes(payload, true));
  const record = context.node.pqRecord;
  if (
    !record ||
    record.keyVersion !== payload.globalKeyVersion ||
    record.keyVersion !== context.node.globalKeyVersion ||
    hex(fromHex(record.publicKey)) !==
      context.node.operatorPublicKey.toLowerCase()
  ) {
    fail(
      'KEY_MISMATCH',
      'PQ payload must use the current registered operator key'
    );
  }
  const recordHash = hash256(serializePQRecord(record));
  const address = new Uint8Array(32);
  address.set(payload.service.address);
  const endpoint = concat(
    Uint8Array.of(payload.service.network, payload.service.address.length),
    address,
    integerBytes(payload.service.port, 2)
  );
  const nevm =
    payload.nevmAddress === ''
      ? Uint8Array.of(0)
      : concat(
          Uint8Array.of(1),
          fromHex(payload.nevmAddress.slice(2), 'NEVM', 20)
        );
  return hash256(
    concat(
      new TextEncoder().encode(PQ_SERVICE_DOMAIN),
      hashBytes(context.chain.genesisHash, 'genesisHash'),
      integerBytes(1, 2),
      integerBytes(payload.version, 2),
      hashBytes(payload.proTxHash, 'proTxHash'),
      integerBytes(payload.globalKeyVersion!, 4),
      integerBytes(record.version, 2),
      integerBytes(record.profile, 2),
      recordHash,
      endpoint,
      vector(payload.payoutScript),
      nevm,
      payload.inputsHash
    )
  );
}

export function reviewFunding(
  request: { transactionHex: string },
  context: {
    previousTransactions: string[];
    maxFeeSatoshis: string;
    node?: { collateralOutpoint?: { txid: string; vout: number } };
  }
): bigint {
  if (
    !Array.isArray(context.previousTransactions) ||
    context.previousTransactions.length > 256
  )
    fail('INVALID_FUNDING', 'Exact funding transactions are required');
  const tx = decodeSentryTransaction(request.transactionHex);
  const previous = new Map(
    context.previousTransactions.map((raw) => {
      const transaction = decodeSentryTransaction(raw);
      return [transaction.txid, transaction] as const;
    })
  );
  if (previous.size !== context.previousTransactions.length)
    fail('INVALID_FUNDING', 'Duplicate funding transactions');
  const seen = new Set<string>();
  const usedPrevious = new Set<string>();
  let totalIn = 0n;
  for (const input of tx.inputs) {
    hashBytes(input.txid, 'input txid');
    const key = `${input.txid}:${input.vout}`;
    const collateral = context.node?.collateralOutpoint;
    if (
      collateral &&
      input.txid === collateral.txid.toLowerCase() &&
      input.vout === collateral.vout
    ) {
      fail(
        'COLLATERAL_SPEND',
        'A service update cannot spend the node collateral'
      );
    }
    if (seen.has(key)) fail('DUPLICATE_INPUT', 'Duplicate transaction input');
    seen.add(key);
    const prev = previous.get(input.txid);
    if (!prev || !prev.outputs[input.vout])
      fail('INVALID_FUNDING', 'Missing exact funding prevout');
    usedPrevious.add(input.txid);
    totalIn += amount(prev.outputs[input.vout].valueSatoshis, 'input amount');
    if (totalIn > MAX_MONEY)
      fail('INVALID_AMOUNT', 'Total funding exceeds MAX_MONEY');
  }
  if (usedPrevious.size !== previous.size)
    fail('INVALID_FUNDING', 'Unreferenced funding transaction');
  const totalOut = tx.outputs.reduce(
    (sum, output) => sum + amount(output.valueSatoshis, 'output amount'),
    0n
  );
  const fee = totalIn - totalOut;
  if (fee < 0n || fee > amount(context.maxFeeSatoshis, 'maximum fee'))
    fail(
      'FEE_LIMIT',
      'Funding fee is negative or exceeds the wallet safety limit'
    );
  return fee;
}

export function reviewSentryOperation(
  value: unknown,
  context: SentryReviewContext
): SentryOperationReview {
  const request = validateSentryOperationRequest(value);
  const expectedChain = validateChain(context.chain);
  if (
    request.chain.genesisHash !== expectedChain.genesisHash ||
    request.chain.era !== expectedChain.era
  ) {
    fail(
      'CHAIN_MISMATCH',
      'Requested chain/era does not match independently resolved wallet chain'
    );
  }
  validateNode(context.node, context.chain);
  const tx = decodeSentryTransaction(request.transactionHex);
  const { payload, outputIndex } = locateServicePayload(tx);
  if (payload.proTxHash !== context.node.proTxHash.toLowerCase())
    fail('NODE_MISMATCH', 'Payload targets a different registered node');
  const fee = reviewFunding(request, context);
  const authorizationHash = hex(serviceAuthorizationDigest(payload, context));
  return {
    operation: 'updateService',
    scheme: payload.version === 4 ? 'slh-dsa-shake-128s' : 'bls-basic',
    chain: expectedChain,
    proTxHash: payload.proTxHash,
    changes: {
      service: {
        previous: currentServiceText(context.node.service),
        next: payload.service.text,
      },
      operatorPayoutScript: {
        previous: hex(fromHex(context.node.operatorPayoutScript)),
        next: hex(payload.payoutScript),
      },
      nevmAddress: {
        previous: normalizeNEVM(context.node.nevmAddress),
        next: payload.nevmAddress,
      },
    },
    feeSatoshis: fee.toString(),
    inputCount: tx.inputs.length,
    outputs: tx.outputs.map((output, i) => ({
      ...output,
      isPayload: i === outputIndex,
    })),
    authorizationHash,
  };
}

export function getSentryCapabilities() {
  return {
    version: 1 as const,
    operations: ['updateService'] as const,
    eras: ['legacy-v3', 'pq-v4'] as const,
    schemes: ['bls-basic', 'slh-dsa-shake-128s'] as const,
    keyRoles: ['operator'] as const,
    feeSigning: 'separate-after-operator-authorization' as const,
    protocolSources: {
      legacy: 'dd1457d89a5906288d0c0813a157413e79f75f6d',
      pq: 'fa24600369c7afbe338afc09d07c840d21c2e205',
    },
  };
}
