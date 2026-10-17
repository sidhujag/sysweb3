import {
  MAX_MONEY,
  MAX_TX_BYTES,
  Reader,
  amount,
  compactSize,
  concat,
  displayHash,
  equal,
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
import type {
  BuildSentryServiceUpdate,
  DecodedSentryTransaction,
  SentryChain,
  SentryNodeState,
  SentryOperationRequest,
} from './types.js';

export const UPDATE_SERVICE_TX_VERSION = 81;
export const LEGACY_SERVICE_VERSION = 3;
export const PQ_SERVICE_VERSION = 4;
export const BLS_SIGNATURE_SIZE = 96;
export const PQ_SIGNATURE_SIZE = 7856;
const MAX_INPUTS_OUTPUTS = 256;
const MAX_SCRIPT = 10_000;

export interface ServiceAddress {
  bytes: Uint8Array;
  text: string;
  network: 1 | 2 | 5;
  address: Uint8Array;
  port: number;
}
export interface ServicePayload {
  version: 3 | 4;
  proTxHash: string;
  service: ServiceAddress;
  payoutScript: Uint8Array;
  inputsHash: Uint8Array;
  globalKeyVersion?: number;
  signature: Uint8Array;
  nevmAddress: string;
}

function ipv4(text: string): Uint8Array | undefined {
  if (!/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(text)) return undefined;
  const parts = text.split('.');
  if (parts.some((p) => Number(p) > 255 || String(Number(p)) !== p))
    return undefined;
  return Uint8Array.from(parts.map(Number));
}

function ipv6(text: string): Uint8Array | undefined {
  if (
    !/^[a-fA-F0-9:]+$/.test(text) ||
    !text.includes(':') ||
    text.split('::').length > 2
  )
    return undefined;
  const sides = text.split('::');
  const left = sides[0] ? sides[0].split(':') : [];
  const right = sides.length === 2 && sides[1] ? sides[1].split(':') : [];
  if ([...left, ...right].some((s) => !/^[a-fA-F0-9]{1,4}$/.test(s)))
    return undefined;
  const gap = 8 - left.length - right.length;
  if ((sides.length === 1 && gap !== 0) || (sides.length === 2 && gap < 1))
    return undefined;
  const groups = [...left, ...Array(gap).fill('0'), ...right];
  return concat(
    ...groups.map((group) => integerBytes(parseInt(group, 16), 2, true))
  );
}

export function serviceFromBytes(bytes: Uint8Array): ServiceAddress {
  if (bytes.length !== 18)
    fail('INVALID_SERVICE', 'Service must contain 16 address bytes and port');
  const port = Number(new Reader(bytes.slice(16)).integer(2, true));
  if (port === 0) fail('INVALID_SERVICE', 'Service port cannot be zero');
  const address = bytes.slice(0, 16);
  const mapped =
    address.slice(0, 10).every((b) => b === 0) &&
    address[10] === 255 &&
    address[11] === 255;
  if (mapped) {
    const ip = address.slice(12);
    if (!nonzero(ip))
      fail('INVALID_SERVICE', 'Service address cannot be unspecified');
    return {
      bytes,
      text: `${Array.from(ip).join('.')}:${port}`,
      network: 1,
      address: ip,
      port,
    };
  }
  if (!nonzero(address))
    fail('INVALID_SERVICE', 'Service address cannot be unspecified');
  const groups = Array.from({ length: 8 }, (_, i) =>
    ((address[i * 2] << 8) | address[i * 2 + 1]).toString(16)
  );
  // Fixed-width identity is independent of how a user compresses IPv6 text.
  return {
    bytes,
    text: `[${groups.join(':')}]:${port}`,
    network: address[0] === 0xfc ? 5 : 2,
    address,
    port,
  };
}

export function parseService(value: unknown): ServiceAddress {
  if (typeof value !== 'string' || value.length > 80)
    fail('INVALID_SERVICE', 'Service must be an IP address and port');
  const match = /^(?:\[([^\]]+)\]|([^:]+)):([0-9]{1,5})$/.exec(value);
  if (!match)
    fail('INVALID_SERVICE', 'Use IPv4:port or [IPv6]:port; DNS is not signed');
  const port = Number(match[3]);
  if (port < 1 || port > 65535 || String(port) !== match[3])
    fail('INVALID_SERVICE', 'Invalid service port');
  const ip = match[1] ? ipv6(match[1]) : ipv4(match[2]);
  if (!ip) fail('INVALID_SERVICE', 'Invalid IP service address');
  const encoded =
    ip.length === 4
      ? concat(new Uint8Array(10), Uint8Array.of(255, 255), ip)
      : ip;
  return serviceFromBytes(concat(encoded, integerBytes(port, 2, true)));
}

export function normalizeNEVM(value: unknown): string {
  if (value === '') return '';
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(value))
    fail(
      'INVALID_NEVM',
      'NEVM must be 0x plus 20 bytes, or empty to unregister'
    );
  return value.toLowerCase();
}

export function payloadBytes(
  payload: ServicePayload,
  hashing = false
): Uint8Array {
  const prefix = concat(
    integerBytes(payload.version, 2),
    hashBytes(payload.proTxHash, 'proTxHash'),
    payload.service.bytes,
    vector(payload.payoutScript),
    payload.inputsHash
  );
  const auth =
    payload.version === 4
      ? concat(
          integerBytes(payload.globalKeyVersion!, 4),
          ...(hashing ? [] : [payload.signature])
        )
      : hashing
      ? new Uint8Array()
      : payload.signature;
  return concat(
    prefix,
    auth,
    vector(
      payload.nevmAddress === ''
        ? new Uint8Array()
        : fromHex(payload.nevmAddress.slice(2), 'NEVM', 20)
    )
  );
}

export function decodePayload(bytes: Uint8Array): ServicePayload {
  const reader = new Reader(bytes);
  const version = reader.number(2);
  if (version !== 3 && version !== 4)
    fail(
      'UNSUPPORTED_ERA',
      'Only current legacy-v3 and PQ-v4 service updates are supported'
    );
  const proTxHash = displayHash(reader.read(32));
  hashBytes(proTxHash, 'proTxHash');
  const service = serviceFromBytes(reader.read(18));
  const payoutScript = reader.vector(MAX_SCRIPT);
  const inputsHash = reader.read(32);
  if (!nonzero(inputsHash))
    fail('INVALID_INPUTS_HASH', 'Inputs hash cannot be zero');
  const globalKeyVersion = version === 4 ? reader.number(4) : undefined;
  if (globalKeyVersion === 0)
    fail('INVALID_KEY_VERSION', 'PQ key version cannot be zero');
  const signature = reader.read(
    version === 4 ? PQ_SIGNATURE_SIZE : BLS_SIGNATURE_SIZE
  );
  const nevm = reader.vector(20);
  if (nevm.length !== 0 && nevm.length !== 20)
    fail('INVALID_NEVM', 'NEVM must be exactly 20 bytes');
  reader.end();
  const result: ServicePayload = {
    version,
    proTxHash,
    service,
    payoutScript,
    inputsHash,
    globalKeyVersion,
    signature,
    nevmAddress: nevm.length ? `0x${hex(nevm)}` : '',
  };
  if (!equal(payloadBytes(result), bytes))
    fail('NON_CANONICAL', 'Payload does not reserialize canonically');
  return result;
}

export function opReturn(payload: Uint8Array): Uint8Array {
  const push =
    payload.length < 76
      ? Uint8Array.of(payload.length)
      : payload.length <= 255
      ? concat(Uint8Array.of(76), integerBytes(payload.length, 1))
      : payload.length <= 65535
      ? concat(Uint8Array.of(77), integerBytes(payload.length, 2))
      : concat(Uint8Array.of(78), integerBytes(payload.length, 4));
  return concat(Uint8Array.of(0x6a), push, payload);
}

export function extractOpReturn(script: Uint8Array): Uint8Array {
  const reader = new Reader(script);
  if (reader.number(1) !== 0x6a)
    fail('INVALID_PAYLOAD', 'Payload output must be OP_RETURN');
  const push = reader.number(1);
  const length =
    push < 76
      ? push
      : push === 76
      ? reader.number(1)
      : push === 77
      ? reader.number(2)
      : push === 78
      ? reader.number(4)
      : -1;
  if (
    length < 0 ||
    length > MAX_TX_BYTES ||
    (push === 76 && length < 76) ||
    (push === 77 && length <= 255) ||
    (push === 78 && length <= 65535)
  )
    fail('NON_CANONICAL', 'Non-canonical OP_RETURN push');
  const payload = reader.read(length);
  reader.end();
  return payload;
}

export function encodeTransaction(
  tx: Pick<
    DecodedSentryTransaction,
    'version' | 'inputs' | 'outputs' | 'lockTime'
  >,
  includeWitness = true
): Uint8Array {
  const witness =
    includeWitness && tx.inputs.some((input) => input.witness.length);
  const encoded = concat(
    integerBytes(tx.version, 4),
    ...(witness ? [Uint8Array.of(0, 1)] : []),
    compactSize(tx.inputs.length),
    ...tx.inputs.map((input) =>
      concat(
        fromHex(input.txid, 'input txid', 32).reverse(),
        integerBytes(input.vout, 4),
        vector(fromHex(input.scriptHex, 'input script')),
        integerBytes(input.sequence, 4)
      )
    ),
    compactSize(tx.outputs.length),
    ...tx.outputs.map((output) =>
      concat(
        integerBytes(amount(output.valueSatoshis, 'output value'), 8),
        vector(fromHex(output.scriptHex, 'output script'))
      )
    ),
    ...(witness
      ? tx.inputs.map((input) =>
          concat(
            compactSize(input.witness.length),
            ...input.witness.map((item) =>
              vector(fromHex(item, 'witness item'))
            )
          )
        )
      : []),
    integerBytes(tx.lockTime, 4)
  );
  if (encoded.length > MAX_TX_BYTES) fail('LIMIT', 'Transaction is too large');
  return encoded;
}

/** Strict general Bitcoin-style transaction decoder for funding and service transactions. */
export function decodeSentryTransaction(
  transactionHex: string
): DecodedSentryTransaction {
  const bytes = fromHex(transactionHex, 'transaction');
  const reader = new Reader(bytes);
  const version = reader.number(4);
  let witness = false;
  if (reader.bytes[reader.offset] === 0) {
    reader.read(1);
    if (reader.number(1) !== 1)
      fail('INVALID_TRANSACTION', 'Unknown witness flag');
    witness = true;
  }
  const inputCount = reader.size(MAX_INPUTS_OUTPUTS);
  if (!inputCount) fail('INVALID_TRANSACTION', 'Transaction has no inputs');
  const inputs: DecodedSentryTransaction['inputs'] = [];
  for (let i = 0; i < inputCount; i++) {
    inputs.push({
      txid: displayHash(reader.read(32)),
      vout: reader.number(4),
      scriptHex: hex(reader.vector(MAX_SCRIPT)),
      sequence: reader.number(4),
      witness: [],
    });
  }
  const outputCount = reader.size(MAX_INPUTS_OUTPUTS);
  if (!outputCount) fail('INVALID_TRANSACTION', 'Transaction has no outputs');
  const outputs: DecodedSentryTransaction['outputs'] = [];
  let total = 0n;
  for (let i = 0; i < outputCount; i++) {
    const value = reader.integer(8);
    total += value;
    if (value > MAX_MONEY || total > MAX_MONEY)
      fail('INVALID_AMOUNT', 'Transaction output value exceeds MAX_MONEY');
    outputs.push({
      valueSatoshis: value.toString(),
      scriptHex: hex(reader.vector(MAX_TX_BYTES)),
    });
  }
  if (witness) {
    for (const input of inputs) {
      const count = reader.size(100);
      for (let i = 0; i < count; i++)
        input.witness.push(hex(reader.vector(MAX_SCRIPT)));
    }
    if (!inputs.some((input) => input.witness.length))
      fail('NON_CANONICAL', 'Superfluous witness encoding');
  }
  const lockTime = reader.number(4);
  reader.end();
  const stripped = encodeTransaction(
    { version, inputs, outputs, lockTime },
    false
  );
  const weight = stripped.length * 3 + bytes.length;
  return {
    version,
    inputs,
    outputs,
    lockTime,
    txid: displayHash(hash256(stripped)),
    weight,
    virtualSize: Math.ceil(weight / 4),
  };
}

export function orderedInputsHash(tx: DecodedSentryTransaction): Uint8Array {
  return hash256(
    concat(
      ...tx.inputs.map((input) =>
        concat(hashBytes(input.txid, 'input txid'), integerBytes(input.vout, 4))
      )
    )
  );
}

export function locateServicePayload(tx: DecodedSentryTransaction): {
  payload: ServicePayload;
  outputIndex: number;
} {
  if (tx.version !== UPDATE_SERVICE_TX_VERSION)
    fail('UNSUPPORTED_OPERATION', 'Transaction is not a service update');
  const indices = tx.outputs.flatMap((output, i) =>
    fromHex(output.scriptHex)[0] === 0x6a ? [i] : []
  );
  if (indices.length !== 1)
    fail('INVALID_PAYLOAD', 'Exactly one OP_RETURN output is required');
  const outputIndex = indices[0];
  if (tx.outputs[outputIndex].valueSatoshis !== '0')
    fail('INVALID_PAYLOAD', 'Payload output must have zero value');
  const payload = decodePayload(
    extractOpReturn(fromHex(tx.outputs[outputIndex].scriptHex))
  );
  // Both pinned Core versions' CheckService currently require IPv4, even
  // though the PQ transcript format can encode additional future families.
  if (payload.service.network !== 1)
    fail(
      'UNSUPPORTED_SERVICE',
      'The current Core service-update policy requires IPv4'
    );
  if (!equal(payload.inputsHash, orderedInputsHash(tx)))
    fail(
      'INPUTS_MISMATCH',
      'Payload inputsHash does not match ordered funding inputs'
    );
  return { payload, outputIndex };
}

function validateChain(chain: SentryChain): void {
  hashBytes(chain.genesisHash, 'genesisHash');
  if (chain.era !== 'legacy-v3' && chain.era !== 'pq-v4')
    fail('UNSUPPORTED_ERA', 'Unsupported Sentry era');
}

export function validateNode(node: SentryNodeState, chain: SentryChain): void {
  validateChain(chain);
  hashBytes(node.proTxHash, 'proTxHash');
  parseService(node.service);
  const payout = fromHex(node.operatorPayoutScript, 'operator payout script');
  if (payout.length > MAX_SCRIPT)
    fail('LIMIT', 'Operator payout script too large');
  normalizeNEVM(node.nevmAddress);
  if (node.collateralOutpoint) {
    hashBytes(node.collateralOutpoint.txid, 'collateral txid');
    uint(node.collateralOutpoint.vout, 32, 'collateral vout');
  }
  const pk = fromHex(
    node.operatorPublicKey,
    'operator public key',
    chain.era === 'pq-v4' ? 32 : 48
  );
  if (!nonzero(pk))
    fail('INVALID_PUBLIC_KEY', 'Operator public key cannot be zero');
  if (
    chain.era === 'pq-v4' &&
    (uint(node.globalKeyVersion, 32, 'globalKeyVersion') === 0 ||
      !node.pqRecord)
  ) {
    fail('INVALID_KEY_VERSION', 'PQ registered key record is required');
  }
}

export function buildSentryServiceUpdate(
  options: BuildSentryServiceUpdate
): SentryOperationRequest {
  validateNode(options.node, options.chain);
  if (
    !Array.isArray(options.inputs) ||
    !options.inputs.length ||
    options.inputs.length > MAX_INPUTS_OUTPUTS ||
    !Array.isArray(options.outputs) ||
    options.outputs.length >= MAX_INPUTS_OUTPUTS
  )
    fail('LIMIT', 'Invalid funding inputs/outputs');
  const inputs = options.inputs.map((input) => ({
    txid: displayHash(hashBytes(input.txid, 'input txid')),
    vout: uint(input.vout, 32, 'input vout'),
    sequence: uint(input.sequence ?? 0xfffffffe, 32, 'sequence'),
    scriptHex: '',
    witness: [],
  }));
  const outputs = options.outputs.map((output) => {
    const script = fromHex(output.scriptHex, 'output script');
    if (script.length > MAX_SCRIPT || script[0] === 0x6a)
      fail('INVALID_OUTPUT', 'Funding outputs cannot contain an OP_RETURN');
    return {
      valueSatoshis: amount(output.valueSatoshis, 'output value').toString(),
      scriptHex: hex(script),
    };
  });
  const tx = {
    version: UPDATE_SERVICE_TX_VERSION,
    inputs,
    outputs,
    lockTime: uint(options.lockTime ?? 0, 32, 'lockTime'),
  };
  const version =
    options.chain.era === 'pq-v4' ? PQ_SERVICE_VERSION : LEGACY_SERVICE_VERSION;
  const payload: ServicePayload = {
    version,
    proTxHash: options.node.proTxHash.toLowerCase(),
    service: parseService(options.service ?? options.node.service),
    payoutScript: fromHex(
      options.operatorPayoutScript ?? options.node.operatorPayoutScript,
      'operator payout'
    ),
    nevmAddress: normalizeNEVM(options.nevmAddress ?? options.node.nevmAddress),
    inputsHash: orderedInputsHash({
      ...tx,
      txid: '',
      weight: 0,
      virtualSize: 0,
    }),
    globalKeyVersion: version === 4 ? options.node.globalKeyVersion : undefined,
    signature: new Uint8Array(
      version === 4 ? PQ_SIGNATURE_SIZE : BLS_SIGNATURE_SIZE
    ),
  };
  outputs.push({
    valueSatoshis: '0',
    scriptHex: hex(opReturn(payloadBytes(payload))),
  });
  const result: SentryOperationRequest = {
    version: 1,
    operation: 'updateService',
    chain: { ...options.chain },
    transactionHex: hex(encodeTransaction(tx)),
  };
  // Runs all decoder bounds and money-range checks before exposing bytes.
  locateServicePayload(decodeSentryTransaction(result.transactionHex));
  return result;
}

/** Conservative fee sizing: assumes every funding input is legacy 148-byte P2PKH. */
export function estimateSentrySignedVBytes(
  request: SentryOperationRequest
): number {
  const tx = decodeSentryTransaction(request.transactionHex);
  locateServicePayload(tx);
  // Each unsigned input already contains 41 bytes. Legacy scripts add at most
  // 108 bytes; P2WPKH is smaller. Arbitrary multisig must use its own estimator.
  return tx.virtualSize + tx.inputs.length * 108;
}
