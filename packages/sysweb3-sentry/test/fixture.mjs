import {
  buildSentryServiceUpdate,
  decodeSentryTransaction,
  importSentryOperatorKey,
} from '../dist/index.js';
import { encodeTransaction } from '../dist/codec.js';
import { hex } from '../dist/bytes.js';

export const BLS_SK = '00'.repeat(31) + '01';
export const GENESIS = '12'.repeat(32);
export const PRO_TX = '23'.repeat(32);
export const PAYOUT = '0014' + '34'.repeat(20);
export const OLD_NEVM = '0x' + '45'.repeat(20);
export const NEW_NEVM = '0x' + '56'.repeat(20);

export function previousTransaction() {
  // Synthetic coinbase funding fixture. Its hash is computed from the bytes,
  // not supplied as an unauthenticated amount alongside the service request.
  return hex(
    encodeTransaction({
      version: 2,
      lockTime: 0,
      inputs: [
        {
          txid: '00'.repeat(32),
          vout: 0xffffffff,
          sequence: 0xffffffff,
          scriptHex: '0101',
          witness: [],
        },
      ],
      outputs: [{ valueSatoshis: '1000000', scriptHex: PAYOUT }],
    })
  );
}

export async function legacyFixture(overrides = {}) {
  const key = await importSentryOperatorKey('bls-basic', BLS_SK);
  const previous = previousTransaction();
  const chain = { genesisHash: GENESIS, era: 'legacy-v3' };
  const node = {
    proTxHash: PRO_TX,
    operatorPublicKey: key.publicKey,
    service: '127.0.0.1:18367',
    operatorPayoutScript: PAYOUT,
    nevmAddress: OLD_NEVM,
    ...overrides,
  };
  const request = buildSentryServiceUpdate({
    chain,
    node,
    nevmAddress: NEW_NEVM,
    inputs: [{ txid: decodeSentryTransaction(previous).txid, vout: 0 }],
    outputs: [{ valueSatoshis: '998000', scriptHex: PAYOUT }],
  });
  const context = {
    chain,
    node,
    previousTransactions: [previous],
    maxFeeSatoshis: '10000',
  };
  return { key, request, context };
}

export function replacePayload(request, mutate) {
  // Helpers use the actual codec instead of making review fields authoritative.
  return import('../dist/codec.js').then(
    ({ locateServicePayload, opReturn, payloadBytes }) => {
      const tx = decodeSentryTransaction(request.transactionHex);
      const { payload, outputIndex } = locateServicePayload(tx);
      mutate(payload);
      tx.outputs[outputIndex].scriptHex = hex(opReturn(payloadBytes(payload)));
      return { ...request, transactionHex: hex(encodeTransaction(tx)) };
    }
  );
}
