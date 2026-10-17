import { equal, fail, fromHex, hex, nonzero } from './bytes.js';
import {
  decodeSentryTransaction,
  encodeTransaction,
  locateServicePayload,
  opReturn,
  payloadBytes,
} from './codec.js';
import {
  PQ_SERVICE_DOMAIN,
  reviewSentryOperation,
  validateSentryOperationRequest,
} from './review.js';

import type {
  SentryImportedKey,
  SentryOperationResponse,
  SentryReviewContext,
  SentryScheme,
} from './types.js';

const BLS_BASIC_DST = 'BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_';
const BLS_SCALAR_ORDER =
  0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n;

function assertScheme(scheme: SentryScheme): void {
  if (scheme !== 'bls-basic' && scheme !== 'slh-dsa-shake-128s')
    fail('UNSUPPORTED_SCHEME', 'Unsupported Sentry operator scheme');
}

/** Import is local-only. SLH imports recompute the root, as Core does. */
export async function importSentryOperatorKey(
  scheme: SentryScheme,
  secretKeyHex: string
): Promise<SentryImportedKey> {
  assertScheme(scheme);
  const secret = fromHex(
    secretKeyHex,
    'operator secret key',
    scheme === 'bls-basic' ? 32 : 64
  );
  let publicKey: Uint8Array;
  try {
    if (scheme === 'bls-basic') {
      // Core imports an exact scalar, not a scalar reduced modulo r. Noble's
      // point multiplication accepts broader integer encodings, so constrain it.
      const scalar = BigInt(`0x${hex(secret)}`);
      if (scalar === 0n || scalar >= BLS_SCALAR_ORDER)
        fail('INVALID_SECRET_KEY', 'Invalid BLS scalar');
      const { bls12_381 } = await import('@noble/curves/bls12-381.js');
      publicKey = bls12_381.longSignatures.getPublicKey(secret).toBytes();
    } else {
      const { slh_dsa_shake_128s } = await import(
        '@noble/post-quantum/slh-dsa.js'
      );
      const reconstructed = slh_dsa_shake_128s.keygen(secret.slice(0, 48));
      try {
        if (!equal(secret, reconstructed.secretKey))
          fail(
            'INVALID_SECRET_KEY',
            'SLH secret key root does not match its seed'
          );
        publicKey = reconstructed.publicKey.slice();
      } finally {
        reconstructed.secretKey.fill(0);
      }
    }
    return { scheme, publicKey: hex(publicKey), secretKey: hex(secret) };
  } catch {
    // Never pass third-party exception details (which may contain key material)
    // across the caller's dapp boundary.
    return fail('INVALID_SECRET_KEY', 'Invalid Sentry operator secret key');
  } finally {
    secret.fill(0);
  }
}

/** Explicit seed generation avoids confusing a SLH seed with an encoded key. */
export async function deriveSentryOperatorKey(
  scheme: SentryScheme,
  seedHex: string
): Promise<SentryImportedKey> {
  assertScheme(scheme);
  const seed = fromHex(
    seedHex,
    'key generation seed',
    scheme === 'bls-basic' ? 32 : 48
  );
  let secret: Uint8Array | undefined;
  try {
    if (scheme === 'bls-basic') {
      const { bls12_381 } = await import('@noble/curves/bls12-381.js');
      const { bytesToNumberBE } = await import('@noble/curves/utils.js');
      const { hkdf } = await import('@noble/hashes/hkdf.js');
      const { sha256 } = await import('@noble/hashes/sha2.js');
      // Match Core's BasicSchemeMPL::KeyGen / HDKeys::KeyGen exactly.
      // Noble keygen consumes 48 bytes of direct entropy; it is not this
      // 32-byte IKM -> HKDF-SHA256 -> Fr derivation.
      const ikm = new Uint8Array(seed.length + 1);
      ikm.set(seed);
      let okm: Uint8Array | undefined;
      try {
        okm = hkdf(
          sha256,
          ikm,
          new TextEncoder().encode('BLS-SIG-KEYGEN-SALT-'),
          Uint8Array.of(0, 48),
          48
        );
        const field = bls12_381.fields.Fr;
        secret = field.toBytes(field.create(bytesToNumberBE(okm)));
      } finally {
        ikm.fill(0);
        okm?.fill(0);
      }
    } else {
      const { slh_dsa_shake_128s } = await import(
        '@noble/post-quantum/slh-dsa.js'
      );
      secret = slh_dsa_shake_128s.keygen(seed).secretKey;
    }
    return await importSentryOperatorKey(scheme, hex(secret));
  } finally {
    seed.fill(0);
    secret?.fill(0);
  }
}

export async function signSentryOperation(
  value: unknown,
  context: SentryReviewContext,
  importedKey: SentryImportedKey
): Promise<SentryOperationResponse> {
  // Do not let account/RPC cache mutation during lazy crypto loading alter the
  // reviewed context. The caller still rechecks liveness before broadcasting.
  context = {
    ...context,
    chain: { ...context.chain },
    previousTransactions: [...context.previousTransactions],
    node: {
      ...context.node,
      pqRecord: context.node.pqRecord
        ? { ...context.node.pqRecord }
        : undefined,
      collateralOutpoint: context.node.collateralOutpoint
        ? { ...context.node.collateralOutpoint }
        : undefined,
    },
  };
  importedKey = { ...importedKey };
  const request = validateSentryOperationRequest(value);
  const review = reviewSentryOperation(request, context);
  if (review.scheme !== importedKey.scheme)
    fail('KEY_MISMATCH', 'Selected operator key uses another scheme');
  const tx = decodeSentryTransaction(request.transactionHex);
  if (
    tx.inputs.some(
      (input) => input.scriptHex !== '' || input.witness.length !== 0
    )
  ) {
    fail(
      'SIGNED_FUNDING',
      'Fee inputs must be signed after operator authorization'
    );
  }
  const { payload, outputIndex } = locateServicePayload(tx);
  if (nonzero(payload.signature))
    fail(
      'ALREADY_AUTHORIZED',
      'Service transaction already contains an operator signature'
    );
  const key = await importSentryOperatorKey(
    importedKey.scheme,
    importedKey.secretKey
  );
  if (
    key.publicKey !== context.node.operatorPublicKey.toLowerCase() ||
    key.publicKey !== importedKey.publicKey.toLowerCase()
  ) {
    fail('KEY_MISMATCH', 'Selected key does not match the registered operator');
  }
  const secret = fromHex(key.secretKey, 'operator secret key');
  const digest = fromHex(review.authorizationHash, 'authorization digest', 32);
  try {
    if (review.scheme === 'bls-basic') {
      const { bls12_381 } = await import('@noble/curves/bls12-381.js');
      const basic = bls12_381.longSignatures;
      payload.signature = basic
        .sign(basic.hash(digest, BLS_BASIC_DST), secret)
        .toBytes();
    } else {
      const { slh_dsa_shake_128s } = await import(
        '@noble/post-quantum/slh-dsa.js'
      );
      payload.signature = slh_dsa_shake_128s.sign(digest, secret, {
        context: new TextEncoder().encode(PQ_SERVICE_DOMAIN),
        extraEntropy: false,
      });
    }
    tx.outputs[outputIndex].scriptHex = hex(opReturn(payloadBytes(payload)));
    const transactionHex = hex(encodeTransaction(tx));
    const result = { ...request, transactionHex };
    if (!(await verifySentryOperation(result, context)))
      fail('SIGNATURE_FAILED', 'Operator authorization did not verify');
    return {
      version: 1,
      operation: 'updateService',
      transactionHex,
      operatorPublicKey: key.publicKey,
      authorizationHash: review.authorizationHash,
    };
  } finally {
    secret.fill(0);
    digest.fill(0);
  }
}

/** Works both before and after the distinct fee-input signing step. */
export async function verifySentryOperation(
  value: unknown,
  context: SentryReviewContext
): Promise<boolean> {
  try {
    const request = validateSentryOperationRequest(value);
    const review = reviewSentryOperation(request, context);
    const { payload } = locateServicePayload(
      decodeSentryTransaction(request.transactionHex)
    );
    if (!nonzero(payload.signature)) return false;
    const digest = fromHex(review.authorizationHash, 'authorization hash', 32);
    const publicKey = fromHex(
      context.node.operatorPublicKey,
      'operator public key',
      review.scheme === 'bls-basic' ? 48 : 32
    );
    if (review.scheme === 'bls-basic') {
      const { bls12_381 } = await import('@noble/curves/bls12-381.js');
      const basic = bls12_381.longSignatures;
      return basic.verify(
        payload.signature,
        basic.hash(digest, BLS_BASIC_DST),
        publicKey
      );
    }
    const { slh_dsa_shake_128s } = await import(
      '@noble/post-quantum/slh-dsa.js'
    );
    return slh_dsa_shake_128s.verify(payload.signature, digest, publicKey, {
      context: new TextEncoder().encode(PQ_SERVICE_DOMAIN),
    });
  } catch {
    return false;
  }
}
