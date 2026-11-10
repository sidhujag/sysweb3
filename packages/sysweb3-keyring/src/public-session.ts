import { privateRecordDomainSet } from './private-records';

import type { IEncryptedPrivateRecord } from './private-records';

/** Public state is supplied as one canonical, immutable host manifest. */
export type PublicSessionCheckpointRequest = Readonly<{
  walletBindingId: string;
  publicState: Uint8Array;
  recordDomains: readonly string[];
}>;
export type PublicSessionRestoreRequest = PublicSessionCheckpointRequest &
  Readonly<{ checkpoint: IEncryptedPrivateRecord }>;
export const MAX_PUBLIC_SESSION_STATE_BYTES = 4 * 1024 * 1024;

export function capturePublicSessionRequest(
  input: PublicSessionCheckpointRequest
): PublicSessionCheckpointRequest {
  if (!input || typeof input !== 'object')
    throw new Error('Invalid public session request');
  const fields = Object.getOwnPropertyDescriptors(input);
  for (const name of ['walletBindingId', 'publicState', 'recordDomains']) {
    if (!fields[name] || !('value' in fields[name]))
      throw new Error('Invalid public session request');
  }
  const walletBindingId = fields.walletBindingId.value;
  const state = fields.publicState.value;
  if (
    typeof walletBindingId !== 'string' ||
    !/^[0-9a-f]{64}$/.test(walletBindingId) ||
    !(state instanceof Uint8Array) ||
    state.length === 0 ||
    state.length > MAX_PUBLIC_SESSION_STATE_BYTES
  )
    throw new Error('Invalid public session request');
  const domains: string[] = JSON.parse(
    privateRecordDomainSet(fields.recordDomains!.value!)
  );
  return Object.freeze({
    walletBindingId,
    publicState: new Uint8Array(state),
    recordDomains: Object.freeze(domains),
  });
}

export function capturePublicSessionCheckpoint(
  input: PublicSessionRestoreRequest
): IEncryptedPrivateRecord {
  const descriptor = Object.getOwnPropertyDescriptor(input, 'checkpoint');
  if (!descriptor || !('value' in descriptor))
    throw new Error('Invalid public session checkpoint');
  const value = descriptor.value;
  if (!value || typeof value !== 'object')
    throw new Error('Invalid public session checkpoint');
  const fields = Object.getOwnPropertyDescriptors(value);
  const names = [
    'version',
    'domain',
    'recordId',
    'profileId',
    'nonce',
    'ciphertext',
  ];
  if (
    Reflect.ownKeys(fields).length !== names.length ||
    names.some((name) => !fields[name] || !('value' in fields[name]))
  )
    throw new Error('Invalid public session checkpoint');
  return Object.freeze(
    Object.fromEntries(names.map((name) => [name, fields[name].value]))
  ) as unknown as IEncryptedPrivateRecord;
}

export async function publicSessionStateDigest(
  state: Uint8Array,
  guard: () => void
): Promise<Uint8Array> {
  guard();
  const digest = new Uint8Array(
    await globalThis.crypto.subtle.digest(
      'SHA-256',
      state as unknown as BufferSource
    )
  );
  guard();
  return digest;
}
