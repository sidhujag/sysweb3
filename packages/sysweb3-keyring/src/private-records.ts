/** Versioned, public envelope. Application metadata belongs inside the plaintext. */
export interface IEncryptedPrivateRecord {
  ciphertext: string;
  domain: string;
  nonce: string;
  profileId: string;
  recordId: string;
  version: 1;
}

export interface IEncryptPrivateRecordParams {
  domain: string;
  plaintext: Uint8Array;
  recordId: string;
}

export interface IDecryptPrivateRecordParams {
  domain: string;
  envelope: IEncryptedPrivateRecord;
  recordId: string;
}

export const MAX_PRIVATE_RECORD_BYTES = 64 * 1024;
export const MAX_PRIVATE_RECORD_LABEL_BYTES = 128;

const NAMESPACE = 'sysweb3/private-record/v1';
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const encoder = new TextEncoder();
const LABEL_START = /^[A-Za-z0-9]/;
const INVALID_LABEL_CHARACTER = /[^A-Za-z0-9._:/-]/;
const PROFILE = /^0x[0-9a-f]{64}$/;
const BASE64 =
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
type Guard = () => void;

// Views passed to WebCrypto are owned, non-shared copies. This cast supports
// DOM typings both before and after generic ArrayBufferLike typed arrays.
const bufferSource = (bytes: Uint8Array): BufferSource =>
  bytes as unknown as BufferSource;

function cryptoProvider(): Crypto {
  if (!globalThis.crypto?.subtle || !globalThis.crypto.getRandomValues) {
    throw new Error('Private record cryptography unavailable');
  }
  return globalThis.crypto;
}

function label(value: string): string {
  if (
    typeof value !== 'string' ||
    value.length > MAX_PRIVATE_RECORD_LABEL_BYTES ||
    !LABEL_START.test(value) ||
    INVALID_LABEL_CHARACTER.test(value)
  ) {
    throw new Error('Invalid private record context');
  }
  return value;
}

function encodeBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}

function decodeBase64(value: string, min: number, max: number): Uint8Array {
  if (
    typeof value !== 'string' ||
    value.length > 4 * Math.ceil(max / 3) ||
    !BASE64.test(value)
  ) {
    throw new Error('Invalid private record envelope');
  }
  const bytes = new Uint8Array(Buffer.from(value, 'base64'));
  if (
    bytes.length < min ||
    bytes.length > max ||
    encodeBase64(bytes) !== value
  ) {
    throw new Error('Invalid private record envelope');
  }
  return bytes;
}

async function importRoot(
  secret: Uint8Array,
  guard: Guard
): Promise<CryptoKey> {
  const key = await cryptoProvider().subtle.importKey(
    'raw',
    bufferSource(secret),
    'HKDF',
    false,
    ['deriveBits', 'deriveKey']
  );
  guard();
  return key;
}

async function profileId(key: CryptoKey, guard: Guard): Promise<string> {
  const bits = await cryptoProvider().subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: bufferSource(encoder.encode(NAMESPACE)),
      info: bufferSource(
        encoder.encode(JSON.stringify([NAMESPACE, 'profile-id']))
      ),
    },
    key,
    256
  );
  guard();
  return `0x${Buffer.from(bits).toString('hex')}`;
}

async function domainKey(
  key: CryptoKey,
  domain: string,
  guard: Guard
): Promise<CryptoKey> {
  const derived = await cryptoProvider().subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: bufferSource(encoder.encode(NAMESPACE)),
      info: bufferSource(
        encoder.encode(JSON.stringify([NAMESPACE, 'encryption-key', domain]))
      ),
    },
    key,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
  guard();
  return derived;
}

function additionalData(domain: string, recordId: string, profile: string) {
  return encoder.encode(
    JSON.stringify([NAMESPACE, 1, domain, recordId, profile])
  );
}

// Internal helpers accept ephemeral bytes and never access wallet storage.
// Only the envelope types and limits are exported from the package entrypoint.
export async function privateRecordProfileId(
  secret: Uint8Array,
  guard: Guard
): Promise<string> {
  return profileId(await importRoot(secret, guard), guard);
}

export async function encryptPrivateRecordBytes(
  secret: Uint8Array,
  params: IEncryptPrivateRecordParams,
  guard: Guard
): Promise<IEncryptedPrivateRecord> {
  const domain = label(params.domain);
  const recordId = label(params.recordId);
  if (
    !(params.plaintext instanceof Uint8Array) ||
    params.plaintext.length > MAX_PRIVATE_RECORD_BYTES
  ) {
    throw new Error('Invalid private record size');
  }
  // Own the input before the first await; caller mutations cannot change it.
  const plaintext = new Uint8Array(params.plaintext);
  try {
    const key = await importRoot(secret, guard);
    const profile = await profileId(key, guard);
    const aesKey = await domainKey(key, domain, guard);
    const nonce = cryptoProvider().getRandomValues(new Uint8Array(NONCE_BYTES));
    const encrypted = await cryptoProvider().subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: bufferSource(nonce),
        tagLength: 128,
        additionalData: bufferSource(additionalData(domain, recordId, profile)),
      },
      aesKey,
      bufferSource(plaintext)
    );
    guard();
    return {
      version: 1,
      domain,
      recordId,
      profileId: profile,
      nonce: encodeBase64(nonce),
      ciphertext: encodeBase64(new Uint8Array(encrypted)),
    };
  } finally {
    plaintext.fill(0);
  }
}

export async function decryptPrivateRecordBytes(
  secret: Uint8Array,
  params: IDecryptPrivateRecordParams,
  guard: Guard
): Promise<Uint8Array> {
  const domain = label(params.domain);
  const recordId = label(params.recordId);
  // Copy primitive fields before awaiting. No caller-owned object is retained.
  const envelope = params.envelope && { ...params.envelope };
  if (
    !envelope ||
    Object.keys(envelope).length !== 6 ||
    envelope.version !== 1 ||
    envelope.domain !== domain ||
    envelope.recordId !== recordId ||
    typeof envelope.profileId !== 'string' ||
    envelope.profileId.length !== 66 ||
    !PROFILE.test(envelope.profileId)
  ) {
    throw new Error('Invalid private record envelope');
  }
  const nonce = decodeBase64(envelope.nonce, NONCE_BYTES, NONCE_BYTES);
  const ciphertext = decodeBase64(
    envelope.ciphertext,
    TAG_BYTES,
    MAX_PRIVATE_RECORD_BYTES + TAG_BYTES
  );
  const key = await importRoot(secret, guard);
  const profile = await profileId(key, guard);
  if (profile !== envelope.profileId) {
    throw new Error('Private record profile mismatch');
  }
  const aesKey = await domainKey(key, domain, guard);
  let plaintext: Uint8Array | undefined;
  try {
    plaintext = new Uint8Array(
      await cryptoProvider().subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: bufferSource(nonce),
          tagLength: 128,
          additionalData: bufferSource(
            additionalData(domain, recordId, profile)
          ),
        },
        aesKey,
        bufferSource(ciphertext)
      )
    );
    guard();
    return plaintext;
  } catch {
    plaintext?.fill(0);
    guard();
    throw new Error('Private record authentication failed');
  }
}
