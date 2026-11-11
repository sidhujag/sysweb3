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

export interface PrivateRecordAccessOptions {
  /** Move this grant with trusted public-session transfer; otherwise transfer retires it. */
  transferable: boolean;
}

export interface IPrivateRecordAccess {
  getPrivateRecordProfileId(): Promise<string>;
  encryptPrivateRecord(
    params: IEncryptPrivateRecordParams
  ): Promise<IEncryptedPrivateRecord>;
  decryptPrivateRecord(
    params: IDecryptPrivateRecordParams
  ): Promise<Uint8Array>;
  dispose(): void;
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

function domainParameters(domain: string): HkdfParams {
  return {
    name: 'HKDF',
    hash: 'SHA-256',
    salt: bufferSource(encoder.encode(NAMESPACE)),
    info: bufferSource(
      encoder.encode(JSON.stringify([NAMESPACE, 'encryption-key', domain]))
    ),
  };
}

async function domainKey(
  key: CryptoKey,
  domain: string,
  guard: Guard
): Promise<CryptoKey> {
  const derived = await cryptoProvider().subtle.deriveKey(
    domainParameters(domain),
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
  return encryptRecord(params, guard, async (domain) => {
    const key = await importRoot(secret, guard);
    return {
      profile: await profileId(key, guard),
      aesKey: await domainKey(key, domain, guard),
    };
  });
}

type RecordKey = { profile: string; aesKey: CryptoKey };
async function encryptRecord(
  params: IEncryptPrivateRecordParams,
  guard: Guard,
  keys: (domain: string) => Promise<RecordKey>
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
    const { profile, aesKey } = await keys(domain);
    guard();
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
  return decryptRecord(params, guard, async (domain) => {
    const key = await importRoot(secret, guard);
    return {
      profile: await profileId(key, guard),
      aesKey: await domainKey(key, domain, guard),
    };
  });
}

async function decryptRecord(
  params: IDecryptPrivateRecordParams,
  guard: Guard,
  keys: (domain: string) => Promise<RecordKey>
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
  const { profile, aesKey } = await keys(domain);
  guard();
  if (profile !== envelope.profileId) {
    throw new Error('Private record profile mismatch');
  }
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

type RecordAccessOwner = {
  active: boolean;
  domainSet: string;
  guard: Guard;
  keys: Map<string, CryptoKey>;
  profile: string;
  transferable: boolean;
  authority: object;
};
const recordAccessOwners = new WeakMap<
  IPrivateRecordAccess,
  RecordAccessOwner
>();

/** Canonical exact set, used only to retrieve a previously granted capability. */
export function privateRecordDomainSet(domains: readonly string[]): string {
  if (!Array.isArray(domains) || domains.length === 0 || domains.length > 8)
    throw new Error('Invalid record domains');
  const names: string[] = [];
  for (let i = 0; i < domains.length; i++) {
    const item = Object.getOwnPropertyDescriptor(domains, String(i));
    if (!item || !('value' in item)) throw new Error('Invalid record domains');
    names.push(label(item.value));
  }
  if (new Set(names).size !== names.length)
    throw new Error('Invalid record domains');
  return JSON.stringify(names.sort());
}
function checkRecordOwner(owner: RecordAccessOwner): void {
  if (!owner.active) throw new Error('Record access retired');
  const result: unknown = owner.guard();
  if (result !== undefined) {
    void Promise.resolve(result).catch(() => undefined);
    throw new Error('Record access requires a synchronous owner guard');
  }
  if (!owner.active) throw new Error('Record access retired');
}
function bindRecordAccess(owner: RecordAccessOwner): IPrivateRecordAccess {
  const check = () => checkRecordOwner(owner);
  const keyFor = async (domain: string): Promise<RecordKey> => {
    check();
    const aesKey = owner.keys.get(domain);
    if (!aesKey) throw new Error('Record domain not authorized');
    return { profile: owner.profile, aesKey };
  };
  const access: IPrivateRecordAccess = Object.freeze({
    async getPrivateRecordProfileId() {
      check();
      return owner.profile;
    },
    encryptPrivateRecord: (params: IEncryptPrivateRecordParams) =>
      encryptRecord(params, check, keyFor),
    decryptPrivateRecord: (params: IDecryptPrivateRecordParams) =>
      decryptRecord(params, check, keyFor),
    dispose() {
      owner.active = false;
      owner.keys.clear();
    },
  });
  recordAccessOwners.set(access, owner);
  return access;
}

/** Internal cache inspection; key material is never returned. */
export function activePrivateRecordDomainSet(
  access: IPrivateRecordAccess,
  authority: object
): string | null {
  const owner = recordAccessOwners.get(access);
  if (!owner?.active) return null;
  if (owner.authority !== authority)
    throw new Error('Record access owner mismatch');
  checkRecordOwner(owner);
  return owner.domainSet;
}

/** Internal transfer policy; callers cannot upgrade an existing grant. */
export function privateRecordAccessCanTransfer(
  access: IPrivateRecordAccess,
  authority: object
): boolean {
  const owner = recordAccessOwners.get(access);
  if (!owner?.active) return false;
  if (owner.authority !== authority)
    throw new Error('Record access owner mismatch');
  checkRecordOwner(owner);
  return owner.transferable;
}

/** Internal trusted SDK transfer. Old methods/dispose cannot affect the moved keys. */
export function transferPrivateRecordAccess(
  access: IPrivateRecordAccess,
  sourceAuthority: object,
  targetAuthority: object,
  guard: Guard
): IPrivateRecordAccess {
  const owner = recordAccessOwners.get(access);
  if (
    !owner ||
    owner.authority !== sourceAuthority ||
    !targetAuthority ||
    typeof targetAuthority !== 'object'
  )
    throw new Error('Record access owner mismatch');
  checkRecordOwner(owner);
  if (!owner.transferable) throw new Error('Record access cannot transfer');
  const keys = owner.keys;
  const next = bindRecordAccess({
    active: true,
    domainSet: owner.domainSet,
    guard,
    keys,
    profile: owner.profile,
    transferable: true,
    authority: targetAuthority,
  });
  owner.keys = new Map();
  owner.active = false;
  return next;
}

/** Derive only the named record keys, then release the root. No key export or derivation surface escapes. */
export async function createPrivateRecordAccess(
  secret: Uint8Array,
  domains: readonly string[],
  options: PrivateRecordAccessOptions,
  guard: Guard,
  authority: object
): Promise<IPrivateRecordAccess> {
  if (!authority || typeof authority !== 'object')
    throw new Error('Record access owner is required');
  const transfer =
    options &&
    typeof options === 'object' &&
    Reflect.ownKeys(options).length === 1
      ? Object.getOwnPropertyDescriptor(options, 'transferable')
      : undefined;
  if (
    !transfer ||
    !('value' in transfer) ||
    typeof transfer.value !== 'boolean'
  )
    throw new Error('Explicit record transfer policy is required');
  const domainSet = privateRecordDomainSet(domains);
  const names: string[] = JSON.parse(domainSet);
  const owner: RecordAccessOwner = {
    active: true,
    domainSet,
    guard,
    keys: new Map(),
    profile: '',
    transferable: transfer.value,
    authority,
  };
  const check = () => checkRecordOwner(owner);
  check();
  let root: CryptoKey | undefined;
  try {
    root = await importRoot(secret, check);
    owner.profile = await profileId(root, check);
    for (const domain of names) {
      owner.keys.set(domain, await domainKey(root, domain, check));
      check();
    }
    return bindRecordAccess(owner);
  } catch (error) {
    owner.active = false;
    owner.keys.clear();
    throw error;
  } finally {
    root = undefined;
  }
}

// This separate HKDF domain cannot decrypt the vault. Checkpoints contain only
// explicitly selected record-domain keys, never the mnemonic or vault key.
// No compatibility fallback to the previous password-wrapped checkpoint.
const PUBLIC_SESSION_DOMAIN = 'sysweb3.public-view.v1';
const CHECKPOINT_HEADER = new Uint8Array([0x50, 0x56, 0x43, 1]);
const CHECKPOINT_FIXED_BYTES = 4 + 32 + 32 + 32 + 1;
type PublicRecordCheckpointContext = Readonly<{
  walletBindingId: string;
  pairFingerprint: string;
  stateDigest: Uint8Array;
  domains: readonly string[];
}>;
const sameBytes = (left: Uint8Array, right: Uint8Array) => {
  let difference = left.length ^ right.length;
  for (let i = 0; i < left.length; i++) difference |= left[i] ^ (right[i] ?? 0);
  return difference === 0;
};
function checkpointContext(context: PublicRecordCheckpointContext) {
  if (
    !/^[0-9a-f]{64}$/.test(context.walletBindingId) ||
    !/^[0-9a-f]{64}$/.test(context.pairFingerprint) ||
    !(context.stateDigest instanceof Uint8Array) ||
    context.stateDigest.length !== 32
  )
    throw new Error('Invalid public record checkpoint context');
  return JSON.parse(privateRecordDomainSet(context.domains)) as string[];
}

/** Internal sealing only. No record key or extractable CryptoKey leaves this module. */
export async function sealPublicRecordCheckpoint(
  rootSecret: Uint8Array,
  wrappingSecret: Uint8Array,
  context: PublicRecordCheckpointContext,
  guard: Guard
): Promise<IEncryptedPrivateRecord> {
  const domains = checkpointContext(context);
  const payload = new Uint8Array(
    CHECKPOINT_FIXED_BYTES +
      domains.reduce((size, domain) => size + 1 + domain.length + 32, 0)
  );
  let derived: Uint8Array | undefined;
  try {
    const root = await importRoot(rootSecret, guard);
    payload.set(CHECKPOINT_HEADER);
    payload.set(Buffer.from(context.pairFingerprint, 'hex'), 4);
    payload.set(context.stateDigest, 36);
    payload.set(
      Buffer.from((await profileId(root, guard)).slice(2), 'hex'),
      68
    );
    payload[100] = domains.length;
    let offset = CHECKPOINT_FIXED_BYTES;
    for (const domain of domains) {
      const name = encoder.encode(domain);
      payload[offset++] = name.length;
      payload.set(name, offset);
      offset += name.length;
      // Same v1 HKDF inputs as domainKey, imported non-extractably on restore.
      derived = new Uint8Array(
        await cryptoProvider().subtle.deriveBits(
          domainParameters(domain),
          root,
          256
        )
      );
      guard();
      payload.set(derived, offset);
      offset += 32;
      derived.fill(0);
      derived = undefined;
    }
    return await encryptPrivateRecordBytes(
      wrappingSecret,
      {
        domain: PUBLIC_SESSION_DOMAIN,
        recordId: context.walletBindingId,
        plaintext: payload,
      },
      guard
    );
  } finally {
    derived?.fill(0);
    payload.fill(0);
  }
}

/** Internal restore imports only the sealed exact domain set as non-extractable keys. */
export async function restorePublicRecordCheckpoint(
  wrappingSecret: Uint8Array,
  envelope: IEncryptedPrivateRecord,
  context: PublicRecordCheckpointContext,
  guard: Guard,
  authority: object
): Promise<IPrivateRecordAccess> {
  const domains = checkpointContext(context);
  const owner: RecordAccessOwner = {
    active: true,
    domainSet: privateRecordDomainSet(domains),
    keys: new Map(),
    guard,
    profile: '',
    transferable: true,
    authority,
  };
  let payload: Uint8Array | undefined, material: Uint8Array | undefined;
  try {
    payload = await decryptPrivateRecordBytes(
      wrappingSecret,
      {
        domain: PUBLIC_SESSION_DOMAIN,
        recordId: context.walletBindingId,
        envelope,
      },
      guard
    );
    if (
      payload.length < CHECKPOINT_FIXED_BYTES ||
      !sameBytes(payload.subarray(0, 4), CHECKPOINT_HEADER) ||
      !sameBytes(
        payload.subarray(4, 36),
        new Uint8Array(Buffer.from(context.pairFingerprint, 'hex'))
      ) ||
      !sameBytes(payload.subarray(36, 68), context.stateDigest) ||
      payload[100] !== domains.length
    )
      throw new Error('Public session checkpoint context changed');
    owner.profile = `0x${Buffer.from(payload.subarray(68, 100)).toString(
      'hex'
    )}`;
    let offset = CHECKPOINT_FIXED_BYTES;
    for (const domain of domains) {
      const length = payload[offset++];
      if (
        length !== domain.length ||
        offset + length + 32 > payload.length ||
        !sameBytes(
          payload.subarray(offset, offset + length),
          encoder.encode(domain)
        )
      )
        throw new Error('Public session checkpoint domains changed');
      offset += length;
      material = new Uint8Array(payload.subarray(offset, offset + 32));
      offset += 32;
      const key = await cryptoProvider().subtle.importKey(
        'raw',
        bufferSource(material),
        { name: 'AES-GCM' },
        false,
        ['encrypt', 'decrypt']
      );
      material.fill(0);
      material = undefined;
      guard();
      owner.keys.set(domain, key);
    }
    if (offset !== payload.length)
      throw new Error('Invalid public session checkpoint');
    guard();
    return bindRecordAccess(owner);
  } catch (error) {
    owner.active = false;
    owner.keys.clear();
    throw error;
  } finally {
    payload?.fill(0);
    material?.fill(0);
  }
}
