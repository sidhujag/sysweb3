# Sentry transaction SDK interface (v1)

Package: `@sidhujag/sysweb3-sentry`. Operator secrets remain local to Pali and
never appear in a dapp request/response. There is no arbitrary-hash signing API.

```ts
type SentryScheme = 'bls-basic' | 'slh-dsa-shake-128s';
type SentryEra = 'legacy-v3' | 'pq-v4';
interface SentryChain {
  genesisHash: string; // 32-byte display-order hex, trusted configured chain
  era: SentryEra;      // resolved by wallet from activation state, NOT the dapp
}
interface SentryNodeState {
  proTxHash: string; // 32-byte display-order hex
  operatorPublicKey: string; // 48-byte BLS or 32-byte SLH public key hex
  service: string; // IPv4:port or [IPv6]:port
  operatorPayoutScript: string; // exact script hex, empty means unset
  nevmAddress: string; // 0x + 20 bytes, or '' (explicitly unregistered)
  globalKeyVersion?: number; // required positive uint32 for pq-v4
  pqRecord?: SentryPQRecord; // REQUIRED full trusted Core record for pq-v4
  collateralOutpoint?: {txid: string; vout: number}; // wallet requires/protects it
}
interface SentryPQRecord {
  version: number; // currently 1
  profile: number; // currently 1 (SLH-DSA-SHAKE-128s)
  keyVersion: number;
  publicKey: string;
  childKeyCommitmentHex: string; // exact canonical 80-byte Core commitment
  activatedHeight: number;
}
interface SentryOperationRequest {
  version: 1;
  operation: 'updateService';
  chain: SentryChain;
  transactionHex: string; // complete funded raw tx, empty input scripts/witness
}
interface SentryReviewContext {
  chain: SentryChain; // wallet's independent chain/era observation
  node: SentryNodeState; // wallet's independent registered node observation
  previousTransactions: string[]; // exact raw funding prevtxs, fetched or hash checked
  maxFeeSatoshis: string; // wallet/user fee safety bound, decimal integer
}
interface SentryOperationReview {
  operation: 'updateService';
  scheme: SentryScheme;
  chain: SentryChain;
  proTxHash: string;
  changes: {
    service: { previous: string; next: string };
    operatorPayoutScript: { previous: string; next: string };
    nevmAddress: { previous: string; next: string };
  };
  feeSatoshis: string;
  inputCount: number;
  outputs: { valueSatoshis: string; scriptHex: string; isPayload: boolean }[];
  authorizationHash: string; // digest bytes hex, NOT reversed display hash
}
interface SentryOperationResponse {
  version: 1;
  operation: 'updateService';
  transactionHex: string; // operator-authorized; fee-input signer still signs afterwards
  operatorPublicKey: string;
  authorizationHash: string;
}
```

Exports (synchronous codec/review, asynchronous crypto to allow lazy loading):

* `getSentryCapabilities()` returns supported operations/eras/key schemes.
* `validateSentryOperationRequest(unknown): SentryOperationRequest` strictly validates
  the public envelope and rejects extra fields (especially secret-key fields).
* `reviewSentryOperation(request, context): SentryOperationReview` independently
  decodes actual transaction bytes, validates OP_RETURN payload and ordered
  input hash, binds configured genesis/era/registered operator, verifies funding
  txids/output amounts, enforces fee bound. UI should show changes plus fee payer
  and all non-payload outputs. Empty next NEVM address explicitly means removal.
  It accepts already fee-signed transactions for final backend verification;
  `signSentryOperation` rejects signed inputs so authorization order is enforced.
* `inspectSentryOperation(request)` returns syntactic `{proTxHash,inputTxids,
  globalKeyVersion?}` only for choosing wallet-owned chain queries. It is not a
  trusted review or authorization result.
* `matchesSentryTransactionIntent(prepared, signed)` checks all original bytes
  except the inserted operator signature and fee-input script/witness. Relays
  MUST use this (or an equivalent comparison) in addition to signature checks:
  Core's operator authorization intentionally does not commit fee outputs.
* `importSentryOperatorKey(scheme, secretKeyHex): Promise<SentryImportedKey>`
  returns `{scheme, publicKey, secretKey}`; secret is a normalized hex string for
  LOCAL encrypted storage only. BLS key is 32 bytes; SLH key is the exact 64-byte
  Core key (or 48-byte generation seed via separate `deriveSentryOperatorKey`).
* `deriveSentryOperatorKey(scheme, seedHex): Promise<SentryImportedKey>` generates
  deterministic keys using vetted scheme keygen, not SA SHA2 keys.
* `signSentryOperation(request, context, importedKey): Promise<SentryOperationResponse>`
  repeats review, verifies key matches registration, locally signs the decoded
  protocol authorization and inserts the signature without changing other bytes.
* `verifySentryOperation(request, context): Promise<boolean>` verifies the on-chain
  operator authorization in an already-authorized transaction.
* `buildSentryServiceUpdate({chain,node,service?,operatorPayoutScript?,nevmAddress?,inputs,outputs,lockTime?})`
  constructs a deterministic unsigned funded transaction. Omitted fields preserve
  independently observed state; `nevmAddress: ''` is explicit unregister.
  Inputs are `{txid,vout,sequence?}`; outputs `{valueSatoshis,scriptHex}` exclude
  the payload, which is appended with zero value. Funding is caller's responsibility.
* `decodeSentryTransaction(rawHex)` returns exact inputs, outputs, lockTime,
  txid, weight and virtualSize for public fee-signing integration.
* `estimateSentrySignedVBytes(request)` returns conservative P2PKH/P2WPKH
  funding size. Allzero operator signature placeholders already occupy the
  exact final 96/7856 bytes. Arbitrary multisig needs its own estimator.

The package uses ESM for the current noble libraries. Import it statically in a
bundler/ESM app or with `await import('@sidhujag/sysweb3-sentry')` in CommonJS.

The public methods recommended for Pali are `sys_getSentryCapabilities` and
`sys_signSentryOperation`; the latter accepts only the public request above.
The wallet obtains `context` independently, then obtains local key material from
its vault. A provider may be the fee payer; do not represent the returned operator
authorization as a fully UTXO-signed/broadcastable transaction.

Initial supported vertical slice is current legacy update-service payload v3 and
PQ PR #609 payload v4. Historical v1/v2 and not-yet-implemented owner/collateral
operations fail closed and are absent from capabilities. They are not silently
treated as updateService or signed with an operator key.
