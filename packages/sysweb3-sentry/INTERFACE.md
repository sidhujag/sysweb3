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
  deterministic keys from exactly 32 BLS seed bytes or 48 SLH seed bytes, not
  SA SHA2 keys. BLS matches Core `BasicSchemeMPL::KeyGen` using its exact
  HKDF-SHA256 salt, IKM suffix, expansion and scalar-field reduction; it does
  not treat the seed as a private scalar or use Noble's 48-byte entropy API.
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

The service API supports current legacy update-service payload v3 and PQ PR
#609 payload v4. Historical service payloads v1/v2 fail closed. Other management
operations use the separate role-aware API below, never a service signature.

## Role-aware management API

Separate `SentryManagementRequest` keeps the public envelope shape above but
supports `register`, `updateRegistrar`, `revoke`, `registerOperator` and
`rotateOperator`. Exact exported TypeScript contracts are in
`src/management-types.ts`; these are additive and do not change the service API.

* Builders: `buildSentryRegistration`, `buildSentryRegistrarUpdate`,
  `buildSentryRevocation`, `buildSentryOperatorUpdate`.
* Discovery/validation: `validateSentryManagementRequest`,
  `inspectSentryManagementOperation` (syntactic only),
  `getSentryManagementCapabilities`.
* Review/verification: `reviewSentryManagementOperation`,
  `verifySentryManagementOperation`, `matchesSentryManagementIntent`.
* Local-only keys: `importSentryAuthorityKey(role, scheme, secretKeyHex)`;
  `role` is owner/operator/collateral/voting, `scheme` adds secp256k1.
* Local signing: `signSentryManagementOperation(request, context, key,
  authorizationId?)`. It fills exactly one required authorization slot. Its
  response has `complete: false` until all role-specific signatures verify.
  The fee-payer signs inputs only after `complete: true`.

Review returns all public fields and an `authorizations` list with ID, role,
scheme, key identity, digest, FIPS context and whether signature bytes are
present. `signed` is a presence marker, not a substitute for verification.
Wallet UI chooses local keys by role and must not offer an operator key as an
owner/collateral key. Never forward the key object into a dapp message.

The context additionally supplies trusted network address prefixes for the
Core collateral signing message, a complete node owner/voting state, or the
exact external collateral transaction and chain's required collateral value.
Only trusted Core preparation capabilities may set `allowOwnerPreparation` or
`allowOperatorPreparation`; these are not public request fields.

PQ operator `candidate` includes the exact canonical child-tree commitment and
must have activation height zero. The node's separate setup process generates
the corresponding WOTS tree; this transaction codec does not invent one.

## Legacy governance funding votes

`SentryGovernanceVoteRequest` is a separate typed protocol, not a transaction or
an arbitrary hash-signing method. Its exact fields are:

```ts
{
  version: 1,
  chain: { genesisHash, era: 'legacy-v3' },
  proposalHash,
  signal: 'funding',
  outcome: 'yes' | 'no' | 'abstain',
  timestamp, // safe integer Unix seconds
  nodes: [{ proTxHash, collateralOutpoint: { txid, vout } }] // 1–20 unique nodes
}
```

Hashes are nonzero lowercase 32-byte hex. The collateral index is a nonnegative
signed-32-bit integer, matching `voteraw`'s RPC parser. Unknown fields, duplicate
node IDs/outpoints and unsupported schemes/eras/signals fail closed.

`reviewSentryGovernanceVote(request, context)` requires independently resolved
`chain`, `now`, `proposalHash` and exactly matching `nodes`, each with the current
`votingKeyId` and `valid: true`. Optional `proposal: {name, url?}` is display
metadata only. New wallet approvals require the timestamp within one hour of
`now` in either direction. This is stricter than Core, which only checks the
future bound.

`signSentryGovernanceVote(request, context, proTxHash, key)` returns one
`SentryGovernanceVoteResponse`: `{proTxHash, collateralOutpoint, voteSig,
signatureHash, voteHash}`. The local key must have role `voting`, scheme
`secp256k1` and match the verified registration. `voteSig` is canonical base64 of
the 65-byte recoverable signature. `signatureHash` and `voteHash` use Core's
display byte order; `governanceVoteDigest(fields)` returns raw signing-digest
hex. `governanceVoteHash(fields)` returns the display-order identity hash.
`verifySentryGovernanceVote(request, context, response)` checks the same binding
and rejects high-S/noncanonical signatures.

`await governanceVotingKeyIds(compressedPublicKey)` returns `{compressed,
uncompressed}` Hash160 identities for legacy voting registration discovery.
The stored key's public representation remains compressed. Signing chooses the
Core compact header for the actual registered encoding (27–30 uncompressed,
31–34 compressed); this does not alter transaction-management key semantics.

Core's signature hashes the serialized collateral outpoint, proposal hash,
outcome, signal and timestamp. **It does not include network/genesis or
proTxHash.** Wallets must independently enforce the trusted envelope and verify
fresh registration context; the signature itself cannot provide those bindings.
`GetHash` orders signal before outcome, unlike `GetSignatureHash`. Native Core
golden vectors cover both orders, all three outcomes and both key encodings.
They exercise signature verification, not live governance-object acceptance.
