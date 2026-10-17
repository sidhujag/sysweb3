# sysweb3-sentry

Strict transaction review and local operator signing for Syscoin Sentry nodes.
The package implements service/NEVM updates for active BLS payload v3
and the PQ payload v4 in Core PR #609, plus external-collateral registration,
owner/registrar updates, revocation and PQ global-operator enrollment/rotation.
It is not an Ethereum signer, a smart-account
SLH signer, a node-hosting client, or an arbitrary-hash signing interface.

See [INTERFACE.md](./INTERFACE.md) for the frozen public envelope. Secrets are
accepted only by local key-import/signing functions, never by request validation.
The wallet must fetch the registered node, funding transactions, genesis and
activation state through its own configured RPC. It must not trust a dapp's
replacement RPC, registered key record, fee claim or human-readable review text.

## Flow

1. The dapp builds an unsigned funded `updateService` request. All payload changes
   are represented by transaction bytes. Omitted builder fields preserve current
   state; an empty NEVM address explicitly unregisters it.
2. The wallet runs `reviewSentryOperation` against independently fetched context,
   displays changed fields and **all** fee outputs, and selects its local operator
   key. Registered collateral must be excluded from funding and supplied to the
   context guard.
3. After user approval, the wallet calls `signSentryOperation`. It refuses signed
   fee inputs and existing operator signatures; it changes only the reserved
   operator-signature bytes. It returns no secrets.
4. The separate fee payer signs the resulting transaction inputs. That signature
   must come last because the operator signature lives in an OP_RETURN output.
5. The relay verifies the operator signature again, checks the current chain/key
   state and broadcasts the exact fully authorized bytes. After confirmation it
   rereads the node's registered NEVM address.

`verifySentryOperation` and `reviewSentryOperation` accept the final fee-signed
transaction. They authenticate funding contents by matching exact previous
transaction hashes, but cannot decide whether an input is currently spent or
whether a node is banned/unconfirmed. Those are fresh RPC/mempool checks.

## Protocol boundaries

* Current non-PQ Core: `dd1457d89a5906288d0c0813a157413e79f75f6d`.
* PQ candidate: `fa24600369c7afbe338afc09d07c840d21c2e205` (PR #609).
* The current BLS v3 digest is Core's SHA256d payload serialization with the
  signature omitted. Inputs hash is SHA256d of **ordered serialized prevouts**.
  BLS uses BasicSchemeMPL's exact `..._NUL_` DST, not POP/AUG or historical v1.
* PQ service signing uses the exact raw `SYS_PQ_PROVIDER_SERVICE_V1` transcript,
  full registered `GlobalKeyRecord` hash, chain genesis and fixed network endpoint.
  The same domain is the FIPS-205 context. Its scheme is **SHAKE-128s**, not the
  Pali smart-account SHA2 scheme.
* Both eras encode the provider payload as a zero-value canonical OP_RETURN
  output on transaction version 81; there is no Dash-style appended extraPayload.
* Current Core policy requires IPv4 service addresses. The internal endpoint
  codec understands IPv6/CJDNS for transcript portability, but service requests
  using those families are rejected until Core policy supports them.
  Core's reset current-state value `0.0.0.0:0` is recognized after operator
  rotation; restoring service requires an explicit valid replacement endpoint.
  The reset value is never accepted as a proposed service address.
* Genesis is cryptographically in the PQ transcript. BLS consensus has no genesis
  field; wallet network binding does not retroactively alter that legacy digest.
* PQ is a pinned candidate adapter, not evidence that an unactivated chain accepts
  PQ transactions. A wallet must resolve era from activation and not a user toggle.

The ESM package uses pinned noble cryptography modules. BLS and SLH code load only
inside asynchronous signing/import operations. SLH import recomputes its public
root just like Core; it can be CPU-intensive, so wallets should invoke it in an
isolated worker without blocking the approval UI.

## Build and tests

`npm ci && npm test` inside this package. Tests use synthetic funding fixtures and
public test keys; no live wallet, RPC, secret or broadcast is involved.

## Other management operations

`getSentryManagementCapabilities` advertises separate management APIs. The
builders `buildSentryRegistration`, `buildSentryRegistrarUpdate`,
`buildSentryRevocation` and `buildSentryOperatorUpdate` return strict public
requests consumed by `reviewSentryManagementOperation` and
`signSentryManagementOperation`. These are not operator-service signatures:

* Existing collateral registration requires the collateral's secp256k1 key and,
  for PQ registration, a separate new-owner proof.
* Registrar changes use the currently enrolled owner: legacy ECDSA or PQ
  SHAKE-128s. Owner replacement additionally requires the new owner's proof.
  An enrolled PQ owner cannot fall back to ECDSA.
* Revocation uses the currently registered operator, BLS or PQ as appropriate.
* Initial PQ operator enrollment/recovery requires owner authorization plus
  proof by the new operator key. Active rotation uses the current operator.
  All version, generation, chain and child-commitment bindings follow Core.

`SentryAuthorityKey` retains explicit owner/operator/collateral/voting roles.
The new operator's 80-byte child-tree commitment must come from the operator's
key-setup process: this package does not generate or manage the WOTS tree and
must not pretend a random commitment is usable. The transaction approves its
exact public commitment; node setup must retain the corresponding secrets.
External collateral is supported; creating and spending a new collateral
output is intentionally a distinct normal wallet transaction.

Pre-activation owner/operator enrollment is accepted only when the wallet's
independently resolved Core context enables the corresponding preparation
capability. A dapp cannot activate this policy with a request flag. Pure voting
messages, governance actions and private node operation are separate protocols.
