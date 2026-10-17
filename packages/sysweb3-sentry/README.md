# sysweb3-sentry

Strict transaction review and local operator signing for Syscoin Sentry nodes.
The package currently implements service/NEVM updates for active BLS payload v3
and the PQ payload v4 in Core PR #609. It is not an Ethereum signer, a smart-account
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

Only `updateService` is advertised today. Registration/collateral ownership,
owner updates, voting, key migration/rotation and revocation require their
separate role-specific protocol adapters; they must not be approximated using
an operator service signature.
