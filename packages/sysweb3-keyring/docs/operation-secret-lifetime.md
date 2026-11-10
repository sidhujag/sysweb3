# Operation-scoped software secrets

`KeyringOptions.secretLifetime` selects the lifetime explicitly:

- `session` preserves the existing extension behavior. A successful unlock keeps the session key available until `lockWallet()` or destruction. This remains the compatibility default.
- `operation` is intended for native hosts requiring fresh authorization for each sensitive action. Native composition must select it explicitly and must not fall back to `session` if the API is unavailable.

Both policies use the same vault encryption, KDF, account derivation, signing, and private-record implementations. There is no alternate wallet or signing engine.

## Public context and secret availability

In operation policy, `initializeWalletSecurely()` and `unlock()` establish authenticated public account context and clear their owned secret buffers before returning. `hasPublicSession()` and `capturePublicSessionGuard()` describe that public context. `isUnlocked()` continues to mean that a usable software secret is currently available; it is false between operations. A host must distinguish public preparation from secret work rather than replace all guards indiscriminately.

Public account records remain owned by the existing bound state getter. Providers, encrypted account fields, and read-only UTXO builders are retained. Owned UTXO reads bind the public session, account, and network. They do not obtain a software signer. Actual signing and secret export remain bound to the separate secret lifetime.

`prepareSessionTransfer()` moves public authority only between operation-policy keyrings when no secret operation is pending. It retains the existing same-host/store checks and one-use transfer. It does not transfer software secrets across the action boundary. Cross-policy transfers are refused.

## Public PSBT preparation

Operation-policy hosts call `syscoinTransaction.preparePSBTForSigning({ psbt }, ownedRead)` before requesting the signing secret. This uses the existing Blockbook path enrichment and validates the selected account against the spent scripts. It returns the same unsigned transaction and assets with public derivation metadata added or normalized, preserving cosigner metadata. The owned read keeps the selected account, network, endpoint, and cancellation guard bound throughout preparation.

In operation policy, public preparation refuses to start while secrets are loaded. `signPSBT()` never fetches missing paths in that policy: unresolved inputs fail before a software signer is obtained. The host still serializes preparation and authorization, and signing repeats the existing account-scope and unsigned-transaction checks. Session policy retains its existing implicit path enrichment during signing.

## One sensitive action

```ts
const result = await keyring.withSecretOperation(
  {
    async withSecret(assertCurrent, consume) {
      // The native host first obtains fresh PIN or device authorization.
      // Its existing protected credential provider supplies the SDK secret.
      await protectedCredential.withSecret(assertCurrent, consume);
    },
  },
  { signal: action.signal, assertCurrent: action.assertCurrent },
  async (secret) => keyring.getSeed(secret)
);
```

The credential provider must call `consume` exactly once. The SDK authenticates that credential using its existing unlock implementation before entering `work`. A missing, duplicate, stale, or concurrent admission is refused. The host must keep the keyring and credential provider private; the callback is a trusted native boundary, not a dapp API.

The action's abort signal clears owned buffers synchronously. Completion and failure also clear them before the work result is released, even if the credential provider remains pending after the work finishes. A late callback cannot revive a cancelled action or clear a successor keyring's state. A full wallet lock additionally retires public context and the existing hardware lifetimes.

The operation can start from a locked keyring. It authenticates and then runs the host's existing secret-dependent hydration before retaining public authority. An initial hydration failure retires that newly created public authority. No separate `unlock()` or second credential prompt is necessary; the host must not return a secret lease to UI. Later `getPrivateRecordProfileId`, private-record decryption, account derivation, secret export, and signing require a fresh operation. Public fee/nonce preparation cannot silently decrypt records; hosts may use previously verified public projections and must perform secret-dependent revalidation inside the authorized action.

## Limits

Clearing overwrites the SDK-owned `SecureBuffer` instances and removes their references. JavaScript strings and third-party cryptographic temporaries are garbage-collected; this is not a guarantee of physical heap erasure. A deliberately exported phrase/key remains the responsibility of its protected presentation until hidden. Signed bytes, encrypted records, and public account metadata are not decrypted wallet-key retention. The API does not add a new PIN, biometric enrollment, nonce planner, or broadcast policy.


## Restricted record access

`createPrivateRecordAccess(domains, { transferable })` requires a live secret operation in operation mode. The transfer choice is required and must be a Boolean. The SDK derives only the named domain AES-GCM keys and the public profile identifier using the existing v1 derivation; the root bytes are cleared before returning. The facade cannot export keys, derive other domains, unlock a wallet, or sign.

`getPrivateRecordAccess(domains)` is a synchronous lookup for exactly the same transferable domain set already created in this public session. Nontransferable private-action grants can only be used through the returned facade; this getter never returns them. It does not read the mnemonic or stored vault. Subsets, supersets, and uninitialized sets are rejected. Hosts should grant transferable access only to their public signed-transaction journal domains; private-note actions use `transferable: false` and dispose their grant when the action ends.

Trusted same-authority public-session transfer moves existing transferable domain keys to a new facade guarded by the target owner. Old facades and in-flight operations are retired, and disposing or destroying the source cannot affect the moved keys. Nontransferable grants are retired rather than moved. Lock and public-session replacement drop all cached grants. The internal move requires an unforgeable SDK owner token, so importing a raw helper cannot detach an application grant from lock revocation.

WebCrypto keys are nonextractable. Disposing a grant drops SDK references to its opaque keys; the engine controls underlying key-memory reclamation. This is not a claim of immediate JavaScript-engine or hardware memory erasure.
