# Changelog

## 1.0.614

### EVM Speed Up signing

- Authenticate the original signed transaction against its requested hash, selected gas payer and configured chain before credential or device access. Support signed types 0, 1 and 2; reject unsupported envelopes and unprotected legacy originals.
- Derive type-0/type-2 fee mode from the signed envelope. Preserve type-1 access lists; `isLegacy: true` retains type 1 for software/Ledger, while false converts it to type 2 using its signed gas price as the fee baseline. Trezor type-1 preservation is rejected before prompting; conversion to type 2 remains supported.
- Preview the maximum execution gas fee without signing or broadcasting. Sending requires an explicit approved ceiling. Final construction cannot exceed it, including when a zero-fee original needs a fresh RPC estimate.
- Select a local outer gas payer with `targetAccount` for smart-account replacements without changing the active account. Capture the provider and signed body across asynchronous work; check returned hardware signatures against the selected payer.
- Add an optional local-signing context check immediately before signing. Existing `beforeBroadcast` arguments keep their position and behavior.

### Required caller migration

The old two-argument `sendTransactionWithEditedFee(hash, isLegacy)` send now throws `Replacement fee approval required`. Hosts must preview, show the maximum fee to the user, obtain approval, then send with that exact ceiling in decimal wei:

```ts
const preview = await keyring.ethereumTransaction.sendTransactionWithEditedFee(
  originalHash,
  isLegacy,
  { previewOnly: true, assertCurrentContext }
);
if (preview.error || preview.maximumFee === undefined) {
  throw new Error('Replacement preview unavailable');
}

// Host UI displays this execution gas fee in the network's native currency.
// Approval is valid only for this original transaction and captured context.
if (await requestUserApproval(preview.maximumFee)) {
  await keyring.ethereumTransaction.sendTransactionWithEditedFee(
    originalHash,
    isLegacy,
    {
      approvedMaximumFee: preview.maximumFee,
      assertCurrentContext,
    }
  );
}
```

`assertCurrentContext` is supplied by the host and must throw when the account, network, provider or unlock session changes, or the original is mined or superseded. Invalidate the quote when the approval UI closes. For smart accounts, pass the same outer payer `{ type, id }` as `targetAccount` to both calls, plus the host's `validateOriginal` and `beforeBroadcast` guards. Authentication and fee limits apply without these optional callbacks; session and UI lifecycle checks rely on the host supplying them. Do not persist signing payloads or approvals.

The ceiling is `gasLimit × gasPrice` for type 0/1, or `gasLimit × maxFeePerGas` for type 2. It covers execution gas, not separate chain-specific fee components. Existing max-send value adjustment and contract-call rejection are retained. This change applies to Speed Up; `cancelSentTransaction` and ordinary sends retain their existing contracts.

Ledger/Trezor dependencies, transports, initialization and signing wrapper APIs are unchanged. Automated tests use real signature reconstruction and protocol serialization with mocked device I/O. Physical device signing, firmware compatibility and live broadcasts remain unverified by this release candidate.
