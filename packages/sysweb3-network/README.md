# Sysweb3 Network

Network registration and RPC validation for EVM and UTXO wallets.

## Installation

```bash
npm install @sidhujag/sysweb3-network
# or
yarn add @sidhujag/sysweb3-network
```

## Usage

Use `validateEvmRpcBatch` for EVM endpoints. For UTXO registrations,
`getSysRpc(draft, owner)` verifies an expected identity and
`observeSysRpc(draft, owner)` observes a first-use endpoint.

### Owned UTXO endpoint verification

Import the verifier directly when you already have a trusted registration and
only need UTXO endpoint identity checks.

```ts
import {
  verifyOwnedUtxoRpc,
  type OwnedUtxoRpcVerification,
} from '@sidhujag/sysweb3-network/cjs/ownedUtxoRpc.js';
```

CommonJS also supports the subpath without the `.js` suffix. Provide the
expected `chainId`, `slip44` and `backendChain` from a trusted profile before
contacting the endpoint. The caller supplies a bounded, redirect-rejecting
`readJson` transport, an abort signal and a synchronous currentness guard.
Use the root `getSysRpc` API with the same owner when you also need the formatted
network registration.

### RPC read response limits

`JsonRpcReadClient.readMany` shares one response budget across batches, splits,
scalar fallbacks and retries: 16 MiB of consumed UTF-8 response bytes, 1,048,576
JSON values/keys and 64 container levels by default. `maxTotalResponseBytes`,
`maxTotalResponseNodes` and `maxResponseDepth` configure those operation limits.
`RpcResponseBudgetError` ends the operation without destroying the client;
per-response `RpcResponseSizeError` can still trigger bounded batch splitting.

For a new custom endpoint, `observeFirstUseUtxoRpc` uses the same transport
and owner guard. It requires HTTPS, with HTTP permitted for `127.0.0.1`
and `[::1]` in local development. It accepts an optional exact SDK coin selection and
returns the matched registration, canonical currency, and
`observedBackendChain`. The backend token comes from the selected endpoint.
The caller owns approval and any pin, and must recheck that pin before using it
as an expected identity on later connections.

## License

MIT License
