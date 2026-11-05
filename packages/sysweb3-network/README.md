## Sysweb3-netowrk

Collection of helpful network functions for Syscoin multi-chain.

Here, you'll find methods that help you to develop your dapp network structure with efficiency and solidity.

## Setup

For use this library, is nice to have:

- [Node.js](https://nodejs.org) 10 or later installed
- [Yarn](https://yarnpkg.com) v1 or v2 installed

For install, you can follow these commands:

- `yarn add @sidhujag/sysweb3-network`
- `npm install @sidhujag/sysweb3-network`

## Usage

The sysweb3-network was builded to have a really simple usability. For example, you can import package and console it to know what kind of functions you'll find:

```js
import sysweb3 from '@sidhujag/sysweb3-network';

console.log(sysweb3);

{
  validateCurrentRpcUrl: function () {},
  getSysRpc: function () {},
  setActiveNetwork: function () {},
  ...
}
```

Inside of source folder, you'll find some files like:

- `rpc.ts`: includes `validateEvmRpcBatch` for EVM connections, `getSysRpc(draft, owner)` for verified UTXO registrations, and `observeSysRpc(draft, owner)` for explicit first use.
- `networks.ts`: this file have `IWeb3Network` interface and `networks` object. There, you'll be able to use these datas to add type in your functions and build an network initial state.
- `web3.ts`: this file have the method `setActiveNetwork`. There, you'll be able to change the current network of your dapp.

These methods are just some of the ones available in our library.

Feel free to explore the possibilities. We hope you enjoy it.

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

For a new custom HTTPS endpoint, `observeFirstUseUtxoRpc` uses the same
transport and owner guard. It accepts an optional exact SDK coin selection and
returns the matched registration, canonical currency, and
`observedBackendChain`. The backend token comes from the selected endpoint.
The caller owns approval and any pin, and must recheck that pin before using it
as an expected identity on later connections.

## License

MIT License
