## Sysweb3-core

Collection of helpful browser functions for Syscoin multi-chain.

Here, you'll find methods that help you to interact with any HTTP client easily.

## Setup

For use this library, is nice to have:

- [Node.js](https://nodejs.org) 10 or later installed
- [Yarn](https://yarnpkg.com) v1 or v2 installed

For install, you can follow these commands:

- `yarn add @sidhujag/sysweb3-core`
- `npm install @sidhujag/sysweb3-core`

## Usage

The sysweb3-core was builded to have a really simple usability. For example, you can import package and console it to know what kind of functions you'll find:

```js
import sysweb3 from '@sidhujag/sysweb3-core';

console.log(sysweb3);

{
  useLocalStorageClientl: function () {},
  getStateStorageDb: function () {},
  ...
}
```

Inside of source folder, you'll find one of the main files: `sysweb3-di.ts`

- There, you'll be able to use all methods to set, get and delete storage (session or local) in your browser. All functions inside this file was build for give an easier experience with browser interaction.

These methods are just some of the ones available in our library.

Feel free to explore the possibilities. We hope you enjoy it.

## Conditional creation

`createManyIfAbsent(items)` creates a set of prefixed records only when all of
them are absent, returning `true` for the creator and `false` when a record
already exists. Write failures reject its promise.

- The built-in memory client checks and commits synchronously.
- Native `chrome.storage.local` or `browser.storage.local` clients require
  `navigator.locks`. A lock named for the captured storage prefix covers the
  complete read, absence check, and awaited batch write. This coordinates
  contexts in the same extension origin and storage partition.
- Custom clients must implement `createItemsIfAbsent(items)`, accepting the
  prefixed, JSON-serialized values and returning `boolean | Promise<boolean>`.
  That method must enforce the absence check and commit atomically in the
  backend. A separate read followed by an ordinary write does not satisfy it.

There is no unlocked or sequential fallback. Backends shared across different
origins or storage partitions need their own atomic implementation or a single
owner. Existing `get`, `set`, `setMany`, and delete behavior is unchanged.

## License

MIT License
