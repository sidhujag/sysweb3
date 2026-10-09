# Sysweb3-keyring

A stateless, multi-chain keyring manager for Syscoin and Ethereum-based networks.

## Overview

The sysweb3-keyring provides a unified interface for managing accounts, transactions, and hardware wallets across Syscoin (UTXO) and Ethereum (EVM) networks. The KeyringManager operates statelessly, relying on external state providers (like Redux) for account and network data.

## Key Features

- **Stateless Architecture**: No internal state storage - integrates with external state management
- **Multi-Chain Support**: Handles both UTXO (Syscoin) and EVM (Ethereum) networks
- **Hardware Wallet Support**: Trezor and Ledger integration
- **Secure Session Management**: Encrypted private key handling with session transfer
- **Transaction Management**: Full transaction lifecycle support for both network types

## Vault encryption compatibility

New vaults require WebCrypto and use PBKDF2-HMAC-SHA-512 (900,000 production
iterations) with AES-256-GCM. Missing WebCrypto rejects the operation without
writing a weaker fallback vault. Restore WebCrypto availability before retrying
an unmarked legacy vault.

Historical fallback vaults used a 20,000-iteration key that also encrypted their
persisted account keys. After authenticating such a CBC vault, the keyring records
the explicit `pbkdf2-sha512-20000` compatibility profile and rewraps the vault with
AES-GCM. This preserves existing account access across restart; it is **not** a
full rekey of those account records to 900,000 iterations. The profile is written
before rewrapping, so interruption of either write remains recoverable. Arbitrary
KDF profiles or parameters are rejected.

Storage clients must return their asynchronous write/delete promises. The core
adapter preserves them so rejected writes do not silently advance vault migration.
Fresh wallet creation additionally requires conditional batch creation. Native
`chrome.storage.local` and `browser.storage.local` use a prefix-scoped Web Lock
around the absence check and awaited write, coordinating contexts in the same
extension origin and storage partition. Custom clients must provide an atomic
`createItemsIfAbsent(items)` backend operation over prefixed, JSON-serialized
values; the built-in memory client provides this operation synchronously.
There is no sequential or unlocked fallback. A backend shared across storage
partitions needs its own atomic implementation or a single owner.

### Release order for 1.0.613

Publish `@sidhujag/sysweb3-core@1.0.29` before `@sidhujag/sysweb3-keyring@1.0.613`.
The updated lock entry describes that intended dependency; its integrity is
intentionally absent until publication. Regenerate and verify the lockfile from
the published registry artifacts before a clean registry installation. Local
validation uses the built package tarballs and does not establish publication.

## Installation

```bash
npm install @sidhujag/sysweb3-keyring
# or
yarn add @sidhujag/sysweb3-keyring
```

## Usage

### Basic Setup

```javascript
import { KeyringManager } from '@sidhujag/sysweb3-keyring';

// Create a vault state getter function (e.g., from Redux store)
const vaultStateGetter = () => store.getState().vault;

// Initialize the keyring manager
const keyringManager = await KeyringManager.createInitialized(
  seedPhrase,
  password,
  vaultStateGetter
);
```

### Account Management

```javascript
// Get active account
const activeAccount = keyringManager.getActiveAccount();

// Create new account
const newAccount = await keyringManager.addNewAccount('My Account');

// Switch active account
await keyringManager.setActiveAccount(accountId, KeyringAccountType.HDAccount);

// Import account from private key
const importedAccount = await keyringManager.importAccount(
  privateKey,
  'Imported Account'
);
```

### Network Management

```javascript
// Set network (automatically switches between UTXO/EVM signers)
await keyringManager.setSignerNetwork(networkConfig);

// Get current network
const network = keyringManager.getNetwork();
```

### Transaction Operations

#### Syscoin (UTXO) Transactions

```javascript
// Estimate transaction fee
const feeEstimate =
  await keyringManager.syscoinTransaction.getEstimateSysTransactionFee({
    txOptions: {},
    amount: 1.0,
    receivingAddress: 'sys1q...',
    feeRate: 0.00001,
    token: null,
  });

// Sign PSBT
const signedPsbt = await keyringManager.syscoinTransaction.signPSBT({
  psbt: psbtData,
  isTrezor: false,
  isLedger: false,
});

// Get addresses
const receivingAddress = await keyringManager.updateReceivingAddress();
const changeAddress = await keyringManager.getNewChangeAddress();
```

#### Ethereum (EVM) Transactions

```javascript
// Send transaction
const txHash = await keyringManager.ethereumTransaction.sendTransaction({
  to: '0x...',
  value: '1000000000000000000', // 1 ETH in wei
  gasLimit: '21000',
  gasPrice: '20000000000', // 20 gwei
});

// Sign message
const signature = await keyringManager.ethereumTransaction.signPersonalMessage([
  '0x48656c6c6f', // "Hello" in hex
  accountAddress,
]);
```

### Hardware Wallet Support

```javascript
// Import Trezor account
const trezorAccount = await keyringManager.importTrezorAccount(
  'Trezor Account'
);

// Import Ledger account
const ledgerAccount = await keyringManager.importLedgerAccount(
  false,
  'Ledger Account'
);
```

### State Management Integration

The KeyringManager requires a `vaultStateGetter` function that returns the current vault state:

```javascript
// Example with Redux
const vaultStateGetter = () => ({
  accounts: {
    [KeyringAccountType.HDAccount]: {
      /* account data */
    },
    [KeyringAccountType.Imported]: {
      /* imported accounts */
    },
  },
  activeAccount: { id: 0, type: KeyringAccountType.HDAccount },
  activeNetwork: {
    /* network config */
  },
  // ... other vault state
});

// The keyring manager will call this function to get current state
const keyringManager = new KeyringManager();
keyringManager.setVaultStateGetter(vaultStateGetter);
```

## Architecture

The stateless design means:

- **No Internal State**: The KeyringManager doesn't store account or network data
- **External State Provider**: Relies on your application's state management (Redux, Context, etc.)
- **Session Management**: Private keys are encrypted and managed securely in memory
- **Multi-Instance Support**: Multiple KeyringManager instances can operate independently

## API Reference

### KeyringManager

Main class for keyring operations:

- `createInitialized(seedPhrase, password, vaultStateGetter)` - Create and initialize keyring
- `addNewAccount(label?)` - Create new HD account
- `setActiveAccount(id, type)` - Switch active account
- `importAccount(privateKey, label?)` - Import account from private key
- `setSignerNetwork(network)` - Set active network
- `unlock(password)` - Unlock keyring
- `lockWallet()` - Lock keyring

### Transaction Managers

- `syscoinTransaction` - UTXO transaction operations
- `ethereumTransaction` - EVM transaction operations

### Hardware Wallet Support

- `importTrezorAccount(label?)` - Import Trezor account
- `importLedgerAccount(isConnected, label?)` - Import Ledger account

## Security

- `initializeSession`, `initializeWalletSecurely`, and the initialization factories create a new wallet only when both vault records are absent. Use `unlock()` to restore an existing wallet. Repeating initialization on a matching live session verifies the stored wallet without rewriting it.
- Fresh vault salt and ciphertext are created together only if both are absent, through the core conditional-creation operation. Native extension contexts sharing an origin/storage partition are coordinated by Web Locks; custom backends must provide atomic `createItemsIfAbsent`. Unsupported adapters are rejected before writing. Existing or incomplete records are preserved.
- UTXO signing authenticates the selected account's paths, public keys and spent scripts. A joint PSBT may include unfinished inputs for another signer: their HD/path hints are removed before the selected private signer runs, then their public metadata is restored to the returned partial PSBT. Another account in the same wallet remains unsigned. At least one unfinished input must authenticate to the selected account; a wholly finalized PSBT retains its existing handling. Standard P2WSH, wrapped P2WSH and P2SH multisig preserve external cosigner signatures and continuation. Hardware paths and single-address imports can reject unsupported joint inputs rather than widening signing authority.
- Hardware signing preserves already-finalized external inputs without requesting their private derivations. Trezor receives them as `EXTERNAL` inputs; Ledger retains their final scripts in PSBTv2 and skips signing/finalizing them again. Unfinished foreign hardware inputs remain unsupported.
- Persisted wallet and account secrets are encrypted; plaintext signing material is used in memory
- Session data is cleared when the keyring is locked
- Hardware wallet integration follows device security models
- Secure memory management with explicit cleanup

## License

MIT License
