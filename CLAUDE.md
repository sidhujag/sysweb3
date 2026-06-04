# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Building

```bash
# Build all packages
yarn build

# Build specific package
cd packages/sysweb3-core && yarn build
cd packages/sysweb3-keyring && yarn build
cd packages/sysweb3-network && yarn build
cd packages/sysweb3-utils && yarn build
```

### Testing

```bash
# Run all tests
yarn test

# Run tests for specific package
cd packages/sysweb3-keyring && yarn test

# Run specific test file
yarn test keyring-manager.spec.ts

# Run tests in watch mode
yarn test --watch

# Run tests with coverage
yarn test --coverage
```

### Linting and Type Checking

```bash
# Run linting
yarn lint
yarn lint:fix  # Auto-fix issues

# Type checking
yarn type-check

# Format code
yarn format
```

## Architecture Overview

SysWeb3 is a multi-chain JavaScript/TypeScript library organized as a monorepo with four core packages:

### Package Dependencies

```
sysweb3-network (base layer - no internal deps)
    ↓
sysweb3-core (depends on network)
    ↓
sysweb3-utils (depends on network)
    ↓
sysweb3-keyring (depends on core, network, utils)
```

### Key Architectural Patterns

1. **Multi-Chain Support**: The system supports both UTXO-based chains (Bitcoin, Syscoin) and account-based chains (Ethereum, EVM-compatible). Network switching is handled through the `INetworkType` enum.

2. **HD Wallet Architecture**: Uses BIP32/BIP44/BIP84 standards for hierarchical deterministic wallets. The `SyscoinHDSigner` manages UTXO accounts while Ethereum uses standard derivation paths.

3. **Hardware Wallet Abstraction**: Trezor and Ledger support is abstracted through `TrezorKeyring` and `LedgerKeyring` classes, providing a unified interface.

4. **State Management**: The `KeyringManager` maintains wallet state including accounts, networks, and balances. State persistence is handled through encrypted vault storage.

5. **Network Synchronization**: Critical logic in `shouldUpdateHDSigner()` determines when HD signers need recreation based on network parameter changes (testnet/mainnet, SLIP44, blockbook URL).

### Critical Components

1. **KeyringManager** (`packages/sysweb3-keyring/src/keyring-manager.ts`): Central orchestrator for all wallet operations. Handles account creation, network switching, and transaction signing.

2. **Network RPC Validation** (`packages/sysweb3-network/src/rpc.ts`): Validates both Ethereum and Bitcoin-like RPC endpoints. Critical for ensuring correct network configuration.

3. **Transaction Handlers**: Separate implementations for Syscoin (`SyscoinTransactions`) and Ethereum (`EthereumTransactions`) transaction creation and signing.

4. **Storage Layer** (`packages/sysweb3-keyring/src/storage.ts`): Handles encrypted vault operations for secure key storage.

### Performance Considerations

1. **Balance Fetching**: Only fetch balances for the active account to reduce network calls
2. **HD Signer Caching**: Reuse HD signers when network parameters haven't changed
3. **Parallel Operations**: Use Promise.all for concurrent network requests where possible
4. **Memory Management**: Clean up unused signers when switching networks

### Security Best Practices

1. **Imported Accounts**: Single-address accounts (WIF imports) cannot perform HD operations
2. **Password Validation**: Always validate passwords before sensitive operations
3. **State Isolation**: Proper cleanup in test environments to prevent state contamination
4. **Error Handling**: Never expose sensitive data in error messages

## Common Development Tasks

### Adding a New Network

1. Add network configuration to `packages/sysweb3-network/src/networks.ts`
2. Update chain validation in `packages/sysweb3-network/src/rpc.ts`
3. Add network-specific tests
4. Update TypeScript types if needed

### Debugging Network Issues

1. Check `shouldUpdateHDSigner()` logic for HD signer recreation
2. Verify network parameters (chainId, slip44)
3. Validate RPC endpoint with `validateSysRpc()` or `validateEthRpc()`
4. Check blockbook URL format for UTXO chains

### Testing Hardware Wallets

Hardware wallet tests use mocks by default. See test setup in:

- `packages/sysweb3-keyring/test/__mocks__/ledger-mock.js`
- `packages/sysweb3-keyring/test/__mocks__/trezor-mock.js`

# Multi-Keyring Architecture: Single Active Keyring Model

## Overview

The multi-keyring architecture has been updated to follow a **single active unlocked keyring** model for enhanced security and clean state management.

## Storage Separation by slip44

### Vault Storage

Each keyring now stores its vault data in a slip44-specific location:

- **Syscoin (slip44=57)**: `vault-57`
- **Ethereum (slip44=60)**: `vault-60`
- **Bitcoin (slip44=0)**: `vault-0`
- **Litecoin (slip44=2)**: `vault-2`
- etc.

This ensures complete isolation between different network types. The vault contains:

- `mnemonic`: The encrypted seed phrase (shared across all keyrings from the same seed)

### Global Settings Storage (Managed by Pali)

Settings that are shared across all keyrings are stored separately by Pali's MainController:

- **`global-settings`**: Contains:
  - `hasEncryptedVault`: Global vault status (true if any vault exists)
  - `advancedSettings`: User preferences shared across all networks
  - `coinsList`: Cached token/asset lists
- **`vault-keys`**: Password hash and salt (shared for all keyrings)

### Redux State

Stored separately under the `'state'` key and contains UI state, account data, network settings, etc.

### Storage Keys Summary

- `sysweb3-vault-{slip44}` - Encrypted mnemonics per slip44 (actual Chrome storage keys)
- `sysweb3-vault-keys` - Password hash/salt (shared)
- `sysweb3-global-settings` - Global settings (managed by Pali)
- `sysweb3-state` - Redux state

Note: The keyring package only manages vault storage. Global wallet settings are managed by Pali's MainController.

### Migration Support

The storage layer includes automatic migration:

1. If a slip44-specific vault doesn't exist, it checks for the legacy global `vault`
2. If found, it migrates the data to the slip44-specific location
3. This ensures backward compatibility while moving to the new architecture

## Key Principles

### 1. **One Unlocked Keyring at a Time**

- Only the active keyring should be unlocked
- All other keyrings remain locked
- This prevents cross-keyring state contamination and provides clear security boundaries

### 2. **Session Transfer on Switch**

- When switching between keyrings (different slip44), session data is transferred
- The previous keyring is locked immediately after session transfer
- This ensures continuity while maintaining security

### 3. **Fail-Fast on Locked Target**

- If switching to a locked keyring and no session can be transferred, the operation fails
- This forces explicit unlock and prevents silent failures

## Implementation Details

### Key Methods Updated:

#### `switchActiveKeyring()`

```typescript
// Handles the complete keyring switching flow:
// 1. Check if session transfer is needed (different slip44 + current unlocked)
// 2. Create target keyring if it doesn't exist
// 3. Transfer session from current to target keyring
// 4. Lock the previous keyring
// 5. Set up network on the new active keyring
// 6. Lock all other keyrings as a safety measure
```

#### `unlockFromController()`

```typescript
// When unlocking:
// 1. Unlock the active keyring with password
// 2. Lock all other keyrings to maintain single-active principle
// 3. Continue with normal unlock flow
```

#### `lockWallet()`

```typescript
// When locking:
// Lock ALL keyrings, not just the active one
// This ensures complete security when user explicitly locks
```

## Benefits

1. **Security**: Clear boundaries - only one keyring has access to sensitive data at a time
2. **Simplicity**: No complex state synchronization between multiple unlocked keyrings
3. **Predictability**: Always know which keyring is active and unlocked
4. **Memory Efficiency**: Only one set of decrypted keys in memory

## Edge Cases Handled

1. **Creating new keyring**: Session is automatically transferred from existing unlocked keyring
2. **Switching to same slip44**: No session transfer needed, just network setup
3. **No unlocked keyring**: Switching fails with clear error message
4. **Explicit lock**: All keyrings are locked for complete security

## Session Data Transfer

The session data includes:

- `sessionPassword`: The encrypted session password
- `sessionMnemonic`: The encrypted mnemonic
- `sessionMainMnemonic`: The main account mnemonic
- `currentSessionSalt`: The salt for session encryption

This data is transferred atomically to prevent partial states.

## Future Considerations

1. **Performance**: Session transfer is fast (just copying encrypted data)
2. **UX**: Users experience seamless network switching without re-entering passwords
3. **Multi-device**: This architecture supports future multi-device scenarios cleanly

### Session Management

The KeyringManager uses encrypted session storage for temporary runtime data:

- `sessionPassword`: The hashed password for the current session
- `sessionMnemonic`: The encrypted mnemonic phrase
