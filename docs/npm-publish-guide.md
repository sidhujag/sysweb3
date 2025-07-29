# Publishing sysweb3 Packages to npm under @syscoin

This guide explains how to publish the sysweb3 packages to npm under the `@syscoin` organization scope.

## Prerequisites

1. **npm Account**: You need an npm account with publish access to the `@syscoin` organization
2. **Node.js**: Version 14 or higher
3. **Yarn**: Version 1.x installed globally

## Step 1: Run the Migration Script

First, update all package names from the incorrect format to the proper npm scoped format:

```bash
cd sysweb3
node scripts/migrate-to-syscoin-npm.js
```

This script will:

- Update all package names from `syscoin/package-name` to `@sidhujag/package-name`
- Update inter-package dependencies to use the new names
- Update pali-wallet's package.json to reference the new names

## Step 2: Build All Packages

Build all packages with their updated names:

```bash
cd sysweb3
yarn build:all
```

This builds all packages in the correct order:

1. sysweb3-core
2. sysweb3-network
3. sysweb3-utils
4. sysweb3-keyring

## Step 3: Login to npm

Login to npm with your account that has access to the @syscoin organization:

```bash
npm login --scope=@syscoin
```

## Step 4: Verify Package Contents (Optional but Recommended)

Before publishing, verify what will be published for each package:

```bash
cd packages/sysweb3-core
yarn release:preflight

cd ../sysweb3-network
yarn release:preflight

cd ../sysweb3-utils
yarn release:preflight

cd ../sysweb3-keyring
yarn release:preflight
```

## Step 5: Publish to npm

### Option A: Publish All at Once

From the sysweb3 root directory:

```bash
cd sysweb3
yarn publish:all
```

### Option B: Publish Individually

If you prefer to publish packages one by one:

```bash
# Publish core first
cd packages/sysweb3-core
yarn release:npm

# Then network
cd ../sysweb3-network
yarn release:npm

# Then utils
cd ../sysweb3-utils
yarn release:npm

# Finally keyring
cd ../sysweb3-keyring
yarn release:npm
```

## Step 6: Update pali-wallet to Use npm Packages

After publishing, update pali-wallet to use the npm packages instead of local file references:

```bash
cd pali-wallet

# Remove local symlinks
rm -rf node_modules/@syscoin

# Install from npm
yarn add @sidhujag/sysweb3-core@latest @sidhujag/sysweb3-network@latest @sidhujag/sysweb3-utils@latest @sidhujag/sysweb3-keyring@latest
```

## Version Management

### Updating Version Numbers

Before publishing, update version numbers in each package's package.json:

```bash
# Example: bump patch version
cd packages/sysweb3-core
npm version patch

# Or manually edit package.json
```

### Version Strategy

- **Patch**: Bug fixes (1.0.1 → 1.0.2)
- **Minor**: New features, backward compatible (1.0.0 → 1.1.0)
- **Major**: Breaking changes (1.0.0 → 2.0.0)

## Troubleshooting

### Permission Denied Error

If you get a permission error when publishing:

```bash
npm ERR! 403 Forbidden - You do not have permission to publish "@sidhujag/package-name"
```

Make sure:

1. You're logged in: `npm whoami`
2. You have publish access to @syscoin org
3. The package doesn't already exist with that exact version

### Package Already Exists

If a version already exists, bump the version number:

```bash
cd packages/sysweb3-core
npm version patch
yarn release:npm
```

### Build Errors

If you encounter build errors:

```bash
# Clean and rebuild
cd sysweb3
rm -rf packages/*/dist
yarn build:all
```

## CI/CD Integration

For automated publishing, you can use GitHub Actions with npm tokens:

1. Generate an npm token: https://www.npmjs.com/settings/YOUR_USERNAME/tokens
2. Add it as a GitHub secret: `NPM_TOKEN`
3. Use in GitHub Actions workflow

## Security Notes

- Never commit npm tokens or credentials
- Use 2FA on your npm account
- Regularly rotate npm tokens
- Review package contents before publishing

## Summary

The complete publishing flow:

```bash
# 1. Migrate package names
cd sysweb3
node scripts/migrate-to-syscoin-npm.js

# 2. Build everything
yarn build:all

# 3. Login to npm
npm login --scope=@syscoin

# 4. Publish
yarn publish:all

# 5. Success! 🎉
```

Your packages are now available at:

- https://www.npmjs.com/package/@sidhujag/sysweb3-core
- https://www.npmjs.com/package/@sidhujag/sysweb3-network
- https://www.npmjs.com/package/@sidhujag/sysweb3-utils
- https://www.npmjs.com/package/@sidhujag/sysweb3-keyring
