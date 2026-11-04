/* eslint-env node */
// Exercise the installed Connect schema outside Jest's CommonJS transform.
const {
  EthereumSignTransaction,
} = require('@trezor/connect-common/lib/types/api/ethereum/common.js');
const { Validate } = require('@trezor/schema-utils');
const request = JSON.parse(process.argv[2], (_key, value) => {
  return value && typeof value === 'object' && 'sdkTestBigInt' in value
    ? BigInt(value.sdkTestBigInt)
    : value;
});
process.stdout.write(
  JSON.stringify({ valid: Validate(EthereumSignTransaction, request) })
);
