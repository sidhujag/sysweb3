// The actual built public helpers must not depend on a host-global Node Buffer.
const assert = require('node:assert/strict');
const { resolve } = require('node:path');
const root = resolve(process.argv[2] || 'dist');
// Model the package's published browser export, as Metro does. Node's own
// uint8array-tools export intentionally relies on Node's global Buffer.
const Module = require('node:module');
const originalLoad = Module._load;
Module._load = function(request, parent, isMain) {
  if (request === 'uint8array-tools') {
    const resolved = Module._resolveFilename(request, parent, isMain);
    const browser = resolved.replace(/src[\/]cjs[\/]index\.cjs$/, 'src/mjs/browser.js');
    if (browser !== resolved) return originalLoad.call(this, browser, parent, isMain);
  }
  return originalLoad.call(this, request, parent, isMain);
};
const { deriveDescriptorAddress } = require(resolve(root, 'cjs/utils/watch-descriptor.js'));
const { convertExtendedKeyVersion } = require(resolve(root, 'cjs/utils/derivation-paths.js'));
const { deriveBip84PublicAddress, parseBip84PublicAccount } = require(resolve(root, 'cjs/public-bip84.js'));
const XPUB = 'xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ';
Module._load = originalLoad;
const saved = Object.getOwnPropertyDescriptor(globalThis, 'Buffer');
let result;
try {
  Reflect.deleteProperty(globalThis, 'Buffer');
  const key = convertExtendedKeyVersion(XPUB, '04b24746');
  const account = parseBip84PublicAccount({ network: 'bitcoin', accountKey: key });
  result = {
    key,
    descriptor: deriveDescriptorAddress(`wpkh(${XPUB}/0/*)`, { kind: 'syscoin', slip44: 0, currency: 'BTC' }),
    receive: deriveBip84PublicAddress({ network: 'bitcoin', accountKey: account.canonicalKey, branch: 0, index: 0 }).address,
  };
} finally {
  if (saved) Object.defineProperty(globalThis, 'Buffer', saved);
}
assert.deepEqual(result, {
  key: 'zpub6qLiJCzi7t1C7qRZx8ULcy2eGbXpmbbQZmu3znjqoR4VZADKELunndvcw4iSVaGx2KhviLLXuB3vcyGcdd2q8XXBQJc5T5qrtorRowa1zfs',
  descriptor: 'bc1qalwlmdxd2ggue4290ekzxl9tetg56neexr6amw',
  receive: 'bc1qalwlmdxd2ggue4290ekzxl9tetg56neexr6amw',
});
console.log('PASS: real public helpers derive without global Buffer');
