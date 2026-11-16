// Build the local dependency graph used by CI without publishing candidate packages.
const { cpSync, existsSync, lstatSync, mkdirSync, rmSync } = require('node:fs');
const { resolve } = require('node:path');
const { execFileSync } = require('node:child_process');

const root = resolve(__dirname, '..');
for (const name of ['sysweb3-network', 'sysweb3-utils']) {
  const directory = resolve(root, 'packages', name);
  execFileSync(process.execPath, [resolve(root, 'node_modules/typescript/bin/tsc'), '-p', 'tsconfig.json'], { cwd: directory, stdio: 'inherit' });
  execFileSync(process.execPath, [resolve(root, 'scripts/package/copy.js')], { cwd: directory, stdio: 'inherit' });
  for (const consumer of [root, ...['sysweb3-network', 'sysweb3-utils', 'sysweb3-keyring'].map(item => resolve(root, 'packages', item))]) {
    const target = resolve(consumer, 'node_modules/@sidhujag', name);
    // CI dependencies are ordinary directories. Never follow a developer's workspace link.
    for (const path of [resolve(consumer, 'node_modules'), resolve(consumer, 'node_modules/@sidhujag'), target]) {
      if (existsSync(path) && lstatSync(path).isSymbolicLink()) throw new Error(`Refusing to replace workspace link ${path}`);
    }
    rmSync(target, { recursive: true, force: true });
    mkdirSync(resolve(target, '..'), { recursive: true });
    cpSync(resolve(directory, 'dist'), target, { recursive: true });
  }
}
