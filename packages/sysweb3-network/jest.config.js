module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx'],
  transform: {
    '^.+\\.(ts|tsx)$': [
      'ts-jest',
      {
        isolatedModules: true,
      },
    ],
  },
  testMatch: ['**/test/**/*.spec.ts'],
  moduleNameMapper: {
    '^@sidhujag/sysweb3-utils$': '<rootDir>/../sysweb3-utils/src',
    '^@sidhujag/sysweb3-core$': '<rootDir>/../sysweb3-core/src',
    '^@sidhujag/sysweb3-keyring$': '<rootDir>/../sysweb3-keyring/src',
    'isomorphic-fetch': '<rootDir>/../../__mocks__/isomorphic-fetch.js',
  },
  setupFilesAfterEnv: ['<rootDir>/../../jest.setup.js'],
};
