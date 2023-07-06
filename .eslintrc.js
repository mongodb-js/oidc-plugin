'use strict';

const shared = require('@mongodb-js/eslint-config-devtools');
const common = require('@mongodb-js/eslint-config-devtools/common');

module.exports = {
  plugins: [...shared.plugins],
  rules: {
    ...shared.rules,
  },
  env: {
    ...shared.env,
  },
  overrides: [
    {
      ...common.jsOverrides,
    },
    {
      ...common.jsxOverrides,
    },
    {
      ...common.tsOverrides,
    },
    {
      ...common.tsxOverrides,
    },
    {
      ...common.testOverrides,
    },
  ],
  settings: {
    ...shared.settings,
  },
  parserOptions: {
    tsconfigRootDir: __dirname,
    project: ['./tsconfig-lint.json'],
  },
};
