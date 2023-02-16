'use strict';
const tsConfigurations = [
  'eslint:recommended',
  'plugin:@typescript-eslint/recommended',
  'plugin:@typescript-eslint/recommended-requiring-type-checking',
];

const tsRules = {
  '@typescript-eslint/no-unused-vars': 'error',
  '@typescript-eslint/no-unsafe-assignment': 'off',
  '@typescript-eslint/no-unsafe-call': 'off',
  '@typescript-eslint/no-unsafe-member-access': 'off',
  '@typescript-eslint/no-unsafe-return': 'off',
  '@typescript-eslint/consistent-type-imports': [
    'error',
    { prefer: 'type-imports' },
  ],
  // Newly converted plugins use `any` quite a lot, we can't enable the rule,
  // but we can warn so we can eventually address this
  '@typescript-eslint/no-unsafe-argument': 'warn',
};

const testConfigurations = ['plugin:mocha/recommended'];

const testRules = {
  'mocha/no-exclusive-tests': 'error',
  'mocha/no-hooks-for-single-case': 'off',
  'mocha/no-setup-in-describe': 'off',
  '@typescript-eslint/no-explicit-any': 'off',
  '@typescript-eslint/no-empty-function': 'off',
  '@typescript-eslint/no-unsafe-argument': 'off',
  '@typescript-eslint/restrict-template-expressions': 'off',
};

module.exports = {
  plugins: ['@typescript-eslint', 'mocha'],
  root: true,
  parserOptions: {
    tsconfigRootDir: __dirname,
    project: ['./tsconfig-lint.json'],
    ecmaVersion: 'latest',
  },
  env: { node: true, es6: true },
  overrides: [
    {
      files: ['**/*.ts'],
      parser: '@typescript-eslint/parser',
      extends: [...tsConfigurations, 'prettier'],
      rules: { ...tsRules },
    },
    {
      files: ['**/*.spec.ts', '**/*.test.ts'],
      env: { mocha: true },
      extends: [...testConfigurations],
      rules: {
        ...testRules,
        '@mongodb-js/compass/unique-mongodb-log-id': 'off',
      },
    },
  ],
  settings: {
    react: {
      version: 'detect',
    },
  },
};
