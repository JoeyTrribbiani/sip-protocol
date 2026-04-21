module.exports = {
  env: {
    node: true,
    es2021: true,
    jest: true
  },
  extends: [
    'eslint:recommended'
  ],
  parserOptions: {
    ecmaVersion: 'latest',
    sourceType: 'module'
  },
  rules: {
    'indent': ['error', 2],
    'linebreak-style': ['error', 'unix'],
    'quotes': ['error', 'single'],
    'semi': ['error', 'always'],
    'no-unused-vars': ['warn'],
    'no-console': 'off',
    'camelcase': 'warn',
    'no-magic-numbers': 'warn',
    'max-len': ['warn', { code: 100 }]
  },
  ignorePatterns: [
    'node_modules/',
    'tests/',
    'examples/',
    '*.min.js'
  ]
};
