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
    'camelcase': 'off',  // 允许snake_case以保持与Python API一致
    'no-magic-numbers': ['warn', {
      ignore: [0, 1],  // 忽略0和1（数组起始索引和自增操作）
      ignoreArrayIndexes: true,  // 忽略数组索引
      ignoreDefaultValues: true  // 忽略默认值
    }],
    'max-len': ['warn', { code: 100 }]
  },
  ignorePatterns: [
    'node_modules/',
    'tests/',
    'examples/',
    '*.min.js'
  ]
};
