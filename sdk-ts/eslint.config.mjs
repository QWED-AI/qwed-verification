import js from '@eslint/js';
import tsParser from '@typescript-eslint/parser';
import tsPlugin from '@typescript-eslint/eslint-plugin';

export default [
    {
        ignores: ['dist/**'],
    },
    js.configs.recommended,
    {
        files: ['**/*.ts'],
        languageOptions: {
            parser: tsParser,
            parserOptions: {
                ecmaVersion: 2022,
                sourceType: 'module',
            },
        },
        plugins: {
            '@typescript-eslint': tsPlugin,
        },
        rules: {
            // This is the legacy eslintrc-shaped config, which is the one that
            // carries a `.rules` object. The `typescript-eslint` meta-package
            // exports a same-named `configs.recommended` that is a flat-config
            // array instead; spreading that here would yield nothing and
            // silently drop all 23 rules.
            ...tsPlugin.configs.recommended.rules,
            // `npm run typecheck` reports undefined names and unused locals
            // with full type information; re-checking them in ESLint only
            // produces duplicate, weaker diagnostics.
            'no-undef': 'off',
            'no-unused-vars': 'off',
            '@typescript-eslint/no-unused-vars': [
                'error',
                { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
            ],
        },
    },
];
