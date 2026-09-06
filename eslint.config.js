// @ts-check
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: ['dist/**', 'coverage/**', 'node_modules/**'],
  },

  // Type-aware linting for everything TypeScript.
  ...tseslint.configs.strictTypeChecked,
  ...tseslint.configs.stylisticTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      // --- Explicitly required by the project brief -------------------------
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/no-unsafe-assignment': 'error',
      '@typescript-eslint/no-unsafe-member-access': 'error',
      '@typescript-eslint/no-unsafe-call': 'error',
      '@typescript-eslint/no-unsafe-return': 'error',
      '@typescript-eslint/no-unsafe-argument': 'error',
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_', caughtErrors: 'all', caughtErrorsIgnorePattern: '^_' },
      ],
      '@typescript-eslint/no-floating-promises': 'error',
      '@typescript-eslint/no-misused-promises': 'error',

      // --- Security posture: attacker-controlled email content -------------
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
      'no-script-url': 'error',
      'no-restricted-properties': [
        'error',
        {
          property: 'innerHTML',
          message: 'Email content is hostile input. Use textContent / el() from src/ui/dom.ts.',
        },
        {
          property: 'outerHTML',
          message: 'Email content is hostile input. Use textContent / el() from src/ui/dom.ts.',
        },
        {
          property: 'insertAdjacentHTML',
          message: 'Email content is hostile input. Use textContent / el() from src/ui/dom.ts.',
        },
      ],
      'no-restricted-globals': [
        'error',
        { name: 'Function', message: 'Never construct functions from extracted email content.' },
      ],

      // --- House style -----------------------------------------------------
      '@typescript-eslint/consistent-type-imports': ['error', { fixStyle: 'separate-type-imports' }],
      '@typescript-eslint/explicit-module-boundary-types': 'off',
      '@typescript-eslint/restrict-template-expressions': ['error', { allowNumber: true }],
      '@typescript-eslint/prefer-nullish-coalescing': ['error', { ignoreConditionalTests: true }],
      eqeqeq: ['error', 'always', { null: 'ignore' }],
      'no-console': 'error',
      curly: ['error', 'multi-line'],
    },
  },

  // The logger is the single sanctioned console surface.
  {
    files: ['src/shared/logger.ts'],
    rules: { 'no-console': 'off' },
  },

  // Build scripts and configs run in Node and are not part of the extension.
  {
    files: ['scripts/**/*.mjs', 'scripts/**/*.js', '*.config.ts', 'eslint.config.js'],
    rules: {
      'no-console': 'off',
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
    },
  },

  // Tests may reach into internals and stub odd shapes.
  {
    files: ['test/**/*.ts'],
    rules: {
      // Dangerous-scheme URLs are *test data* here: the suite has to feed `javascript:` and `data:`
      // URLs to the detectors that exist to catch them.
      'no-script-url': 'off',
      '@typescript-eslint/no-non-null-assertion': 'off',
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
      '@typescript-eslint/no-unsafe-argument': 'off',
      '@typescript-eslint/no-unsafe-call': 'off',
    },
  },

  {
    files: ['**/*.js', '**/*.mjs'],
    ...tseslint.configs.disableTypeChecked,
  },
);
