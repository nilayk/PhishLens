import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // The detection + scoring stack must run without Chrome or a DOM.
    environment: 'node',
    include: ['test/**/*.test.ts'],
    globals: false,
    coverage: {
      provider: 'v8',
      include: ['src/analysis/**', 'src/shared/**'],
      reporter: ['text', 'html'],
    },
  },
  define: {
    __PHISHLENS_DEV__: 'false',
    __PHISHLENS_VERSION__: '"0.1.0-test"',
  },
});
