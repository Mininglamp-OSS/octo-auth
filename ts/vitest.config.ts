import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['tests/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      // types-ext is an ambient-augmentation module with no runtime code;
      // v8 coverage would report 0/0 for it and skew nothing, but excluding
      // makes the report cleaner.
      exclude: ['src/**/*.d.ts', 'src/types-ext.ts'],
      reporter: ['text', 'html', 'json-summary'],
      thresholds: {
        lines: 90,
        functions: 90,
        branches: 85,
        statements: 90,
      },
    },
  },
})
