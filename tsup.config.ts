import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/**/*.ts', '!src/**/*.test.ts', '!src/**/*.spec.ts'],
  format: ['esm', 'cjs'],
  dts: {
    resolve: true,
  },
  sourcemap: true,
  splitting: false,
  clean: true,
  treeshake: true,
  tsconfig: './tsconfig.json',
});
