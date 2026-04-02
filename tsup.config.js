import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['index.js'],
  format: ['esm', 'cjs'],
  outDir: 'dist',
  splitting: false,
  clean: true,
  external: [
    'node:crypto',
    'node:dgram',
    'node:net',
    'node:tls',
    'node:fs',
  ],
});
