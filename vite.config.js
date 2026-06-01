import { defineConfig } from 'vite';

export default defineConfig({
  base: './', // GitHub Pages とローカルプレビューの両方で動作するように相対パスに設定
  build: {
    outDir: 'dist',
    assetsDir: 'assets',
    sourcemap: true
  },
  server: {
    port: 3000,
    open: true
  }
});
