import { defineConfig } from 'vite';
import fs from 'node:fs';
import path from 'node:path';

export default defineConfig({
  base: './', // GitHub Pages とローカルプレビューの両方で動作するように相対パスに設定
  build: {
    outDir: 'dist',
    assetsDir: 'assets',
    sourcemap: false,
    rollupOptions: {
      input: {
        main: './index.html',
        quiz: './quiz.html'
      }
    }
  },
  plugins: [
    {
      name: 'copy-docs',
      closeBundle() {
        const copyFolder = (src, dest) => {
          if (fs.existsSync(src)) {
            fs.cpSync(src, dest, { recursive: true, force: true });
          }
        };
        copyFolder('product-docs', 'dist/product-docs');
        copyFolder('backoffice-docs', 'dist/backoffice-docs');
      }
    }
  ],
  server: {
    port: 3000,
    open: true
  }
});
