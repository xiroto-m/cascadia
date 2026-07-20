import { defineConfig } from 'vite';

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
  server: {
    port: 3000,
    open: true
  }
});
