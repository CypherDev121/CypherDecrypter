import { defineConfig } from 'vite';

// Chemins relatifs : le même build sert l'app Tauri (tauri://localhost)
// et le site GitHub Pages (/CypherDecrypter/).
export default defineConfig({
  base: './',
  clearScreen: false,
  server: {
    port: 5173,
    strictPort: true,
  },
  build: {
    outDir: 'dist',
    target: 'es2022',
    sourcemap: true,
  },
});
