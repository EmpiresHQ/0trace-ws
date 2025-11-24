import { defineConfig } from 'vite'
import tailwindcss from '@tailwindcss/vite'

const WS_URL = process.env.WS_URL || 'ws://localhost:8080';

export default defineConfig({
  root: './site',
  plugins: [
    tailwindcss(),
  ],
  define: {
    '__WS_URL__': JSON.stringify(WS_URL),
  },
  build: {
    outDir: '../dist',
    emptyOutDir: true,
    rollupOptions: {
      input: './site/index.html'
    }
  }
})
