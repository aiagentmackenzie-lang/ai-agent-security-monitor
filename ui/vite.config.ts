import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Served by the Fastify API at /ui/. The built bundle uses absolute paths
// under /ui/ and calls the API with absolute paths (e.g. /dashboard/summary),
// so it works regardless of where it is hosted behind the API.
export default defineConfig({
  plugins: [react()],
  base: '/ui/',
  build: {
    outDir: 'dist',
    sourcemap: false,
    emptyOutDir: true,
  },
  server: {
    port: 5174,
    proxy: {
      '/agents': 'http://127.0.0.1:8000',
      '/alerts': 'http://127.0.0.1:8000',
      '/policies': 'http://127.0.0.1:8000',
      '/dashboard': 'http://127.0.0.1:8000',
      '/discovery': 'http://127.0.0.1:8000',
      '/health': 'http://127.0.0.1:8000',
    },
  },
});