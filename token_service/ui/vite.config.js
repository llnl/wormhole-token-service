import process from 'node:process';
import { defineConfig, loadEnv } from 'vite';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  const port = process.env.TOKEN_SERVICE_PORT || env.TOKEN_SERVICE_PORT || 5000;

  return {
    plugins: [tailwindcss()],
    server: {
      proxy: {
        '/api': {
          target: `http://localhost:${port}`,
          changeOrigin: true,
        },
      },
    },
  };
});
