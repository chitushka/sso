import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// In dev the API runs on :8080; cookies must flow, so we proxy instead of CORS.
export default defineConfig({
  plugins: [vue()],
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://localhost:8080',
      '/oauth2': 'http://localhost:8080',
      '/.well-known': 'http://localhost:8080',
      '/health': 'http://localhost:8080'
    }
  }
})
