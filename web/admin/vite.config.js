import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// В режиме разработки API работает на :8080; proxy сохраняет cookie без CORS.
export default defineConfig({
  plugins: [vue()],
  test: {
    environment: 'jsdom'
  },
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
