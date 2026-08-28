import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The dev server proxies /api to the .NET API so the browser can call it
// without CORS/absolute-URL issues.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    host: true,
    proxy: {
      '/api': {
        target: 'http://localhost:5111',
        changeOrigin: true
      }
    }
  }
})
