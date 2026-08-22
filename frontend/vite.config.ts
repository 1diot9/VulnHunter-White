import path from 'path'
import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

function envPort(name: string, fallback: number): number {
  const raw = Number.parseInt(process.env[name] || '', 10)
  return Number.isInteger(raw) && raw >= 1 && raw <= 65535 ? raw : fallback
}

const backendPort = envPort('VULNHUNTER_PORT', 16780)
const frontendPort = envPort('VULNHUNTER_FRONTEND_PORT', 15173)

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes('node_modules')) return
          if (
            id.includes('react-markdown') ||
            id.includes('remark-gfm') ||
            id.includes('remark-') ||
            id.includes('micromark') ||
            id.includes('mdast-') ||
            id.includes('hast-') ||
            id.includes('unist-') ||
            id.includes('vfile') ||
            id.includes('property-information') ||
            id.includes('space-separated-tokens') ||
            id.includes('comma-separated-tokens') ||
            id.includes('devlop') ||
            id.includes('decode-named-character-reference') ||
            id.includes('character-entities') ||
            id.includes('trim-lines') ||
            id.includes('ccount') ||
            id.includes('longest-streak') ||
            id.includes('markdown-table') ||
            id.includes('zwitch') ||
            id.includes('bail') ||
            id.includes('trough') ||
            id.includes('unified') ||
            id.includes('/mdast') ||
            id.includes('/hast')
          ) {
            return 'markdown'
          }
          if (
            id.includes('/react/') ||
            id.includes('/react-dom/') ||
            id.includes('/scheduler/') ||
            id.includes('react-router')
          ) {
            return 'react-vendor'
          }
        },
      },
    },
  },
  server: {
    port: frontendPort,
    strictPort: true,
    proxy: {
      '/api': {
        target: `http://127.0.0.1:${backendPort}`,
        changeOrigin: true,
        timeout: 0,
        configure: (proxy) => {
          proxy.on('proxyRes', (proxyRes, req) => {
            if (String(req.url || '').includes('/stream')) {
              proxyRes.headers['cache-control'] = 'no-cache'
              proxyRes.headers['x-accel-buffering'] = 'no'
            }
          })
        },
      },
    },
  },
})
