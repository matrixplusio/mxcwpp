import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { resolve } from 'path'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
    },
  },
  // P0-7: bundle 拆分 + 按需加载 + 大依赖独立 chunk (审计修复: 2.1MB → 拆为多 chunk 浏览器并行加载)
  build: {
    chunkSizeWarningLimit: 800,
    rollupOptions: {
      output: {
        manualChunks: {
          'vendor-antd': ['ant-design-vue', '@ant-design/icons-vue'],
          'vendor-echarts': ['echarts', 'vue-echarts'],
          'vendor-vue': ['vue', 'vue-router', 'pinia'],
          'vendor-pdf': ['html2pdf.js'],
          'vendor-utils': ['dayjs', 'axios'],
        },
        chunkFileNames: 'assets/[name]-[hash].js',
        entryFileNames: 'assets/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash].[ext]',
      },
    },
    sourcemap: false,
    minify: 'esbuild',
    cssCodeSplit: true,
    reportCompressedSize: false,
  },
  server: {
    port: 3000,
    host: '0.0.0.0', // 允许外部访问
    allowedHosts: true, // 允许任意 host（Gotenberg 从 ui 容器名访问）
    watch: {
      usePolling: true,
      interval: 500,
    },
    proxy: {
      '/api': {
        target: process.env.VITE_API_TARGET || 'http://manager:8080',
        changeOrigin: true,
      },
      '/uploads': {
        target: process.env.VITE_API_TARGET || 'http://manager:8080',
        changeOrigin: true,
      },
      '/agent': {
        target: process.env.VITE_API_TARGET || 'http://manager:8080',
        changeOrigin: true,
      },
    },
  },
})
