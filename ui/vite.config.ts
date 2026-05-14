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
  server: {
    port: 3000,
    host: '0.0.0.0', // 允许外部访问
    watch: {
      usePolling: true,
      interval: 500,
    },
    proxy: {
      '/api': {
        // 在 Docker 容器内，使用服务名访问；本地开发时使用 localhost
        target: process.env.VITE_API_TARGET || 'http://manager:8080',
        changeOrigin: true,
      },
      '/uploads': {
        // 代理静态文件服务（Logo 等上传的文件）
        target: process.env.VITE_API_TARGET || 'http://manager:8080',
        changeOrigin: true,
      },
      '/agent': {
        // 代理 Agent 安装/卸载脚本（不需要认证）
        target: process.env.VITE_API_TARGET || 'http://manager:8080',
        changeOrigin: true,
      },
    },
  },
})
