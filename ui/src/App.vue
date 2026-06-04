<template>
  <a-config-provider
    :theme="themeConfig"
    :get-popup-container="getPopupContainer"
  >
    <router-view />
  </a-config-provider>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { theme } from 'ant-design-vue'
import { useThemeStore } from '@/stores/theme'

const themeStore = useThemeStore()

// 共享 token（浅色/暗色通用）
const sharedToken = {
  colorPrimary: '#3B82F6',
  colorInfo: '#3B82F6',
  colorSuccess: '#22C55E',
  colorWarning: '#F59E0B',
  colorError: '#EF4444',
  borderRadius: 6,
  borderRadiusLG: 10,
  borderRadiusSM: 4,
  fontFamily: "'PingFang SC', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, 'Noto Sans', sans-serif",
  fontSize: 14,
}

// 共享组件 token
const sharedComponents = {
  Button: { borderRadius: 6 },
  Card: { borderRadiusLG: 10 },
  Input: { borderRadius: 6 },
  Select: { borderRadius: 6 },
  Modal: { borderRadiusLG: 10 },
  Tag: { borderRadiusSM: 4 },
  Tabs: { cardBorderRadius: 6 },
}

// 全局 popup 容器永远锚到 body，避免 tooltip/popover/dropdown 在父组件 unmount 时
// 触发 "Cannot read properties of null (reading 'parentNode')" 错误。
// ant-design-vue 4.x + a-table 行内 tooltip / a-drawer 关闭场景常见。
// 副作用：popup 不跟随父滚动（但 ant-design 用 absolute 位置计算 follow trigger，无影响）。
const getPopupContainer = () => document.body

const themeConfig = computed(() => {
  if (themeStore.isDark) {
    return {
      algorithm: theme.darkAlgorithm,
      token: {
        ...sharedToken,
        colorBgContainer: '#161B22',
        colorBgLayout: '#0D1117',
        colorBgElevated: '#1C2333',
        colorText: '#E5E5E5',
        colorTextSecondary: '#AAAAAA',
        colorTextTertiary: '#888888',
        colorTextQuaternary: '#555555',
        colorBorder: 'rgba(30, 58, 95, 0.4)',
        colorBorderSecondary: 'rgba(30, 58, 95, 0.2)',
        colorFillSecondary: '#1C2333',
        colorFillTertiary: '#161B22',
        colorFillQuaternary: '#0D1117',
        boxShadow: '0 4px 12px rgba(0, 0, 0, 0.3)',
        boxShadowSecondary: '0 2px 8px rgba(0, 0, 0, 0.2)',
      },
      components: {
        ...sharedComponents,
        Table: {
          borderRadiusLG: 10,
          headerBg: '#1C2333',
          rowHoverBg: 'rgba(59, 130, 246, 0.06)',
          headerColor: '#E5E5E5',
        },
        Menu: {
          itemBorderRadius: 6,
          subMenuItemBorderRadius: 6,
          darkItemBg: 'transparent',
          darkSubMenuItemBg: 'transparent',
          darkItemSelectedBg: 'rgba(59, 130, 246, 0.15)',
          darkItemHoverBg: 'rgba(59, 130, 246, 0.08)',
          darkItemSelectedColor: '#3B82F6',
        },
      },
    }
  }

  // 浅色主题
  return {
    algorithm: theme.defaultAlgorithm,
    token: {
      ...sharedToken,
      colorBgContainer: '#FFFFFF',
      colorBgLayout: '#F0F2F5',
      colorBgElevated: '#FFFFFF',
      colorText: '#1D2129',
      colorTextSecondary: '#4E5969',
      colorTextTertiary: '#86909C',
      colorTextQuaternary: '#C9CDD4',
      colorBorder: '#E5E8EF',
      colorBorderSecondary: '#F2F3F5',
      colorFillSecondary: '#F7F8FA',
      colorFillTertiary: '#F2F3F5',
      colorFillQuaternary: '#F7F8FA',
      boxShadow: '0 2px 8px rgba(0, 0, 0, 0.08)',
      boxShadowSecondary: '0 1px 4px rgba(0, 0, 0, 0.05)',
    },
    components: {
      ...sharedComponents,
      Table: {
        borderRadiusLG: 10,
        headerBg: '#F7F8FA',
        rowHoverBg: 'rgba(59, 130, 246, 0.04)',
        headerColor: '#1D2129',
      },
      Menu: {
        itemBorderRadius: 6,
        subMenuItemBorderRadius: 6,
      },
    },
  }
})
</script>

<style>
#app {
  width: 100%;
  height: 100vh;
}
</style>
