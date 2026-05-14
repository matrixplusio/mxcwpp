<template>
  <a-config-provider :theme="themeConfig">
    <router-view />
  </a-config-provider>
</template>

<script setup lang="ts">
import { theme } from 'ant-design-vue'

/**
 * 主题配置 — 对齐 Elkeid / Arco Design 配色
 * 主色: #165DFF (Arco Blue)
 */
const themeConfig = {
  algorithm: theme.defaultAlgorithm,
  token: {
    // 主色系
    colorPrimary: '#165DFF',
    colorInfo: '#165DFF',
    colorSuccess: '#00B42A',
    colorWarning: '#FF7D00',
    colorError: '#F53F3F',

    // 圆角
    borderRadius: 4,
    borderRadiusLG: 8,
    borderRadiusSM: 2,

    // 背景
    colorBgContainer: '#FFFFFF',
    colorBgLayout: '#F2F3F5',
    colorBgElevated: '#FFFFFF',

    // 文字
    colorText: '#1D2129',
    colorTextSecondary: '#4E5969',
    colorTextTertiary: '#86909C',
    colorTextQuaternary: '#C9CDD4',

    // 边框
    colorBorder: '#E5E6EB',
    colorBorderSecondary: '#E5E8EF',

    // 填充
    colorFillSecondary: '#F2F3F5',
    colorFillTertiary: '#F7F8FA',
    colorFillQuaternary: '#FAFAFA',

    // 字体
    fontFamily: "'PingFang SC', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, 'Noto Sans', sans-serif",
    fontSize: 14,

    // 阴影
    boxShadow: '0 4px 10px rgba(0, 0, 0, 0.1)',
    boxShadowSecondary: '0 1px 2px rgba(0, 0, 0, 0.03), 0 2px 4px rgba(0, 0, 0, 0.04)',
  },
  components: {
    Button: {
      borderRadius: 4,
    },
    Card: {
      borderRadiusLG: 8,
    },
    Input: {
      borderRadius: 4,
    },
    Select: {
      borderRadius: 4,
    },
    Table: {
      borderRadiusLG: 8,
      headerBg: '#F7F8FA',
      rowHoverBg: '#F7F8FA',
      headerColor: '#1D2129',
    },
    Modal: {
      borderRadiusLG: 8,
    },
    Tag: {
      borderRadiusSM: 2,
    },
    Menu: {
      itemBorderRadius: 4,
      subMenuItemBorderRadius: 4,
    },
    Tabs: {
      cardBorderRadius: 4,
    },
  },
}
</script>

<style>
#app {
  width: 100%;
  height: 100vh;
}
</style>
