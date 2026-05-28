<template>
  <a-drawer
    :open="open"
    :width="width"
    :title="undefined"
    :closable="false"
    :header-style="{ display: 'none' }"
    :body-style="{ padding: 0, background: 'var(--mxsec-card-bg)' }"
    class="detail-drawer"
    @close="$emit('update:open', false)"
  >
    <!-- 自定义标题栏 -->
    <div class="drawer-header">
      <div class="drawer-title-area">
        <h3 class="drawer-title">{{ title }}</h3>
        <slot name="header" />
      </div>
      <span class="drawer-close" @click="$emit('update:open', false)">&times;</span>
    </div>

    <!-- 主体内容 -->
    <div class="drawer-body">
      <slot />
    </div>

    <!-- 底部操作栏 -->
    <div v-if="$slots.footer" class="drawer-footer">
      <slot name="footer" />
    </div>
  </a-drawer>
</template>

<script setup lang="ts">
withDefaults(defineProps<{
  open: boolean
  title: string
  width?: number
}>(), {
  width: 600,
})

defineEmits<{
  'update:open': [value: boolean]
}>()
</script>

<style scoped>
.drawer-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 16px 24px;
  border-bottom: 1px solid var(--mxsec-border);
  min-height: 56px;
}

.drawer-title-area {
  display: flex;
  align-items: center;
  gap: 12px;
  flex: 1;
  min-width: 0;
}

.drawer-title {
  margin: 0;
  font-size: 16px;
  font-weight: 600;
  color: var(--mxsec-text-1);
}

.drawer-close {
  font-size: 24px;
  color: var(--mxsec-text-3);
  cursor: pointer;
  line-height: 1;
  padding: 4px;
  border-radius: 4px;
  transition: color 0.15s, background 0.15s;
  flex-shrink: 0;
}

.drawer-close:hover {
  color: var(--mxsec-text-1);
  background: rgba(59, 130, 246, 0.08);
}

.drawer-body {
  padding: 20px 24px;
  overflow-y: auto;
  flex: 1;
}

.drawer-footer {
  padding: 12px 24px;
  border-top: 1px solid var(--mxsec-border);
  display: flex;
  gap: 8px;
  justify-content: flex-end;
}
</style>

<style>
/* 全局 Drawer 暗色适配 */
.detail-drawer .ant-drawer-content {
  background: var(--mxsec-card-bg);
}

.detail-drawer .ant-drawer-body {
  display: flex;
  flex-direction: column;
}
</style>
