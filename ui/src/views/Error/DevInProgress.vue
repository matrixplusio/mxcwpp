<template>
  <div class="dev-page">
    <a-result
      status="info"
      title="功能开发中"
      sub-title="该功能正在开发中，敬请期待"
    >
      <template #icon>
        <tool-outlined style="color: #1677ff" />
      </template>
      <template #extra>
        <a-button type="primary" @click="goBack">
          返回上一页
        </a-button>
      </template>
    </a-result>
  </div>
</template>

<script setup lang="ts">
import { useRouter } from 'vue-router'
import { ToolOutlined } from '@ant-design/icons-vue'

const router = useRouter()

const goBack = () => {
  if (window.history.length > 1) {
    router.back()
  } else {
    router.push('/')
  }
}
</script>

<style scoped>
.dev-page {
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 60vh;
}
</style>
