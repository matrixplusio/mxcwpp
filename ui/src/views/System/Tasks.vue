<template>
  <div class="system-tasks-page">
    <div class="page-header">
      <h2>任务列表</h2>
    </div>

    <a-card :bordered="false">
      <a-empty description="任务列表功能开发中..." />
    </a-card>
  </div>
</template>

<script setup lang="ts">
// 任务列表页面 - 可以创建批量任务用于主机执行，比如重启或者批量执行任务（如：基线检查等）
</script>

<style scoped>
.system-tasks-page {
  width: 100%;
}

.page-header {
  margin-bottom: 24px;
}

.page-header h2 {
  margin: 0;
  font-size: 20px;
  font-weight: 600;
}
</style>
