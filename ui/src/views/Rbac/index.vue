<template>
  <div class="rbac-page">
    <div class="page-header">
      <h2>角色权限</h2>
    </div>
    <RolePermissions />
  </div>
</template>

<script setup lang="ts">
import RolePermissions from '@/views/Users/components/RolePermissions.vue'
</script>

<style scoped>
.rbac-page {
  padding: 16px;
}
.page-header {
  margin-bottom: 16px;
}
.page-header h2 {
  margin: 0;
}
</style>
