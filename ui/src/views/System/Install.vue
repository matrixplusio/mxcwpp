<template>
  <div class="system-install-page">
    <div class="page-header">
      <h2>安装配置指引</h2>
    </div>

    <a-card :bordered="false">
      <a-tabs v-model:activeKey="activeTab" type="card">
        <a-tab-pane key="linux" tab="Linux">
          <LinuxInstallGuide />
        </a-tab-pane>
        <a-tab-pane key="kubernetes" tab="Kubernetes">
          <KubernetesInstallGuide />
        </a-tab-pane>
      </a-tabs>
    </a-card>
  </div>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import LinuxInstallGuide from './components/LinuxInstallGuide.vue'
import KubernetesInstallGuide from './components/KubernetesInstallGuide.vue'

const route = useRoute()
const router = useRouter()

const validTabs = ['linux', 'kubernetes']
const activeTab = ref(validTabs.includes(route.query.tab as string) ? (route.query.tab as string) : 'linux')

watch(activeTab, (newTab) => {
  router.replace({ query: { ...route.query, tab: newTab } })
})

watch(
  () => route.query.tab,
  (newTab) => {
    if (newTab && validTabs.includes(newTab as string) && newTab !== activeTab.value) {
      activeTab.value = newTab as string
    }
  }
)
</script>

<style scoped>
.system-install-page {
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
