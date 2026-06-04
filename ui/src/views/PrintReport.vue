<template>
  <div class="print-page report-print-ready">
    <component
      :is="ReportComponent"
      v-if="ReportComponent && tokenReady"
      :date-range="dateRange"
    />
    <div v-else class="print-page__loading">
      正在加载报告数据...
    </div>
    <!-- 通知 Gotenberg PDF render 完成的标记 -->
    <div v-if="renderReady" id="report-ready" data-status="ready" />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, shallowRef, watch } from 'vue'
import { useRoute } from 'vue-router'
import dayjs from 'dayjs'
import type { Dayjs } from 'dayjs'

const route = useRoute()

// 报告类型: edr / antivirus / vulnerability / kube
const reportType = computed(() => String(route.params.type || 'edr'))
const ReportComponent = shallowRef<any>(null)

// 从 query 取打印 token + 时间范围
const tokenReady = ref(false)
const renderReady = ref(false)

const dateRange = computed<[Dayjs, Dayjs]>(() => {
  const s = (route.query.start_time as string) || dayjs().subtract(7, 'day').format('YYYY-MM-DD')
  const e = (route.query.end_time as string) || dayjs().format('YYYY-MM-DD')
  return [dayjs(s), dayjs(e)]
})

onMounted(async () => {
  // 把 print token 写入 localStorage 让 axios interceptor 拾取
  // (与正常登录流程一致，避免改 client.ts 接口)
  const token = (route.query.token as string) || ''
  if (token) {
    localStorage.setItem('mxcsec_token', token)
  }
  tokenReady.value = true

  // 动态加载对应报告组件
  // 打印路由优先用文档式 PrintTemplate（A4 印刷品风格），无则回退 dashboard 组件
  const loaders: Record<string, () => Promise<any>> = {
    edr: () => import('@/views/System/reports/EDRPrintTemplate.vue'),
    antivirus: () => import('@/views/System/reports/AntivirusReport.vue'),
    vulnerability: () => import('@/views/System/reports/VulnerabilityReport.vue'),
    kube: () => import('@/views/System/reports/KubeReport.vue'),
  }
  const loader = loaders[reportType.value]
  if (loader) {
    const mod = await loader()
    ReportComponent.value = mod.default
  }

  // 等待报告组件数据加载完成（简单延迟，Gotenberg waitDelay 3s 兜底）
  setTimeout(() => {
    renderReady.value = true
  }, 2500)
})

watch(() => route.fullPath, () => {
  renderReady.value = false
})
</script>

<style scoped>
.print-page {
  padding: 24px;
  background: #ffffff;
  min-height: 100vh;
}

.print-page__loading {
  text-align: center;
  padding: 48px;
  color: rgba(0, 0, 0, 0.45);
  font-size: 14px;
}

/* 打印态全屏 */
@media print {
  .print-page {
    padding: 0;
  }
}
</style>
