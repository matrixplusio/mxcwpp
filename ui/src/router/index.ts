import { createRouter, createWebHistory } from 'vue-router'
import type { RouteRecordRaw } from 'vue-router'
import Layout from '@/layouts/BasicLayout.vue'
import { useAuthStore } from '@/stores/auth'

const routes: RouteRecordRaw[] = [
  {
    path: '/login',
    name: 'Login',
    component: () => import('@/views/Login.vue'),
    meta: { title: '登录', public: true },
  },
  {
    path: '/',
    component: Layout,
    redirect: '/dashboard',
    meta: { requiresAuth: true },
    children: [
      {
        path: 'dashboard',
        name: 'Dashboard',
        component: () => import('@/views/Dashboard/index.vue'),
        meta: { title: '安全概览' },
      },
      {
        path: 'hosts',
        name: 'Hosts',
        component: () => import('@/views/Hosts/index.vue'),
        meta: { title: '主机列表' },
      },
      {
        path: 'hosts/:hostId',
        name: 'HostDetail',
        component: () => import('@/views/Hosts/Detail.vue'),
        meta: { title: '主机详情' },
      },
      {
        path: 'business-lines',
        name: 'BusinessLines',
        component: () => import('@/views/BusinessLines/index.vue'),
        meta: { title: '业务线管理' },
      },
      {
        path: 'policies',
        name: 'Policies',
        component: () => import('@/views/Policies/index.vue'),
        meta: { title: '基线检查' },
      },
      {
        path: 'policies/:policyId',
        name: 'PolicyDetail',
        component: () => import('@/views/Policies/Detail.vue'),
        meta: { title: '基线检查详情' },
      },
      {
        path: 'policy-groups',
        name: 'PolicyGroups',
        component: () => import('@/views/PolicyGroups/index.vue'),
        meta: { title: '策略组管理' },
      },
      {
        path: 'policy-groups/policies/:policyId/rules',
        name: 'PolicyRules',
        component: () => import('@/views/PolicyGroups/PolicyRules.vue'),
        meta: { title: '规则管理' },
      },
      {
        path: 'tasks',
        name: 'Tasks',
        component: () => import('@/views/Tasks/index.vue'),
        meta: { title: '任务执行' },
      },
      {
        path: 'baseline/fix',
        name: 'BaselineFix',
        component: () => import('@/views/Baseline/Fix.vue'),
        meta: { title: '基线修复' },
      },
      {
        path: 'baseline/fix-history',
        name: 'BaselineFixHistory',
        component: () => import('@/views/Baseline/FixHistory.vue'),
        meta: { title: '修复历史' },
      },
      {
        path: 'system/collection',
        name: 'SystemCollection',
        component: () => import('@/views/System/Collection.vue'),
        meta: { title: '平台授权' },
      },
      {
        path: 'system/components',
        name: 'SystemComponents',
        component: () => import('@/views/System/Components.vue'),
        meta: { title: '组件列表', adminOnly: true },
      },
      {
        path: 'system/install',
        name: 'SystemInstall',
        component: () => import('@/views/System/Install.vue'),
        meta: { title: '安装配置' },
      },
      {
        path: 'users',
        name: 'Users',
        component: () => import('@/views/Users/index.vue'),
        meta: { title: '用户管理', adminOnly: true },
      },
      {
        path: 'system/settings',
        name: 'SystemSettings',
        component: () => import('@/views/System/Settings.vue'),
        meta: { title: '基本设置', adminOnly: true },
      },
      {
        path: 'system/notification',
        name: 'SystemNotification',
        component: () => import('@/views/System/Notification.vue'),
        meta: { title: '通知管理', adminOnly: true },
      },
      {
        path: 'system/reports',
        name: 'SystemReports',
        component: () => import('@/views/System/Reports.vue'),
        meta: { title: '统计报表' },
      },
      {
        path: 'system/task-report',
        name: 'SystemTaskReport',
        component: () => import('@/views/System/TaskReport.vue'),
        meta: { title: '任务报告' },
      },
      {
        path: 'alerts',
        name: 'Alerts',
        component: () => import('@/views/Alerts/index.vue'),
        meta: { title: '告警管理' },
      },
      {
        path: 'alerts/:alertId',
        name: 'AlertDetail',
        component: () => import('@/views/Alerts/Detail.vue'),
        meta: { title: '告警详情' },
      },
      {
        path: 'system/inspection',
        name: 'Inspection',
        component: () => import('@/views/Inspection/index.vue'),
        meta: { title: '运维巡检' },
      },
      // FIM（文件完整性监控）
      {
        path: 'fim/dashboard',
        name: 'FIMDashboard',
        component: () => import('@/views/FIM/Dashboard/index.vue'),
        meta: { title: 'FIM 概览' },
      },
      {
        path: 'fim/policies',
        name: 'FIMPolicies',
        component: () => import('@/views/FIM/Policies/index.vue'),
        meta: { title: 'FIM 策略' },
      },
      {
        path: 'fim/events',
        name: 'FIMEvents',
        component: () => import('@/views/FIM/Events/index.vue'),
        meta: { title: 'FIM 事件' },
      },
      {
        path: 'fim/tasks',
        name: 'FIMTasks',
        component: () => import('@/views/FIM/Tasks/index.vue'),
        meta: { title: 'FIM 任务' },
      },
      {
        path: 'fim/baselines',
        name: 'FIMBaselines',
        component: () => import('@/views/FIM/Baselines/index.vue'),
        meta: { title: '基线管理' },
      },
      // === 以下功能开发中，暂用占位页 ===
      // 资产指纹 (全局维度)
      {
        path: 'asset-fingerprint',
        name: 'AssetFingerprint',
        component: () => import('@/views/AssetFingerprint/index.vue'),
        meta: { title: '资产指纹' },
      },
      // 白名单
      {
        path: 'whitelist',
        name: 'Whitelist',
        component: () => import('@/views/Whitelist/index.vue'),
        meta: { title: '白名单' },
      },
      // 漏洞通报
      {
        path: 'vuln-bulletins',
        name: 'VulnBulletins',
        component: () => import('@/views/VulnBulletins/index.vue'),
        meta: { title: '漏洞通报' },
      },
      {
        path: 'vuln-bulletins/:id',
        name: 'VulnBulletinDetail',
        component: () => import('@/views/VulnBulletins/Detail.vue'),
        meta: { title: '通报详情' },
      },
      // 漏洞列表
      {
        path: 'vuln-list',
        name: 'VulnList',
        component: () => import('@/views/VulnList/index.vue'),
        meta: { title: '漏洞列表' },
      },
      {
        path: 'vuln-list/:id',
        name: 'VulnDetail',
        component: () => import('@/views/VulnList/Detail.vue'),
        meta: { title: '漏洞详情' },
      },
      {
        path: 'vuln-scan-history/:id',
        name: 'ScanHistoryDetail',
        component: () => import('@/views/VulnList/ScanHistoryDetail.vue'),
        meta: { title: '扫描记录详情' },
      },
      {
        path: 'vuln-remediation',
        name: 'VulnRemediation',
        component: () => import('@/views/VulnRemediation/index.vue'),
        meta: { title: '修复报告' },
      },
      {
        path: 'vuln-remediation/tasks',
        name: 'RemediationTasks',
        component: () => import('@/views/VulnRemediation/Tasks.vue'),
        meta: { title: '修复任务' },
      },
      {
        path: 'vuln-remediation/tasks/:id',
        name: 'RemediationTaskDetail',
        component: () => import('@/views/VulnRemediation/TaskDetail.vue'),
        meta: { title: '任务详情' },
      },
      {
        path: 'vuln-remediation/policies',
        name: 'RemediationPolicies',
        component: () => import('@/views/VulnRemediation/Policies.vue'),
        meta: { title: '修复策略' },
      },
      {
        path: 'vuln-scan-schedules',
        name: 'VulnScanSchedules',
        component: () => import('@/views/VulnList/ScanSchedules.vue'),
        meta: { title: '扫描计划' },
      },
      {
        path: 'vuln-scan-executions/:id',
        name: 'VulnScanExecutionDetail',
        component: () => import('@/views/VulnList/ExecutionDetail.vue'),
        meta: { title: '执行详情' },
      },
      {
        path: 'vuln-db-manage',
        name: 'VulnDBManage',
        component: () => import('@/views/System/VulnDBManage.vue'),
        meta: { title: '漏洞库管理' },
      },
      {
        path: 'sbom-import',
        name: 'SBOMImport',
        component: () => import('@/views/System/SBOMImport.vue'),
        meta: { title: 'SBOM 导入' },
      },
      // 病毒查杀
      {
        path: 'virus/scan',
        name: 'VirusScan',
        component: () => import('@/views/Virus/Scan.vue'),
        meta: { title: '病毒查杀' },
      },
      {
        path: 'virus/quarantine',
        name: 'VirusQuarantine',
        component: () => import('@/views/Virus/Quarantine.vue'),
        meta: { title: '文件隔离箱' },
      },
      // EDR 告警事件
      {
        path: 'detection/events',
        name: 'EDRAlerts',
        component: () => import('@/views/EDRAlerts/index.vue'),
        meta: { title: 'EDR 告警事件' },
      },
      // 检测规则管理
      {
        path: 'detection/rules',
        name: 'DetectionRules',
        component: () => import('@/views/Detection/Rules.vue'),
        meta: { title: '检测规则' },
      },
      // 威胁情报
      {
        path: 'threat-intel',
        name: 'ThreatIntel',
        component: () => import('@/views/ThreatIntel/index.vue'),
        meta: { title: '威胁情报' },
      },
      // 系统管理 — 迁移助手
      {
        path: 'system/migration',
        name: 'SystemMigration',
        component: () => import('@/views/System/Migration.vue'),
        meta: { title: '迁移助手', adminOnly: true },
      },
      // 系统管理 — 配置备份
      {
        path: 'system/backup',
        name: 'SystemBackup',
        component: () => import('@/views/System/Backup.vue'),
        meta: { title: '配置备份', adminOnly: true },
      },
      // 系统监控
      {
        path: 'system/host-monitor',
        name: 'HostMonitor',
        component: () => import('@/views/Monitoring/HostMonitor.vue'),
        meta: { title: '主机监控' },
      },
      {
        path: 'system/service-monitor',
        name: 'ServiceMonitor',
        component: () => import('@/views/Monitoring/ServiceMonitor.vue'),
        meta: { title: '后端服务' },
      },
      {
        path: 'system/service-alert',
        name: 'ServiceAlert',
        component: () => import('@/views/Monitoring/ServiceAlert.vue'),
        meta: { title: '服务告警' },
      },
      // 审计日志
      {
        path: 'audit-log',
        name: 'AuditLog',
        component: () => import('@/views/AuditLog/index.vue'),
        meta: { title: '审计日志', adminOnly: true },
      },
      // 容器集群
      {
        path: 'kube/clusters',
        name: 'KubeClusters',
        component: () => import('@/views/Kube/ClusterList.vue'),
        meta: { title: '集群管理' },
      },
      {
        path: 'kube/clusters/:id',
        name: 'KubeClusterDetail',
        component: () => import('@/views/Kube/ClusterDetail.vue'),
        meta: { title: '集群详情' },
      },
      {
        path: 'kube/alarms',
        name: 'KubeAlarms',
        component: () => import('@/views/Kube/Alarms.vue'),
        meta: { title: '容器告警' },
      },
      {
        path: 'kube/events',
        name: 'KubeEvents',
        component: () => import('@/views/Kube/Events.vue'),
        meta: { title: '安全事件' },
      },
      {
        path: 'kube/baseline',
        name: 'KubeBaseline',
        component: () => import('@/views/Kube/Baseline.vue'),
        meta: { title: '容器基线' },
      },
      {
        path: 'kube/baseline-rules',
        name: 'KubeBaselineRules',
        component: () => import('@/views/Kube/BaselineRules.vue'),
        meta: { title: '基线规则' },
      },
      {
        path: 'kube/whitelist',
        name: 'KubeWhitelist',
        component: () => import('@/views/Kube/Whitelist.vue'),
        meta: { title: '容器白名单' },
      },
      {
        path: 'kube/image-scan',
        name: 'ImageScan',
        component: () => import('@/views/Kube/ImageScan.vue'),
        meta: { title: '镜像扫描' },
      },
      // RASP 已弃用，由 Tetragon eBPF EDR 替代
      // 保留路由兼容旧书签，重定向到检测规则页
      {
        path: 'rasp/apps',
        redirect: '/detection/rules',
      },
      {
        path: 'rasp/config',
        redirect: '/detection/rules',
      },
      {
        path: 'rasp/alarms',
        redirect: '/alerts',
      },
      {
        path: 'rasp/vulns',
        redirect: '/vuln-list',
      },
    ],
  },
  // 404 错误页面
  {
    path: '/404',
    name: 'NotFound',
    component: () => import('@/views/Error/404.vue'),
    meta: { title: '页面不存在', public: true },
  },
  // 500 错误页面
  {
    path: '/500',
    name: 'ServerError',
    component: () => import('@/views/Error/500.vue'),
    meta: { title: '服务器错误', public: true },
  },
  // 捕获所有未匹配的路由
  {
    path: '/:pathMatch(.*)*',
    redirect: '/404',
  },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

// 路由守卫
router.beforeEach(async (to, _from, next) => {
  const authStore = useAuthStore()
  const { useSiteConfigStore } = await import('@/stores/site-config')
  const siteConfigStore = useSiteConfigStore()

  // 初始化站点配置（如果还未初始化）
  if (!siteConfigStore.config.site_name || siteConfigStore.config.site_name === '矩阵云安全平台') {
    await siteConfigStore.init()
  }

  // 更新页面标题
  if (to.meta.title) {
    document.title = `${to.meta.title} - ${siteConfigStore.siteName}`
  } else {
    document.title = siteConfigStore.siteName
  }

  // 公开路由（如登录页）直接放行
  if (to.meta.public) {
    // 如果已登录，重定向到首页
    if (authStore.isAuthenticated()) {
      next('/')
    } else {
      next()
    }
    return
  }

  // 需要认证的路由
  if (to.meta.requiresAuth) {
    if (!authStore.isAuthenticated()) {
      next('/login')
      return
    }
    // 初始化认证信息
    try {
      await authStore.initAuth()
    } catch (error) {
      console.error('认证初始化失败:', error)
      // 认证失败，跳转到登录页
      next('/login')
      return
    }

    // 管理员路由权限检查
    if (to.meta.adminOnly && authStore.user?.role !== 'admin') {
      next('/dashboard')
      return
    }
  }

  next()
})

// 路由错误处理
router.onError((error) => {
  console.error('路由错误:', error)
  // 如果是组件加载失败，跳转到 500 页面
  if (error.message && error.message.includes('Failed to fetch dynamically imported module')) {
    router.push('/500')
  }
})

export default router
