import type { Component } from 'vue'
import {
  DashboardOutlined,
  DatabaseOutlined,
  SafetyOutlined,
  SettingOutlined,
  FileSearchOutlined,
  AlertOutlined,
  MonitorOutlined,
  BugOutlined,
  AuditOutlined,
  CloudServerOutlined,
  ThunderboltOutlined,
  ToolOutlined,
  SecurityScanOutlined,
} from '@ant-design/icons-vue'

export interface MenuItem {
  key: string
  title: string
  icon?: Component
  route?: string
  children?: MenuItem[]
  adminOnly?: boolean
}

/**
 * 侧边栏菜单配置 — 参考 Elkeid 导航结构
 * 手风琴模式: 同一时间只展开一个子菜单
 */
export const menuConfig: MenuItem[] = [
  {
    key: 'dashboard',
    title: '安全概览',
    icon: DashboardOutlined,
    route: '/dashboard',
  },
  {
    key: 'assets',
    title: '资产中心',
    icon: DatabaseOutlined,
    children: [
      { key: 'hosts', title: '主机列表', route: '/hosts' },
      { key: 'asset-fingerprint', title: '资产指纹', route: '/asset-fingerprint' },
      { key: 'business-lines', title: '业务线管理', route: '/business-lines' },
    ],
  },
  {
    key: 'alert-center',
    title: '告警中心',
    icon: AlertOutlined,
    children: [
      { key: 'alerts', title: '告警列表', route: '/alerts' },
      { key: 'whitelist', title: '白名单', route: '/whitelist' },
    ],
  },
  {
    key: 'vuln-management',
    title: '漏洞管理',
    icon: BugOutlined,
    children: [
      { key: 'vuln-bulletins', title: '漏洞通报', route: '/vuln-bulletins' },
      { key: 'vuln-list', title: '漏洞列表', route: '/vuln-list' },
      { key: 'vuln-scan-schedules', title: '扫描计划', route: '/vuln-scan-schedules' },
      { key: 'vuln-remediation', title: '修复报告', route: '/vuln-remediation' },
      { key: 'remediation-tasks', title: '修复任务', route: '/vuln-remediation/tasks' },
      { key: 'remediation-policies', title: '修复策略', route: '/vuln-remediation/policies' },
      { key: 'vuln-db-manage', title: '漏洞库管理', route: '/vuln-db-manage' },
      { key: 'vuln-data-sources', title: '漏洞源管理', route: '/vuln-data-sources' },
      { key: 'sbom-import', title: 'SBOM 导入', route: '/sbom-import' },
    ],
  },
  {
    key: 'baseline',
    title: '基线安全',
    icon: SafetyOutlined,
    children: [
      { key: 'policies', title: '基线检查', route: '/policies' },
      { key: 'policy-groups', title: '策略组管理', route: '/policy-groups' },
      { key: 'tasks', title: '任务执行', route: '/tasks' },
      { key: 'baseline-fix', title: '基线修复', route: '/baseline/fix' },
      { key: 'baseline-fix-history', title: '修复历史', route: '/baseline/fix-history' },
    ],
  },
  {
    key: 'fim',
    title: '文件完整性',
    icon: FileSearchOutlined,
    children: [
      { key: 'fim-dashboard', title: 'FIM 概览', route: '/fim/dashboard' },
      { key: 'fim-policies', title: 'FIM 策略', route: '/fim/policies' },
      { key: 'fim-events', title: 'FIM 事件', route: '/fim/events' },
      { key: 'fim-tasks', title: 'FIM 任务', route: '/fim/tasks' },
      { key: 'fim-baselines', title: '基线管理', route: '/fim/baselines' },
    ],
  },
  {
    key: 'virus',
    title: '病毒查杀',
    icon: SecurityScanOutlined,
    children: [
      { key: 'virus-scan', title: '病毒扫描', route: '/virus/scan' },
      { key: 'virus-quarantine', title: '文件隔离箱', route: '/virus/quarantine' },
    ],
  },
  {
    key: 'kube',
    title: '容器集群',
    icon: CloudServerOutlined,
    children: [
      { key: 'kube-clusters', title: '集群管理', route: '/kube/clusters' },
      { key: 'kube-alarms', title: '安全告警', route: '/kube/alarms' },
      { key: 'kube-events', title: '安全事件', route: '/kube/events' },
      { key: 'kube-baseline', title: '基线检查', route: '/kube/baseline' },
      { key: 'kube-baseline-rules', title: '基线规则', route: '/kube/baseline-rules' },
      { key: 'kube-whitelist', title: '告警白名单', route: '/kube/whitelist' },
      { key: 'kube-image-scan', title: '镜像扫描', route: '/kube/image-scan' },
    ],
  },
  {
    key: 'detection',
    title: '威胁检测',
    icon: ThunderboltOutlined,
    children: [
      { key: 'edr-events', title: 'EDR 事件', route: '/edr/events' },
      { key: 'detection-rules', title: '检测规则', route: '/detection/rules' },
      { key: 'threat-intel', title: '威胁情报', route: '/threat-intel' },
      { key: 'storylines', title: '攻击故事线', route: '/storylines' },
      { key: 'hunting', title: '威胁狩猎', route: '/hunting' },
      { key: 'anomaly', title: 'ML 异常检测', route: '/anomaly' },
      { key: 'bde', title: '行为基线', route: '/bde' },
      { key: 'host-isolation', title: '主机隔离', route: '/host-isolation' },
    ],
  },
  {
    key: 'operations',
    title: '运维中心',
    icon: ToolOutlined,
    children: [
      { key: 'system-components', title: '组件管理', route: '/system/components', adminOnly: true },
      { key: 'system-install', title: '安装配置', route: '/system/install' },
      { key: 'system-reports', title: '报告管理', route: '/system/reports' },
      { key: 'system-task-report', title: '任务报告', route: '/system/task-report' },
      { key: 'inspection', title: '运维巡检', route: '/system/inspection' },
      { key: 'system-backup', title: '配置备份', route: '/system/backup', adminOnly: true },
      { key: 'system-migration', title: '迁移助手', route: '/system/migration', adminOnly: true },
    ],
  },
  {
    key: 'system',
    title: '系统管理',
    icon: SettingOutlined,
    children: [
      { key: 'users', title: '用户管理', route: '/users', adminOnly: true },
      { key: 'rbac', title: '角色权限', route: '/rbac', adminOnly: true },
      { key: 'system-notification', title: '通知管理', route: '/system/notification', adminOnly: true },
      { key: 'system-settings', title: '基本设置', route: '/system/settings', adminOnly: true },
      { key: 'system-data-retention', title: '数据保留策略', route: '/system/data-retention', adminOnly: true },
      { key: 'system-feature-flags', title: '功能开关', route: '/system/feature-flags', adminOnly: true },
      { key: 'system-collection', title: '平台授权', route: '/system/collection' },
    ],
  },
  {
    key: 'monitoring',
    title: '系统监控',
    icon: MonitorOutlined,
    children: [
      { key: 'host-monitor', title: '主机监控', route: '/system/host-monitor' },
      { key: 'service-monitor', title: '后端服务', route: '/system/service-monitor' },
      { key: 'service-alert', title: '服务告警', route: '/system/service-alert' },
    ],
  },
  {
    key: 'audit',
    title: '审计日志',
    icon: AuditOutlined,
    route: '/audit-log',
    adminOnly: true,
  },
]

/**
 * 根据用户角色过滤菜单项，移除 adminOnly 项（非 admin 用户）
 * 如果一个父级的所有 children 都被过滤掉，则隐藏该父级
 */
export function filterMenuByRole(items: MenuItem[], role: string): MenuItem[] {
  return items
    .filter((item) => !item.adminOnly || role === 'admin')
    .map((item) => {
      if (!item.children) return item
      const children = item.children.filter((child) => !child.adminOnly || role === 'admin')
      if (children.length === 0) return null
      return { ...item, children }
    })
    .filter((item): item is MenuItem => item !== null)
}

/**
 * 扁平化菜单, 生成 key -> route 映射表
 */
export function buildRouteMap(items: MenuItem[]): Record<string, string> {
  const map: Record<string, string> = {}
  for (const item of items) {
    if (item.route) {
      map[item.key] = item.route
    }
    if (item.children) {
      Object.assign(map, buildRouteMap(item.children))
    }
  }
  return map
}

/**
 * 根据当前路径, 反查选中的 menu key 和展开的 submenu key
 */
export function resolveMenuKeys(path: string): { selectedKey: string; openKey: string } {
  let best = { selectedKey: '', openKey: '', matchLen: 0 }

  for (const item of menuConfig) {
    if (item.route === path) {
      return { selectedKey: item.key, openKey: '' }
    }
    if (item.children) {
      for (const child of item.children) {
        if (child.route && path.startsWith(child.route) && child.route.length > best.matchLen) {
          best = { selectedKey: child.key, openKey: item.key, matchLen: child.route.length }
        }
      }
    }
  }

  return { selectedKey: best.selectedKey, openKey: best.openKey }
}

/**
 * 路由映射表 (由 menuConfig 自动生成)
 */
export const routeMap = buildRouteMap(menuConfig)
