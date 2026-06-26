import {
  LayoutDashboard, Database, Bell, Bug, ShieldCheck, FileSearch,
  ScanLine, Boxes, Zap, Wrench, Settings, Activity, ScrollText,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";

// perms: 该菜单需要的权限码（任一命中即显示）。空数组表示所有登录用户可见。
export interface MenuItem { key: string; path: string; title: string; icon: LucideIcon; perms: string[]; }

export const MENUS: MenuItem[] = [
  { key: "dashboard", path: "/dashboard", title: "安全概览", icon: LayoutDashboard, perms: ["dashboard"] },
  { key: "assets", path: "/assets", title: "资产中心", icon: Database, perms: ["assets"] },
  { key: "alert-center", path: "/alert-center", title: "告警中心", icon: Bell, perms: ["alerts"] },
  { key: "vuln-management", path: "/vuln-management", title: "漏洞管理", icon: Bug, perms: ["vuln"] },
  { key: "baseline", path: "/baseline", title: "基线安全", icon: ShieldCheck, perms: ["baseline"] },
  { key: "fim", path: "/fim", title: "文件完整性", icon: FileSearch, perms: ["fim"] },
  { key: "virus", path: "/virus", title: "病毒查杀", icon: ScanLine, perms: ["virus"] },
  { key: "kube", path: "/kube", title: "容器集群", icon: Boxes, perms: ["kube"] },
  { key: "detection", path: "/detection", title: "威胁检测", icon: Zap, perms: ["detection"] },
  { key: "operations", path: "/operations", title: "运维中心", icon: Wrench, perms: ["operations"] },
  { key: "system", path: "/system", title: "系统管理", icon: Settings, perms: ["system_config", "user_manage"] },
  { key: "monitoring", path: "/monitoring", title: "系统监控", icon: Activity, perms: ["monitoring"] },
  { key: "audit", path: "/audit-log", title: "审计日志", icon: ScrollText, perms: ["audit_log"] },
];
