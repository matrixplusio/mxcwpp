# MXCWPP-PLATFORM 前端 UI 开发规范（约束 + 指导）

> **这份文档是前端开发的唯一事实源。** 新建任何模块/页面前先读它，照它做即可与全站一致。看完应能直接动工，不需再问"用什么组件、什么间距、什么色、怎么取数"。

**主对标**：Phenomenon Studio 的 **Isora**（GRC 合规平台）—— 蓝 / 白 / 干净企业风、数据表带状态 pill、大留白、柔阴影、浮动面板。结构精髓参考 CareOps（浮动白面板 + pill 导航 + 圆角图表）。**亮色蓝白为主**。不要安全大屏 / 赛博朋克 / 霓虹 / 满屏红 / 重渐变 / 噪点。

技术栈：Next.js 15 App Router（client SPA）+ TS + Tailwind + Framer Motion + Zustand + TanStack Query + axios + ECharts + lucide-react。

---

## 0. 黄金法则（违反即返工）

1. **不裸用颜色值**，只用 token（`bg-primary` `text-muted` `border-border`…）。图表色只用 `echartsTheme` 导出的常量。
2. **不直接调 axios**，只用 `lib/api/<module>.ts` 封装的 `get/post/put/del`；响应走统一 `{code,message,data}` 契约。
3. **列表页/设置页/详情抽屉 照模板抄**（见 §5），不要每页自创布局。
4. **危险操作必须二次确认**（删除/重启/迁移…），用 `ConfirmDialog`。
5. **告警级别配色全站统一**：严重=红 `#E5484D` / 高危=橙 `#F59E0B` / 中危=蓝 `#2563EB` / 低危=灰 `#94A3B8`（用 `severityColors` / `SeverityTag`）。
6. **三态必处理**：loading / error / empty，列表空用 `EmptyState`。
7. **每个 API 调用 try/catch**（或 TanStack Query 的 isError），错误用 toast，不静默。
8. **不重新发明后端契约**：端点/字段名镜像现有 Vue（见各模块附录 / 源 `ui/src/api`）。

---

## 1. 设计 Token（`tailwind.config.ts`）

### 色板
| 角色 | token | 值 |
|---|---|---|
| 画布背景 | （body 渐变） | `#F5F8FC→#F6F8FB→#F3F6FB` |
| 卡片/面 | `surface` | `#FFFFFF` |
| 次级填充/表头 | `surface-muted` | `#F8FAFC` |
| 浅填充/hover | `bg` | `#F6F8FB` |
| 发丝边框 | `border` | `#E9EDF3` |
| 强分隔 | `border-strong` | `#DCE2EA` |
| 主色 | `primary` / `primary-hover` | `#2563EB` / `#1D4ED8` |
| 渐变副色 | `accent` | `#4F7DF9` |
| 成功/警告/危险/信息 | `success`/`warning`/`danger`/`info` | `#16A34A`/`#F59E0B`/`#E5484D`/`#0EA5E9` |
| 主文字/次/弱 | `ink`/`muted`/`faint` | `#0F172A`/`#64748B`/`#94A3B8` |

### 圆角 / 阴影 / 间距
- 圆角：`rounded-panel`(20) 大面板 · `rounded-card`(16) 卡片 · `rounded-control`(10) 按钮/输入/小块 · `rounded-full` 胶囊/标签。
- 阴影：`shadow-card`（卡片默认）· `shadow-hover`（hover）· `shadow-float`（弹层/登录 mockup）。
- 间距 4px 栅格：4/8/12/16/**24**/32/48。卡片内边距 `p-5`~`p-6`；区块间距 `space-y-5`/`gap-5`；页面内边距 `p-6 lg:p-8`。

### 字体
Inter。标题 700–800 `tracking-tight`；大数字 `tabular-nums` 700；区块小标题 13/600 muted；正文 14；辅助 12–13 muted。

---

## 2. 组件库目录（`src/components/ui`）

> 用现成的，不要重造。缺的按本规范补到 `ui/` 再用。

### 已有
| 组件 | 文件 | 用途 / 关键 props |
|---|---|---|
| `Button` | ui/Button.tsx | `variant: primary\|ghost\|danger`；主按钮渐变 `from-primary to-accent` |
| `Card` / `CardHeader` | ui/Card.tsx | 卡片容器 + 头部（`title`,`extra`） |
| `StatCard` | ui/StatCard.tsx | KPI 卡（`label,value,icon,tone`），渐变图标 chip + 大数字 |
| `ScoreGauge` | dashboard/ScoreGauge.tsx | 0–100 环形评分（≥80 绿/≥60 橙/<60 红） |
| `ChartCard` | ui/ChartCard.tsx | ECharts 容器（`title,option,height,extra`） |
| `SeverityTag` | ui/Tag.tsx | 告警级别 pill（`level: Severity`） |
| `PageHeader` | ui/PageHeader.tsx | 页标题区（`title,desc,extra`） |
| `EmptyState` | ui/EmptyState.tsx | 空状态 |
| `BrandMark` | ui/BrandMark.tsx | 品牌图标（渐变盾） |

### 待建 kit（模块页必需，建好登记到本表）
| 组件 | 文件 | 用途 / 关键 props |
|---|---|---|
| `DataTable` | ui/DataTable.tsx | 通用表格：`columns`(key/title/align/render?)、`rows`、`rowKey`、`loading`、`empty`、`onRowClick?`；表头 `surface-muted` 大写 muted、行 hover、发丝分隔、py-3 |
| `Pagination` | ui/Pagination.tsx | `page,pageSize,total,onChange`；右对齐 ghost 圆角按钮 |
| `Drawer` | ui/Drawer.tsx | 右侧详情抽屉：`open,onClose,title,width?`；遮罩 + framer 滑入；放详情/编辑表单 |
| `Modal` | ui/Modal.tsx | 居中弹窗：`open,onClose,title,footer?`；放小表单/确认 |
| `ConfirmDialog` | ui/ConfirmDialog.tsx | 危险操作二次确认：`open,title,desc,danger?,onConfirm,onCancel` |
| `FilterBar` | ui/FilterBar.tsx | 列表筛选行容器（横向排列 SearchInput/Select），右侧放主操作按钮 |
| `SearchInput` | ui/SearchInput.tsx | 带放大镜图标输入，`value,onChange,placeholder` |
| `Select` | ui/Select.tsx | 原生 select 封装（统一样式），`options,value,onChange` |
| `Input`/`Textarea` | ui/Input.tsx | 表单输入，统一焦点环 `focus:ring-4 focus:ring-primary/10` |
| `FormField` | ui/FormField.tsx | `label + 控件 + error` 垂直组 |
| `Switch` | ui/Switch.tsx | 开关，`checked,onChange` |
| `Tabs` | ui/Tabs.tsx | pill tab，`items:{key,label},active,onChange` |
| `StatusTag` | ui/Tag.tsx | 通用状态 pill：`tone: success\|warning\|danger\|info\|neutral` + 文案；用于 online/offline、active/inactive、任务状态等 |
| `Toast` | ui/toast.ts | 全局提示 `toast.success/error(msg)`（轻量，挂 Providers） |

### 组件硬规矩
- 纯展示组件不取数；数据从 props 进。
- 所有可点行/项有 hover 态。
- 图标统一 lucide-react，尺寸 16–20。
- 颜色只用 token；语义状态用 `StatusTag`/`SeverityTag`。

---

## 3. 数据 / API 约定

### 文件结构（每个模块一套）
```
src/lib/api/<module>.ts      // 该模块所有端点，导出 <module>Api 对象
src/lib/api/types.ts         // 共享类型（小模块）；大模块可 types/<module>.ts
src/app/(console)/<route>/page.tsx          // 列表/主页
src/app/(console)/<route>/<sub>/page.tsx     // 子页
src/components/<module>/...  // 该模块专属展示组件
```

### API 模块写法
```ts
import { get, post, put, del } from "./client";  // del 需在 client 补充(见下)
import type { User, Paged } from "./types";
export const systemApi = {
  listUsers: (params: { page: number; page_size: number; username?: string; role?: string; status?: string }) =>
    get<Paged<User>>("/users", params),
  createUser: (body: Partial<User>) => post<User>("/users", body),
  updateUser: (id: number, body: Partial<User>) => put<User>(`/users/${id}`, body),
  deleteUser: (id: number) => del<void>(`/users/${id}`),
};
```
- `client.ts` 已有 `get/post`；**补 `put/del`**（同写法）后纳入本规范。
- 分页参数统一 `page` / `page_size`；分页响应统一 `Paged<T> = { items: T[]; total: number }`（以现有后端实际为准，镜像之）。
- `/v2/` 前缀路由由 `resolveBaseURL` 自动处理，照常传 `/v2/...`。

### 取数（TanStack Query）
- 列表：`useQuery({ queryKey: ["users", params], queryFn: () => systemApi.listUsers(params) })`。
- 变更：`useMutation`，成功后 `queryClient.invalidateQueries` + `toast.success`，失败 `toast.error(e.message)`。
- queryKey 命名：`[模块, 子资源, 关键参数]`。

### 三态
```tsx
{isLoading && <TableSkeleton/* 或 文案 */ />}
{isError && <div className="text-danger">数据加载失败，请重试</div>}
{data && data.items.length === 0 && <EmptyState title="暂无数据" />}
{data && data.items.length > 0 && <DataTable .../>}
```

---

## 4. 交互约定

- **危险操作**（删除/重启/迁移/恢复）→ `ConfirmDialog`，确认按钮 `variant="danger"`。
- **创建/编辑** → `Drawer`（字段多）或 `Modal`（字段少）内放表单；保存成功关闭 + toast + 刷新列表。
- **表单校验**：必填即时提示，错误显示在 `FormField` 下方红字；提交失败保留输入。
- **反馈**：所有写操作结果走 `toast`。
- **时间**：列表直接显示后端字符串（如 `2026-06-17 00:43:53`），右对齐 `tabular-nums faint`。
- **状态/级别**：一律 pill；级别用 `SeverityTag`，其他状态用 `StatusTag`（在线=success、离线=neutral/danger 视语义、active=success、inactive=neutral、任务 success/failed/running 对应 success/danger/info）。
- **动效**：克制。页面进入 `motion` 渐显（layout 已统一包）；卡片 hover 上浮；抽屉/弹窗滑入淡入；无循环动画。

---

## 5. 页面模板（直接套）

### 5.1 列表页（最常用：用户/通知/审计/备份/组件…）
布局：`PageHeader(title,desc,extra=主操作按钮)` → `FilterBar(筛选 + 右侧操作)` → `Card{ DataTable + Pagination }` → `Drawer/Modal`(详情/编辑) + `ConfirmDialog`(删除)。
```tsx
"use client";
export default function UsersPage() {
  const [params, setParams] = useState({ page: 1, page_size: 20, username: "", role: "", status: "" });
  const { data, isLoading, isError } = useQuery({ queryKey: ["users", params], queryFn: () => systemApi.listUsers(params) });
  // columns: [{key:'username',title:'用户名'}, {key:'role',title:'角色',render:(r)=><StatusTag .../>}, ... {key:'actions',title:'操作',render:(r)=>编辑/删除}]
  return (
    <>
      <PageHeader title="用户管理" desc="平台用户与角色" extra={<Button onClick={openCreate}>新建用户</Button>} />
      <div className="space-y-4">
        <FilterBar>
          <SearchInput .../><Select .../><Select .../>
        </FilterBar>
        <Card>
          <DataTable columns={columns} rows={data?.items ?? []} rowKey="id" loading={isLoading} />
          <Pagination page={params.page} pageSize={params.page_size} total={data?.total ?? 0} onChange={(p)=>setParams({...params,page:p})} />
        </Card>
      </div>
      {/* <Drawer/Modal 编辑> <ConfirmDialog 删除> */}
    </>
  );
}
```

### 5.2 设置/表单页（基本设置/数据保留/功能开关）
布局：`PageHeader` → 一个或多个 `Card`（每段一卡，`CardHeader` 当段标题）→ 卡内 `FormField` 垂直排 → 底部/卡内 `Button` 保存。`useQuery` 取当前值填表，`useMutation` 保存。

### 5.3 主从页（RBAC 角色权限）
布局：左 `Card`（角色列表，选中高亮）+ 右 `Card`（该角色权限，按 module 分组 checkbox 网格）。选角色 → 取权限 → 改 → 保存。

### 5.4 Tab 分组页（报告管理：overview/antivirus/...）
`PageHeader(extra=RangePicker)` → `Tabs` → 各 tab 内容（KPI 卡 + 图表，复用 dashboard 组件）。

### 5.5 向导页（迁移助手）
`PageHeader` → 步骤指示 → 分步 `Card`（连接 → 选范围 → 执行/进度）→ 任务列表（DataTable + 进度条）。

### 5.6 主从/详情（组件管理：组件→版本→包）
列表页 + `Drawer` 内展开版本/包的嵌套表 + 上传/发布操作。

---

## 6. 路由 / 菜单约定

- 控制台页面放 `src/app/(console)/<route>/page.tsx`；子页 `<route>/<sub>/page.tsx`。
- 一级菜单在 `src/config/menu.ts`（13 项，勿改命名/路径，镜像后端）。
- 二级菜单（子页导航）：模块内用 `Tabs` 或左侧子导航；与现有 Vue 子路由对齐（见附录）。
- 路由命名、端点全部镜像现有 Vue，后端零改。

---

## 7. 新模块开发 Checklist

1. [ ] 读本文档 + 该模块附录（端点/字段/列/筛选/动作）。
2. [ ] `lib/api/<module>.ts`：按附录端点写 `<module>Api`（镜像契约）。
3. [ ] `types.ts`：补该模块实体类型（字段名镜像后端）。
4. [ ] 缺的 kit 组件先补到 `ui/`（登记 §2 表）。
5. [ ] 按 §5 对应模板写页面，复用组件，不自创布局。
6. [ ] 三态 + 危险确认 + toast + 校验齐全。
7. [ ] 配色/间距/圆角全用 token；级别用 severity 配色。
8. [ ] `pnpm lint` 过；起 dev 截图自查（对照本规范与 Isora）。
9. [ ] commit（中文、无 AI 字眼）。

---

## 附录 A：系统管理（system）契约
子页：用户管理 `/system/users`、角色权限 `/system/rbac`、通知管理 `/system/notifications`、基本设置 `/system/settings`、数据保留 `/system/retention`、功能开关 `/system/feature-flags`（路径以本工程 `(console)/system/*` 重整，菜单 key=system）。
- 用户：`GET/POST /users`，`PUT/DELETE /users/{id}`。User{id,username,email,role(admin|user),status(active|inactive),last_login,created_at,updated_at}。列：username/email/role/status/last_login/操作；筛选 username/role/status。
- RBAC：`GET /rbac/permissions`、`GET /rbac/roles`、`GET/PUT /rbac/roles/{role}/permissions`。Permission{id,code,name,module}；Role{code,name,permissions[]}。主从页。
- 通知：`GET/POST /notifications`、`GET/PUT/DELETE /notifications/{id}`、`POST /notifications/test`。Notification{id,name,notify_category,enabled,type(lark|webhook),severities[],scope,scope_value,config{webhook_url,secret,user_notes}}。列：name/category/enabled(Switch)/severities/scope/type/操作；筛选 keyword/enabled。
- 基本设置：`GET/PUT /system-config/site`、`POST /system-config/upload-logo`、`GET/PUT /system-config/alert`。SiteConfig{site_name,site_logo,site_domain,backend_url}。设置页。
- 数据保留：`GET /retention-policies`、`PUT /retention-policies/{chTable}`。RetentionPolicy{id,ch_table,display_name,description,retention_days,updated_by,updated_at}。列表+行内编辑。
- 功能开关：`GET /feature-flags`、`PUT /feature-flags/{key}`。FeatureFlag{id,key,value,default_value,description,updated_by,updated_at}。列表+编辑。

## 附录 B：审计日志（audit）契约
单页 `/audit-log`。`GET /audit-logs`(page,page_size,username,resource_type,action)。AuditLog{id,username,action(POST|PUT|DELETE),resource_type,resource_id,path,ip,status_code,created_at}。列：created_at/username/action(pill 绿POST/蓝PUT/红DELETE)/resource(type+id)/path/ip/status_code(pill)；筛选 username/resource_type(select)/action(select)。只读。

## 附录 C：运维中心（operations）契约
子页：组件管理 `/operations/components`、运维巡检 `/operations/inspection`、配置备份 `/operations/backup`、迁移助手 `/operations/migration`、报告管理 `/operations/reports`、任务报告 `/operations/task-report`、安装配置 `/operations/install`（按 `(console)/operations/*` 重整）。
- 组件：`GET/POST /components`、`GET/DELETE /components/{id}`、版本 `/components/{id}/versions`（GET/POST）、`PUT .../set-latest`、`DELETE .../{versionId}`、包 `POST .../packages`、`DELETE /packages/{id}`、`GET /components/plugin-status`、`POST /components/agent/push-update`、`GET /components/push-records`、`POST /components/plugins/broadcast`。Component/ComponentVersion/ComponentPackage/PluginSyncStatus/ComponentPushRecord（字段见调查）。Tab 过滤 all/agent/plugin/dependency；主从详情 Drawer。
- 巡检：`GET /inspection/overview`、`POST /inspection/hosts/{id}/restart-agent`、`POST /inspection/batch-restart-agent`。InspectionSummary + InspectionHostItem。汇总卡 + 列表 + 重启(确认)。
- 备份：`GET/POST /system/backup`、`POST /system/backup/{id}/restore`、`DELETE /system/backup/{id}`、`GET/PUT /system/backup/config`。Backup{type,status,scope,remark,file_size,created_by,created_at}。列表 + 创建/恢复(确认)/删除(确认) + 自动备份配置。
- 迁移：`POST /system/migration/test-connection`、`GET/POST /system/migration/jobs`、`GET /.../{id}`、`POST /.../{id}/cancel`。MigrationJob{...,status,progress,...}。向导 + 任务列表。
- 报告：`GET /reports/stats`(date range)。Tab 页 + RangePicker + KPI/图表。
- 任务报告：`GET /task-reports`。列表页。

> 字段细节以 `ui/src/api/*` 与后端实际为准；本附录为索引。开发某页前回查对应 Vue 源确认。
