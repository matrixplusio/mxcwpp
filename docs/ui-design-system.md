# mxcwpp UI 设计系统 (Design System)

**目标**: 统一全平台 UI 语言, 卡片 / 间距 / 颜色 / 交互 一致.

## 1. 卡片组件清单 (统一)

| 用途 | 组件 | 路径 |
|---|---|---|
| **KPI 数值卡** (顶部 4-6 列) | `<StatCard>` | `ui/src/components/StatCard.vue` |
| **区块卡** (大图表 / 列表) | `<SectionCard>` (待建, 用 `.dashboard-card` 占位) | `ui/src/views/.../*.vue` |
| 原 `a-card size="small"` + 自定义 div | **禁用** | 全部替换为 StatCard |
| 原 `.baseline-stat-card` / `.monitor-stat-card` / 等 | **删除** | 全部替换为 StatCard |

### KPI StatCard 规格 (统一)

| 字段 | 规范 |
|---|---|
| min-height | **140px** (4 卡片高度一致) |
| padding | 18px |
| border-radius | 10px |
| border | 1px solid `--mxcwpp-border` |
| border-top | 2px solid (彩色, 区分类别) |
| 标题字号 | 11px, 大写, letter-spacing 0.5px |
| 数值字号 | 28px, font-weight 700 |
| value 区域 | flex 撑开 + 底部 tags/progress 贴底 |
| hover | translateY(-2px) + 边框变色 |
| countUp 动画 | ease-out cubic, 800ms |

颜色色板 (border-top + emphasis):

| 类别 | hex |
|---|---|
| 信息蓝 | `#3B82F6` |
| 成功绿 | `#22C55E` |
| 警示橙 | `#F59E0B` |
| 危险红 | `#EF4444` |
| 强调青 | `#06B6D4` |
| 紫色 (漏洞类) | `#8B5CF6` |
| 中性灰 | `#86909C` |

## 2. Grid + 间距规范

| 用途 | gutter |
|---|---|
| Row (4 卡片) | `[16, 16]` |
| Row (3 区块) | `[12, 12]` |
| Section row 间距 | margin-bottom: 16px |

a-col span 标准:
- 4 卡片 KPI: `:span="6"` (24/4)
- 5 卡片 KPI: `:span="4"` + 末尾 `:span="8"` 占满
- 6 卡片 KPI: `:span="4"` 各占 1/6
- 主图 + 副图: 左 `:span="10"` + 中 `:span="7"` + 右 `:span="7"`
- 双图: `:span="12"` + `:span="12"`

## 3. SectionCard 规格 (大区块)

CSS class `.dashboard-card`:
- background: `var(--mxcwpp-card-bg)`
- border: 1px solid `var(--mxcwpp-border)`
- border-radius: 10px
- padding 0 (头部 + body 内部 padding)

头部 `.card-header`:
- 高 48px
- padding: 0 16px
- flex justify-content: space-between
- `.card-title` font-size 14px, font-weight 600
- 右侧 action (按钮 / radio group / link)

body `.card-body`:
- padding: 16px
- 图表区: `style="height: 260px"` (统一)

## 4. 全局 CSS 变量 (已有, 使用)

```css
--mxcwpp-card-bg     /* 卡片背景 */
--mxcwpp-border      /* 边框 */
--mxcwpp-text-1      /* 主标题 */
--mxcwpp-text-2      /* 次级 */
--mxcwpp-text-3      /* 辅助 */
--mxcwpp-primary-bg  /* 主色 hover */
--mxcwpp-fill-1      /* 浅填充 */
```

## 5. 已迁移页面 (用 StatCard)

| 页面 | 状态 |
|---|---|
| Dashboard (Row 2 4 卡) | ✓ |
| Hosts (top 3 卡) | 部分 (distribution-card 待迁) |
| Kube/Baseline (4 卡) | ✓ |
| EDR/Events (5 卡) | ✓ |
| Monitoring/HostMonitor (6 卡) | ✓ |

## 6. 待迁移页面 (Phase 2)

grep `<a-card` 共 174 处. 优先按用户反馈页面迁:
- AlertCenter / AuditLog
- VulnList / VulnBulletins  
- Policies / PolicyGroups
- FIM Events / FIM Tasks
- Kube/Clusters / Kube/Events
- AssetFingerprint
- 各类详情页 (`*/Detail.vue`)

## 7. Tooltip 规范

echarts tooltip 必须设:
```js
tooltip: {
  trigger: 'item',
  confine: true,        // 限定在容器内
  appendToBody: true,   // 浮到 body, 不被 overflow:hidden 切
  backgroundColor: chartTheme.tooltipBg,
  borderColor: chartTheme.tooltipBorder,
  textStyle: { color: chartTheme.tooltipText, fontSize: 12 },
}
```

## 8. 主题色 / 暗色模式

变量已支持 light / dark 切换 (themeStore.isDark). 新加 CSS 必须用 `var(--mxcwpp-*)` 而非硬编码颜色.
