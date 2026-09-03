# MXCWPP-PLATFORM Web (React)

P1 地基 + 安全概览。技术栈：Next.js 15 + Tailwind + Framer Motion + Zustand + TanStack Query + ECharts。

## 开发

```bash
pnpm install
cp .env.local.example .env.local   # 设 API_TARGET 指向后端
pnpm dev                            # http://localhost:5173
```

## 与现有 ui/ 关系

- 现有 Vue 工程位于 `../ui/`，原地保留，本工程不影响它。
- 回切：`git checkout dev` 或部署指向 `ui/`。

## 范围

P1 仅安全概览实装，其余 12 菜单为占位页。后续 P2(Landing)/P3+(各模块)。

## 脚本

- `pnpm dev` — 开发服务器 (端口 5173)
- `pnpm build` — 生产构建
- `pnpm lint` — 类型检查 (tsc)
- `pnpm test` — 单元测试 (vitest)
- `pnpm test:e2e` — Playwright 端到端测试 (全路由渲染/无错/鉴权断言)
- `pnpm test:e2e:ui` — Playwright UI 模式

## 端到端测试 (Playwright)

复用已运行的开发服务器 (`http://localhost:5173`)，先确保 `pnpm dev` 已启动。

凭证从环境变量读取，**禁止硬编码**：`E2E_USERNAME`(默认 `admin`)、`E2E_PASSWORD`(必填)。

```bash
pnpm exec playwright install chromium   # 首次安装浏览器
E2E_PASSWORD='你的密码' pnpm test:e2e
```

测试登录一次并复用会话 (`e2e/.auth/user.json`)，逐条遍历全部控制台子路由，断言：未跳转登录页(鉴权生效)、无 Next.js 运行时错误浮层、页面正确渲染、无控制台报错。
