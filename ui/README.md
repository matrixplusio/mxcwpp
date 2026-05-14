# Matrix Cloud Security Platform - UI

前端 UI 项目，基于 Vue3 + TypeScript + Pinia + Ant Design Vue 构建。

## 技术栈

- **Vue 3** - 渐进式 JavaScript 框架
- **TypeScript** - 类型安全的 JavaScript 超集
- **Pinia** - Vue 的状态管理库
- **Ant Design Vue** - 企业级 UI 组件库
- **Vue Router** - Vue 官方路由管理器
- **Axios** - HTTP 客户端
- **Vite** - 下一代前端构建工具

## 项目结构

```
ui/
├── src/
│   ├── api/              # API 客户端封装
│   │   ├── client.ts     # Axios 实例配置
│   │   ├── types.ts      # API 类型定义
│   │   ├── hosts.ts      # 主机相关 API
│   │   ├── policies.ts   # 策略相关 API
│   │   ├── tasks.ts      # 任务相关 API
│   │   └── results.ts    # 结果相关 API
│   ├── layouts/          # 布局组件
│   │   └── BasicLayout.vue
│   ├── router/           # 路由配置
│   │   └── index.ts
│   ├── views/            # 页面组件
│   │   ├── Hosts/        # 主机管理页面
│   │   ├── Policies/      # 策略管理页面
│   │   └── Tasks/         # 任务管理页面
│   ├── App.vue           # 根组件
│   └── main.ts           # 入口文件
├── index.html            # HTML 模板
├── package.json          # 依赖配置
├── tsconfig.json         # TypeScript 配置
├── vite.config.ts        # Vite 配置
└── README.md            # 项目说明
```

## 开发指南

### 安装依赖

```bash
cd ui
npm install
```

### 启动开发服务器

```bash
npm run dev
```

开发服务器将在 `http://localhost:3000` 启动，并自动代理 API 请求到后端服务器（`http://localhost:8080`）。

### 构建生产版本

```bash
npm run build
```

构建产物将输出到 `dist/` 目录。

### 预览生产构建

```bash
npm run preview
```

## 功能页面

### 1. 主机列表 (`/hosts`)

- 显示所有注册的主机
- 支持按操作系统和状态筛选
- 显示主机基线得分（圆形进度条）
- 支持查看主机详情

### 2. 主机详情 (`/hosts/:hostId`)

- 显示主机基本信息
- 显示基线得分和统计信息
- 显示基线检查结果列表
- 支持按状态和严重级别筛选结果

### 3. 策略管理 (`/policies`)

- 显示所有策略列表
- 支持创建、编辑、删除策略
- 支持启用/禁用策略
- 支持按操作系统筛选

### 4. 策略详情 (`/policies/:policyId`)

- 显示策略基本信息
- 显示策略包含的所有规则
- 支持编辑策略

### 5. 扫描任务 (`/tasks`)

- 显示所有扫描任务
- 支持创建新的扫描任务
- 支持执行任务
- 支持按状态筛选任务

## API 集成

前端通过 `/api/v1` 路径访问后端 API，开发环境下通过 Vite 代理转发请求。

### API 端点

#### 主机管理 API
- `GET /api/v1/hosts` - 获取主机列表
- `GET /api/v1/hosts/:hostId` - 获取主机详情
- `GET /api/v1/hosts/:hostId/metrics` - 获取主机监控数据
- `GET /api/v1/hosts/status-distribution` - 获取主机状态分布
- `GET /api/v1/hosts/risk-distribution` - 获取主机风险分布

#### 策略管理 API
- `GET /api/v1/policies` - 获取策略列表
- `GET /api/v1/policies/:policyId` - 获取策略详情
- `POST /api/v1/policies` - 创建策略
- `PUT /api/v1/policies/:policyId` - 更新策略
- `DELETE /api/v1/policies/:policyId` - 删除策略
- `GET /api/v1/policies/:policyId/statistics` - 获取策略统计信息

#### 任务管理 API
- `GET /api/v1/tasks` - 获取任务列表
- `GET /api/v1/tasks/:taskId` - 获取任务详情
- `POST /api/v1/tasks` - 创建任务
- `POST /api/v1/tasks/:taskId/run` - 执行任务

#### 检测结果 API
- `GET /api/v1/results` - 获取检测结果列表
- `GET /api/v1/results/:resultId` - 获取检测结果详情
- `GET /api/v1/results/host/:hostId/score` - 获取主机基线得分
- `GET /api/v1/results/host/:hostId/summary` - 获取主机基线摘要

#### Dashboard API
- `GET /api/v1/dashboard/stats` - 获取 Dashboard 统计数据

#### 资产数据 API
- `GET /api/v1/assets/processes` - 获取进程列表
- `GET /api/v1/assets/ports` - 获取端口列表
- `GET /api/v1/assets/users` - 获取账户列表

## 开发规范

### 代码风格

- 使用 TypeScript 进行类型检查
- 使用 Composition API（`<script setup>`）
- 组件命名使用 PascalCase
- 文件命名使用 kebab-case

### 组件规范

- 页面组件放在 `views/` 目录
- 可复用组件放在 `components/` 目录
- 使用 Ant Design Vue 组件库

### API 调用

- 所有 API 调用通过 `src/api/` 目录下的封装函数
- 使用 TypeScript 类型定义确保类型安全
- 统一错误处理在 `api/client.ts` 中实现

## 部署

### 开发环境

开发环境使用 Vite 开发服务器，配置了 API 代理。

### 生产环境

1. 构建前端项目：
   ```bash
   npm run build
   ```

2. 将 `dist/` 目录部署到 Web 服务器（如 Nginx）

3. 配置 Nginx 反向代理：
   ```nginx
   server {
       listen 80;
       server_name your-domain.com;
       
       # 前端静态文件
       location / {
           root /path/to/dist;
           try_files $uri $uri/ /index.html;
       }
       
       # API 代理
       location /api {
           proxy_pass http://localhost:8080;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
       }
   }
   ```

## 参考

- [Vue 3 文档](https://vuejs.org/)
- [Ant Design Vue 文档](https://antdv.com/)
- [Vite 文档](https://vitejs.dev/)
- [TypeScript 文档](https://www.typescriptlang.org/)
