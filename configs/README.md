# configs

本地开发与源码运行用的配置样例，以及随二进制一起编译进去的检测规则。
容器化部署用的模板在 [`deploy/config/`](../deploy/config/)，由 `deploy/deploy.sh` 渲染，不在这里。

## 服务配置

| 文件 | 谁读取 | 说明 |
|---|---|---|
| `server.yaml.example` | Manager、AgentCenter、Consumer、Scanner | 复制为 `configs/server.yaml`（不入库）后使用，是这几个服务的默认配置路径 |
| `engine.yaml` | Engine | 默认配置路径 `-config configs/engine.yaml` |
| `vulnsync.yaml` | VulnSync | 默认配置路径 `-config configs/vulnsync.yaml` |
| `llmproxy.yaml` | —— | **LLMProxy 目前不读取这个文件**，配置全部来自环境变量 `MXCWPP_LLMPROXY_*`；文件只说明有哪些配置项 |
| `agent.yaml.example` | Agent | Agent 的配置项参考；Agent 默认依赖构建时嵌入的参数，不需要配置文件 |
| `air/*.toml` | Air | 本地热重载开发（`deploy/docker-compose.dev.yml`）用 |

`internal/deploy` 下的测试会用各服务自己的加载函数读取上面的样例，样例与代码对不上时测试失败。

## 检测规则

| 目录 | 用途 |
|---|---|
| `rules/` | 服务端内置检测规则，Manager 首次启动时导入数据库；以 Go 包形式嵌入（`embed.go`） |
| `agent-rules/` | Agent 端 EDR 规则，编译进 Agent 二进制；以 Go 包形式嵌入 |

这两个目录被代码按包路径引用，移动时要同步修改导入路径。
