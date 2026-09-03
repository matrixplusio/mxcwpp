# Matrix Cloud Security Platform - Server 配置模板
# 所有 __XXX__ 占位符由 deploy.sh 或 dev-docker-start.sh 从 .env 文件替换
# 如需新增配置项，在此模板添加占位符，并在 .env.example 和 deploy.sh 中同步

server:
  grpc:
    host: "0.0.0.0"
    port: __GRPC_PORT__
  http:
    host: "0.0.0.0"
    port: __SERVER_HTTP_PORT__
  jwt_secret: "__JWT_SECRET__"
  manager_addr: "__MANAGER_ADDR__"
  instance_id: "__INSTANCE_ID__"
  cors_origins: __CORS_ORIGINS__
  # Manager↔AgentCenter 管理面鉴权密钥（deploy.sh 从 .env INTERNAL_SECRET 替换；留空自动生成）。
  # AC 管理端口绑定 0.0.0.0 时必填且需足够强度，否则 fail-closed 拒绝启动。
  internal_secret: "__INTERNAL_SECRET__"
  # 生产安全加固（依赖 Redis）：安全响应头(含 HSTS，UI 走 443 HTTPS)、登录限流、JWT 黑名单。
  security:
    headers:
      enabled: true
      hsts: true
    login_rate_limit:
      enabled: true
      rps: 10
      burst: 5
    jwt_blacklist:
      enabled: true

database:
  type: "mysql"
  mysql:
    host: "__MYSQL_HOST__"
    port: __MYSQL_PORT__
    user: "__MYSQL_USER__"
    password: "__MYSQL_PASSWORD__"
    database: "__MYSQL_DATABASE__"
    charset: "utf8mb4"
    parse_time: true
    loc: "Asia/Shanghai"
    max_idle_conns: __DB_MAX_IDLE_CONNS__
    max_open_conns: __DB_MAX_OPEN_CONNS__
    conn_max_lifetime: "__DB_CONN_MAX_LIFETIME__"

redis:
  # 单节点模式（sentinel: false 时生效）
  addr: "__REDIS_ADDR__"
  password: "__REDIS_PASSWORD__"
  db: __REDIS_DB__
  pool_size: __REDIS_POOL_SIZE__
  # Sentinel 模式（生产 HA）：将 sentinel 设为 true 并填写 sentinel_addrs
  sentinel: __REDIS_SENTINEL__
  master_name: "__REDIS_MASTER_NAME__"
  sentinel_addrs:
    - "__REDIS_SENTINEL_ADDR_1__"
    - "__REDIS_SENTINEL_ADDR_2__"
    - "__REDIS_SENTINEL_ADDR_3__"

kafka:
  enabled: __KAFKA_ENABLED__
  # KRaft 模式：dev 默认单 broker，pret/生产默认 3 broker
  brokers:
    - "__KAFKA_BROKER_1__"
    - "__KAFKA_BROKER_2__"
    - "__KAFKA_BROKER_3__"
  topic_prefix: "__KAFKA_TOPIC_PREFIX__"
  producer:
    required_acks: -1

clickhouse:
  enabled: __CLICKHOUSE_ENABLED__
  addrs:
    - "__CLICKHOUSE_ADDR__"
  database: "__CLICKHOUSE_DATABASE__"
  username: "__CLICKHOUSE_USER__"
  password: "__CLICKHOUSE_PASSWORD__"
  max_open_conns: 50
  max_idle_conns: 10
  conn_max_lifetime: 1h

metrics:
  basic_auth_user: "__METRICS_BASIC_AUTH_USER__"
  basic_auth_password: "__METRICS_BASIC_AUTH_PASSWORD__"
  prometheus:
    enabled: __PROMETHEUS_ENABLED__
    query_url: "__PROMETHEUS_QUERY_URL__"
    timeout: "__PROMETHEUS_TIMEOUT__"

mtls:
  ca_cert: "/etc/mxcwpp/certs/ca.crt"
  # CA 私钥：AgentCenter 用它按 AgentID 在线签发一机一证（per_agent_cert）。
  ca_key: "/etc/mxcwpp/certs/ca.key"
  server_cert: "/etc/mxcwpp/certs/server.crt"
  server_key: "/etc/mxcwpp/certs/server.key"
  # Agent enroll 引导令牌（deploy.sh 从 .env ENROLL_TOKEN 替换；留空自动生成强令牌）。
  # 生产（非 insecure_dev_mode）必填且需 ≥32 强度，否则 AgentCenter fail-closed 拒绝启动。
  enroll_token: "__ENROLL_TOKEN__"
  # 一机一证 + 强制客户端证书 CN==AgentID：生产强制开启，杜绝伪造 AgentID / 共享私钥。
  per_agent_cert: true
  enforce_agent_id: true

log:
  level: "__LOG_LEVEL__"
  format: "__LOG_FORMAT__"
  file: "/var/log/mxcwpp/server.log"
  error_file: "/var/log/mxcwpp/error.log"
  max_age: __LOG_MAX_AGE__

agent:
  heartbeat_interval: __HEARTBEAT_INTERVAL__
  work_dir: "/var/lib/mxcwpp-agent"

plugins:
  dir: "__PLUGINS_DIR__"
  base_url: "__PLUGINS_BASE_URL__"

# PDF 服务端渲染（Gotenberg sidecar）
#
# 此前模板缺这一段：全新部署渲染出的配置没有 gotenberg_url，报告导出得到的是
# 一个损坏的 .pdf 而不是明确报错——典型的静默失败。
pdf:
  gotenberg_url: "http://gotenberg:3000"   # 同 mxcwpp-net 网络内的服务别名
  internal_url: "http://manager:8080"      # Gotenberg 回拉 manager 静态资源

# 检测产出的通知灰度（见 docs/configuration.md「alerting」）
#
# 留空即全部类别不通知，告警仍照常入库、列表与大屏可见。
# 这些链路此前从未通知过，一次全开会淹没值班，因此确认某类误报收敛后再逐个加入。
alerting:
  notify_categories: []
  min_severity: "high"
  suppress_window_minutes: 30

# 客户自有 SIEM 外发（CEF over Syslog）
#
# 与通知渠道是两件事：通知叫醒人、可被抑制；外发是把记录交给客户日志系统，必须全量。
# 未启用时不影响任何功能，告警照常入库并按 alerting 配置通知。
siem:
  enabled: false
  protocol: "tcp"            # tcp / udp
  address: ""                # 如 siem.example.com:514
  facility: 1
