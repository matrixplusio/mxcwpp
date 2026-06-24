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
  internal_secret: "__INTERNAL_SECRET__"

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
  server_cert: "/etc/mxcwpp/certs/server.crt"
  server_key: "/etc/mxcwpp/certs/server.key"

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
