# mxsec 灾备运行手册 (DR Runbook, M1-5)

## 目标 SLA

| 指标 | 目标值 | 说明 |
|---|---|---|
| RPO (Recovery Point Objective) | ≤ 5 min | 增量备份频率 |
| RTO (Recovery Time Objective) | ≤ 30 min | 全量恢复完成时间 |
| 备份保留 (本地) | 7 天 | xtrabackup tar.gz |
| 备份保留 (异地) | 30 天 | OSS 桶 (S3/OSS/GCS) |
| 演练频率 | 季度 | 全量灾备恢复 |

## 备份策略

### MySQL (xtrabackup)

```
全量: 每日 02:00 通过 mxsec-mysql-backup.timer
增量: 每 5 分钟 cron (可选, 高 RPO 场景)
压缩: pigz -9 并行 gzip
上传: aws s3 cp (或 ossutil/gsutil)
保留: 本地 7 天, OSS 30 天 (生命周期策略自动归档)
```

部署:
```sh
# 复制脚本 + systemd unit
cp deploy/backup/mysql-xtrabackup.sh /usr/local/bin/mxsec-mysql-xtrabackup.sh
chmod +x /usr/local/bin/mxsec-mysql-xtrabackup.sh
cp deploy/systemd/timers/mxsec-mysql-backup.* /etc/systemd/system/

# 环境配置
cat > /etc/mxsec/backup.env <<'EOF'
MYSQL_USER=mxsec_backup
MYSQL_PASSWORD=...
MYSQL_DATA_DIR=/var/lib/mysql
BACKUP_DIR=/var/lib/mxsec-backup/mysql
OSS_BUCKET=s3://mxsec-backups/mysql
OSS_TOOL=aws s3
PROM_PUSHGATEWAY=http://prometheus:9091
RETENTION_DAYS=7
EOF
chmod 600 /etc/mxsec/backup.env

systemctl daemon-reload
systemctl enable --now mxsec-mysql-backup.timer
```

### ClickHouse (内置 BACKUP)

每日 03:00 全量 BACKUP DATABASE mxsec, 不阻塞读写。
增量未实现 (CH 23.x 实验性 INCREMENTAL BACKUP, 风险待评估)。

### MySQL 主从复制 (热备)

```
主节点: gtid_mode=ON + log_bin
从节点: replicate-do-db=mxsec + read_only=1
延迟: < 1s (典型)
异地: GTID 跨 Region 复制 (mxctl deploy --topology=multi-region)
```

## 恢复流程

### MySQL 全量恢复

```sh
# 1. 停服
systemctl stop mxsec-manager mxsec-consumer mxsec-engine mxsec-agentcenter mysql

# 2. 解压最新全量
LATEST=$(ls -dt /var/lib/mxsec-backup/mysql/*-full.tar.gz | head -1)
mkdir -p /tmp/restore
tar -xzf "$LATEST" -C /tmp/restore

# 3. (若需要应用增量)
xtrabackup --prepare --target-dir=/tmp/restore/*-full
# 增量
for incr in $(ls -d /var/lib/mxsec-backup/mysql/*-incremental); do
  xtrabackup --prepare --apply-log-only \
    --target-dir=/tmp/restore/*-full --incremental-dir="$incr"
done

# 4. copy 回 datadir
rm -rf /var/lib/mysql/*
xtrabackup --copy-back --target-dir=/tmp/restore/*-full
chown -R mysql:mysql /var/lib/mysql

# 5. 启服
systemctl start mysql
mysql -e "FLUSH PRIVILEGES;"
systemctl start mxsec-manager mxsec-agentcenter mxsec-consumer mxsec-engine
```

### ClickHouse 全量恢复

```sh
# 1. 下载备份
aws s3 cp s3://mxsec-backups/clickhouse/mxsec_<date>.zip /tmp/

# 2. 恢复
clickhouse-client --query "RESTORE DATABASE mxsec FROM File('/tmp/mxsec_<date>.zip')"
```

## 异地灾备 (Multi-Region)

### 架构

```
Primary Region (cn-east-1)             DR Region (cn-west-1)
  manager + 6 微服务  ←─ Kafka MirrorMaker 2 ─→  manager + 6 微服务 (standby)
  MySQL Primary       ←─ GTID 复制 ─→            MySQL Replica
  Redis Sentinel      ←─ replication ─→          Redis Sentinel
  ClickHouse 分片                                 ClickHouse 分片
```

### 切换

```sh
# 1. 提升 DR Region MySQL Replica 为 Primary
mysql -e "STOP SLAVE; RESET SLAVE ALL;"

# 2. mxctl 切换流量
mxctl region failover --to=cn-west-1 --confirm

# 3. DNS 切换 (CDN/智能 DNS, 60s 收敛)
# 4. 通知 Agent fallback (Agent 心跳带 multi-region endpoint, 自动切换)
```

预期 RTO: 30 min (含 Agent 全量切换 + 数据一致性验证)

## 演练 SOP

季度全量演练 checklist:

- [ ] 在隔离环境恢复最新全量 + 应用所有增量
- [ ] 起 standby Manager + Engine + Consumer 验证服务启动
- [ ] 抽样 10 个核心表对比 row count + checksum
- [ ] Agent 注册压测 (1000 agent)
- [ ] 异地 OSS 下载延迟测试 (< 30 min for 100GB)
- [ ] DR 报告归档 docs/dr-reports/YYYY-Qx.md

## 监控

```promql
# 备份成功率 (期望 100%)
rate(mxsec_backup_status_total{status="success"}[7d])
  / rate(mxsec_backup_status_total[7d])

# 最近备份时间距今超过 25h 告警
time() - mxsec_backup_started_at > 25*3600

# 备份大小异常 (突然下降 50% 告警)
deriv(mxsec_backup_size_bytes[7d]) < -0.5
```

## 待实现 (Sprint 5+)

- mxctl backup verify 一键校验恢复正确性
- 增量备份 5min 频率 cron 落地
- 自动跨 Region MirrorMaker 2 配置生成
- DR 报告自动生成 + 邮件
