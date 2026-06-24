# Prod 部署 2.4.0 — alerts / vulnerabilities / host_vulnerabilities 迁 CH

## 背景

把 3 张高频 OLTP 表迁到 ClickHouse 双写：
- `alerts` (1.6w 行 / 预期增长)
- `vulnerabilities` (5w 行 / CVE 库)
- `host_vulnerabilities` (92w 行 / 主机漏洞关联)

实现方式：GORM `AfterCreate/AfterUpdate/AfterSave` hook 自动同步 CH，**所有 200+ 处 db.Create/Save/Updates 调用零修改**获双写能力。失败仅 log，不阻塞 MySQL 事务。

## 当前状态

- ✅ Schema + hooks + ETL 工具 + setup 注入：commit `224c767` 已推 main
- ✅ Prod node1 `/data/src/mxcwpp` 已 `git pull` 最新
- ✅ ETL 二进制已编译：prod node1 `/tmp/etl-alerts-vulns-ch`
- ⏳ Prod CH 3 张表未建（待 manager 2.4.0 启动自动 ensureSchemas）
- ⏳ Prod 仍跑 2.3.0（未 bump 也未 deploy）
- ⏳ 历史数据未迁（CH 表建好后跑 ETL）

## 部署步骤

### 1. bump 版本

```bash
ssh -p 51337 devops@35.241.106.122
cd /data/src/mxcwpp
sudo sed -i 's/version: 2.3.0/version: 2.4.0/' deploy/prod/cluster.yaml
sudo grep '^  version:' deploy/prod/cluster.yaml  # 验证 2.4.0
```

### 2. build + push 5 images

```bash
sudo ./scripts/build-images.sh --version 2.4.0 --registry harbor.slileisure.com/mxcwpp --push
```

### 3. mxctl deploy

```bash
sudo ./bin/mxctl deploy -f deploy/prod/cluster.yaml
```

预期：manager 启动时 `ensureSchemas` 自动建 CH `alerts` / `vulnerabilities` / `host_vulnerabilities` 3 张表。同时 GORM hooks 启用，新增告警/漏洞数据双写 MySQL + CH。

### 4. 验证 CH 表已建

```bash
sudo ssh -p 51337 centos@10.170.3.3 'sudo docker exec mxcwpp-clickhouse clickhouse-client --user default --password 6a59253f957fbbeefe11676f7f3b269b --database mxcwpp -q "SHOW TABLES LIKE \"alerts\"; SHOW TABLES LIKE \"%vuln%\""'
```

### 5. 历史数据迁移 ETL

```bash
sudo /tmp/etl-alerts-vulns-ch -config deploy/prod/out/prod-cluster/nodes/node1-control/config/server.yaml -table all -batch 5000
```

预计耗时（按 dev 经验外推）：
- alerts 1.6w：< 10s
- vulnerabilities 5w：< 30s
- host_vulnerabilities 92w：3-5 分钟

完成后打印 MySQL/CH 对账行数。若 CH < MySQL 退出码 2 表示有遗漏。

### 6. 抽样验证查询

```bash
sudo ssh -p 51337 centos@10.170.3.3 'sudo docker exec mxcwpp-clickhouse clickhouse-client --user default --password 6a59253f957fbbeefe11676f7f3b269b --database mxcwpp -q "SELECT count() FROM alerts FINAL; SELECT count() FROM vulnerabilities FINAL; SELECT count() FROM host_vulnerabilities FINAL"'
```

预期 alerts ≥ 16312、vulnerabilities ≥ 51394、host_vulnerabilities ≥ 919468。

### 7. 测 PDF (验证报告附录已写 ClickHouse)

打开 http://mxcwpp.sl-devops.com 各报告页「导出 PDF」按钮，检查最后一章「附录」数据来源是否写 ClickHouse。

## 回滚

- 若新版本异常：`./bin/mxctl deploy -f deploy/prod/cluster.yaml` 用 2.3.0 重新部署（先把 cluster.yaml version 改回）
- CH 表保留不影响 MySQL，回滚后业务继续读 MySQL
- 双写失败容错：CH 写不成功不阻塞 MySQL 事务，业务不受影响

## 后续阶段（明天后）

阶段 1 完成后，业务路径双写 + 报告附录显 CH，但**读路径仍 MySQL**。

阶段 2 待评估：
- 报告 `BuildEDRReportData` / `BuildVulnReportData` 改读 CH（性能提升但需重写 GROUP BY / JOIN）
- UI 列表 endpoint 改读 CH（`/api/v1/alerts` / `/api/v1/vulnerabilities`）
- 单条详情 by ID 保留 MySQL（OLTP 最佳）

每改一个读路径前先观察 CH 数据完整性 + 写入延迟。
