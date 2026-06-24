# deploy/certs/ — mTLS 证书复用目录（**节点本地状态**）

## 说明

`mxctl render` 在此目录读写 mTLS 证书（ca/server/agent/client）。所有 `*.key` `*.pem` 已 `.gitignore`，**不入 git**。本目录是 control 节点本地状态，不在节点间同步。

## 行为

- **首次** render：生成 CA + server + agent 证书写入本目录。
- **后续** render：
  - 若 `server.crt` SAN 未覆盖 `cluster.yaml` 的 `additional_sans` + 内置 hostname → 自动**用现 CA + 现 server.key 重签** server.crt 并覆盖（CA 不变，兼容已部署 agent 端 ca.crt 信任链）。
  - 其他证书（CA / agent.crt）不改动。

## 严禁

- **手动 cp** 别处证书到此目录（5 周潜伏事故根因：本目录的 server.crt 与 `cluster.yaml` 配置漂移）
- **跨环境复用**（dev/prod 各自独立目录或独立 control 节点）
- **删除 `ca.key`**（删后下次 render 会生成新 CA，所有已部署 agent ca.crt 失效，需逐台分发新 ca.crt）

## 备份策略

CA 私钥 `ca.key` 是集群信任根，**必须**异地备份（一旦丢失全集群 mTLS 重建）。建议：
- chmod 600 owner-only 在 control 节点
- 同时备份到独立保密存储（KMS / Vault / age-encrypted）
- 备份频率：每次 render 后

## 故障排查

| 现象 | 检查 |
|---|---|
| agent TLS handshake fail `hostname mismatch` | `openssl x509 -in server.crt -noout -ext subjectAltName` 对比 `cluster.yaml` additional_sans |
| 新 deploy 后 agent 全断 + 无 reconnect | 验证 CA 是否被换：`openssl x509 -in ca.crt -noout -fingerprint -sha256` vs agent 端 `/var/lib/mxcwpp-agent/certs/ca.crt` |
| render 无 reissue 但 SAN 不对 | 跑 `mxctl render -f deploy/prod/cluster.yaml` 看 stderr 是否输出 `server.crt SAN 已更新并重签` 警告 |
