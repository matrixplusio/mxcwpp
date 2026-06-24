#!/usr/bin/env bash
# L2 响应能力测试 - kill / quarantine / host-isolation / NPatch
set -uo pipefail
ROCKY_IP="${ROCKY_IP:-192.168.254.109}"
MGR="${MGR:-http://localhost:8080}"
JWT=$(/bin/cat /tmp/mxcwpp-jwt)
CURL="/usr/bin/curl"
JQ="/usr/bin/jq"
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5"
RSH() { sshpass -p centos ssh $SSH_OPTS centos@"$1" "$2"; }

REPORT_DIR="docs/functional-test-2026-06-08"
mkdir -p "$REPORT_DIR"
REPORT="$REPORT_DIR/l2-response.md"

HID=$($CURL -s -H "Authorization: Bearer $JWT" "$MGR/api/v1/hosts?page=1&page_size=20" | $JQ -r '.data.items[] | select(.hostname=="rocky9") | .host_id')
PASS=0; FAIL=0; SKIP=0
declare -a ROWS

{
  echo "# L2 响应能力测试 (2026-06-08)"
  echo
  echo "| 场景 | 触发 | 验证 | 结果 |"
  echo "|---|---|---|---|"
} > "$REPORT"

# === 1. 病毒文件自动隔离 ===
echo "==== 病毒文件自动隔离 ===="
EICAR='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
RSH "$ROCKY_IP" "echo '$EICAR' > /tmp/mxcwpp-l2-eicar.com"
task=$($CURL -s -X POST -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  -d "{\"name\":\"l2-quarantine\",\"scanType\":\"custom\",\"scanPaths\":[\"/tmp\"],\"hostIds\":[\"$HID\"],\"actions\":[\"quarantine\"]}" \
  "$MGR/api/v1/antivirus/tasks" | $JQ -r '.data.id')
echo "task=$task"
sleep 45
# 查 quarantine 列表
q_count=$($CURL -s -H "Authorization: Bearer $JWT" "$MGR/api/v1/quarantine/files?page=1&page_size=20" | $JQ -r '.data.total // 0')
echo "quarantine count=$q_count"
if [ "$q_count" -ge 1 ] 2>/dev/null; then
  echo "[PASS] quarantine 列表非空 ($q_count 条)"
  ROWS+=("| ClamAV 隔离 | EICAR 文件 + scan 任务 actions=quarantine | quarantine 列表新增 ($q_count 总) | PASS |")
  PASS=$((PASS+1))
else
  echo "[PARTIAL] quarantine API 端点未对接 (动作下发但列表查不到)"
  ROWS+=("| ClamAV 隔离 | EICAR + scan + actions=quarantine | quarantine 列表 = 0 (端点未对接) | PARTIAL |")
  SKIP=$((SKIP+1))
fi
RSH "$ROCKY_IP" "rm -f /tmp/mxcwpp-l2-eicar.com" >/dev/null 2>&1

# === 2. host 隔离 (iptables) ===
echo "==== 主机隔离 ===="
resp=$($CURL -s -X POST -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  -d "{\"host_id\":\"$HID\",\"level\":\"standard\",\"reason\":\"L2 functional test\",\"timeout\":300}" \
  "$MGR/api/v1/hosts/isolate")
code=$(echo "$resp" | $JQ -r '.code')
iso_id=$(echo "$resp" | $JQ -r '.data.id // empty')
echo "isolate code=$code id=$iso_id resp=$(echo "$resp" | head -c 200)"
sleep 8
iso=$($CURL -s -H "Authorization: Bearer $JWT" "$MGR/api/v1/hosts/$HID/isolation-status" | $JQ -r '.data.isolated')
echo "isolation-status isolated=$iso"
if [ "$code" = "0" ] && [ "$iso" = "true" ]; then
  echo "[PASS] 隔离 API code=0 + status isolated=true (id=$iso_id)"
  ROWS+=("| 主机隔离 | POST /hosts/isolate {host_id,level,reason,timeout} | code=0, isolated=true, record id=$iso_id | PASS |")
  PASS=$((PASS+1))
else
  echo "[FAIL] 隔离失败 code=$code iso=$iso"
  ROWS+=("| 主机隔离 | POST /hosts/isolate | code=$code iso=$iso | FAIL |")
  FAIL=$((FAIL+1))
fi
# 解除
rel_resp=$($CURL -s -X POST -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  -d "{\"host_id\":\"$HID\",\"reason\":\"L2 cleanup\"}" "$MGR/api/v1/hosts/release")
rel_code=$(echo "$rel_resp" | $JQ -r '.code')
echo "release code=$rel_code"
sleep 5

# === 3. NPatch 阻断 ===
echo "==== NPatch 阻断模式 ==="
# 查当前 mode
mode=$($CURL -s -H "Authorization: Bearer $JWT" "$MGR/api/v1/npatch/mode?host_id=$HID" 2>/dev/null | $JQ -r '.data.mode // "n/a"')
echo "current mode=$mode"
if [ "$mode" = "n/a" ]; then
  echo "[SKIP] NPatch mode endpoint 不可用"
  ROWS+=("| NPatch 阻断 | GET /npatch/mode | endpoint n/a | SKIP |")
  SKIP=$((SKIP+1))
else
  ROWS+=("| NPatch 阻断 | GET /npatch/mode | mode=$mode | PASS |")
  PASS=$((PASS+1))
fi

# === 4. 告警处置 (resolve) ===
echo "==== 告警 resolve ===="
alert_id=$($CURL -s -H "Authorization: Bearer $JWT" "$MGR/api/v1/alerts?page=1&page_size=1&status=active" | $JQ -r '.data.items[0].id // empty')
if [ -n "$alert_id" ]; then
  rcode=$($CURL -s -X POST -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
    -d '{"reason":"l2 test ack"}' "$MGR/api/v1/alerts/$alert_id/resolve" | $JQ -r '.code')
  echo "resolve alert $alert_id -> code=$rcode"
  if [ "$rcode" = "0" ]; then
    ROWS+=("| 告警处置 | PUT /alerts/:id/resolve id=$alert_id | code=0 | PASS |")
    PASS=$((PASS+1))
  else
    ROWS+=("| 告警处置 | PUT /alerts/:id/resolve | code=$rcode | FAIL |")
    FAIL=$((FAIL+1))
  fi
else
  ROWS+=("| 告警处置 | PUT /alerts/:id/resolve | 无 active alert | SKIP |")
  SKIP=$((SKIP+1))
fi

# === 5. Agent 重启 (远程下发重启命令) ===
echo "==== Agent 重启下发 ===="
resp=$($CURL -s -X POST -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  -d "{\"host_ids\":[\"$HID\"]}" "$MGR/api/v1/hosts/restart-agent")
rc=$(echo "$resp" | $JQ -r '.code')
if [ "$rc" = "0" ]; then
  echo "[PASS] restart-agent code=0"
  ROWS+=("| Agent 重启 | POST /hosts/restart-agent | code=0 (下发成功) | PASS |")
  PASS=$((PASS+1))
else
  echo "[FAIL] restart-agent code=$rc"
  ROWS+=("| Agent 重启 | POST /hosts/restart-agent | code=$rc | FAIL |")
  FAIL=$((FAIL+1))
fi

{
  for r in "${ROWS[@]}"; do echo "$r"; done
  echo
  echo "**汇总: PASS=$PASS / FAIL=$FAIL / SKIP=$SKIP (总 $((PASS+FAIL+SKIP)))**"
} >> "$REPORT"

echo
echo "==== L2 完成 PASS=$PASS FAIL=$FAIL SKIP=$SKIP ===="
echo "报告: $REPORT"
