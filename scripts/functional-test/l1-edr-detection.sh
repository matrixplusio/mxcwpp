#!/usr/bin/env bash
# L1 EDR 检测覆盖测试 — 跑 ~30 攻击样本 在 dev VM, 验 cel 规则命中.
#
# 用法:
#   ROCKY_IP=10.0.0.109 CENTOS_IP=10.0.0.114 \
#     bash scripts/functional-test/l1-edr-detection.sh
#
# 凭证: SSH user=centos pass=centos
# JWT: /tmp/mxcwpp-jwt

set -uo pipefail
ROCKY_IP="${ROCKY_IP:-10.0.0.109}"
CENTOS_IP="${CENTOS_IP:-10.0.0.114}"
MGR="${MGR:-http://localhost:8080}"
JWT_FILE="${JWT_FILE:-/tmp/mxcwpp-jwt}"
JWT=$(cat "$JWT_FILE")

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5"
RSH() { sshpass -p centos ssh $SSH_OPTS centos@"$1" "$2"; }

REPORT_DIR="docs/functional-test-2026-06-08"
mkdir -p "$REPORT_DIR"
REPORT="$REPORT_DIR/l1-edr-detection.md"

# 收集触发开始时间 (本地时区, 与 alert.last_seen_at 同格式 "YYYY-MM-DD HH:MM:SS")
T0=$(date '+%Y-%m-%d %H:%M:%S')
echo "T0=$T0"

PASS=0; FAIL=0
declare -a ROWS

# trigger_and_check: $1=样本名 $2=主机IP $3=触发cmd $4=期望命中关键词(title|rule_id, 用|分隔多个OR)
trigger_and_check() {
  local name="$1" ip="$2" cmd="$3" kw="$4"
  local start_ts=$(date '+%Y-%m-%d %H:%M:%S')
  RSH "$ip" "$cmd" >/dev/null 2>&1
  sleep 12
  # 字符串字典序比较 last_seen_at >= start_ts (本地时区同格式)
  local hits=$(curl -s -H "Authorization: Bearer $JWT" "$MGR/api/v1/alerts?page=1&page_size=80" \
    | jq -r --arg kw "$kw" --arg t0 "$start_ts" '[(.data.items // [])[] | select((.last_seen_at // "") >= $t0) | select((.title // "") | test($kw;"i")) | .rule_id] | unique | join(",")')
  if [ -n "$hits" ]; then
    PASS=$((PASS+1))
    ROWS+=("| $name | $ip | PASS | $hits |")
    echo "[PASS] $name on $ip → $hits"
  else
    FAIL=$((FAIL+1))
    ROWS+=("| $name | $ip | FAIL | — |")
    echo "[FAIL] $name on $ip"
  fi
}

echo "==== L1 EDR 检测覆盖 ===="
echo "rocky9=$ROCKY_IP centos7=$CENTOS_IP start=$T0"
echo

# === 1. 反弹 shell 5 种 ===
trigger_and_check "bash /dev/tcp 反弹" "$ROCKY_IP" \
  "bash -c '(bash -i >/dev/tcp/127.0.0.1/1 0>&1) &' ; sleep 1; pkill -f 'bash -i' || true" \
  "反弹|reverse|bash"
trigger_and_check "nc 反弹 shell"  "$ROCKY_IP" \
  "(rm -f /tmp/_f; mkfifo /tmp/_f; cat /tmp/_f | /bin/sh -i 2>&1 | nc 127.0.0.1 1 >/tmp/_f) >/dev/null 2>&1 & sleep 1; pkill -f mkfifo || true; rm -f /tmp/_f" \
  "反弹|reverse|nc|ncat"
trigger_and_check "python pty 反弹" "$ROCKY_IP" \
  "python3 -c 'import socket,subprocess,pty,os; s=socket.socket(); s.settimeout(1);
try: s.connect((\"127.0.0.1\",1))
except: import sys; sys.exit(0)' || true" \
  "反弹|reverse|python"
trigger_and_check "perl 反弹 shell" "$ROCKY_IP" \
  "perl -e 'use Socket; socket(S,2,1,6); connect(S,sockaddr_in(1,inet_aton(\"127.0.0.1\"))) or exit; exec \"/bin/sh\";' >/dev/null 2>&1 || true" \
  "反弹|reverse|perl"
trigger_and_check "openssl 加密反弹" "$ROCKY_IP" \
  "timeout 2 openssl s_client -quiet -connect 127.0.0.1:1 -no_ign_eof 2>/dev/null < /dev/null || true" \
  "反弹|reverse|openssl"

# === 2. 持久化 6 种 ===
trigger_and_check "cron 写入" "$ROCKY_IP" \
  "echo '* * * * * /tmp/mxcwpp-test.sh' | sudo -n tee /etc/cron.d/mxcwpp-test-\$\$ >/dev/null 2>&1; sudo -n rm -f /etc/cron.d/mxcwpp-test-\$\$" \
  "cron|persistence|持久化"
trigger_and_check "bashrc 写入" "$ROCKY_IP" \
  "echo 'export MXCWPP_E2E=1' >> ~/.bashrc; sed -i '/MXCWPP_E2E/d' ~/.bashrc" \
  "bashrc|persistence|持久化"
trigger_and_check "authorized_keys 写" "$ROCKY_IP" \
  "mkdir -p ~/.ssh; echo 'ssh-rsa AAAAB3NzaC1yc2EmxcwppE2E test@e2e' >> ~/.ssh/authorized_keys; sed -i '/mxcwppE2E/d' ~/.ssh/authorized_keys" \
  "ssh|authorized|keys|persistence"
trigger_and_check "systemd 服务" "$ROCKY_IP" \
  "echo '[Unit]
Description=mxcwpp-test' | sudo -n tee /etc/systemd/system/mxcwpp-test.service >/dev/null 2>&1; sudo -n rm -f /etc/systemd/system/mxcwpp-test.service" \
  "systemd|service|persistence"
trigger_and_check "rc.local 写" "$ROCKY_IP" \
  "echo '#!/bin/sh' | sudo -n tee /etc/rc.local >/dev/null 2>&1 || true; sudo -n rm -f /etc/rc.local 2>/dev/null" \
  "rc.local|persistence"
trigger_and_check "ld.so.preload" "$ROCKY_IP" \
  "echo '/tmp/evil.so' | sudo -n tee /etc/ld.so.preload >/dev/null 2>&1; sudo -n rm -f /etc/ld.so.preload" \
  "preload|ld.so|持久化"

# === 3. 提权 4 种 ===
trigger_and_check "sudo 失败 5 次" "$ROCKY_IP" \
  "for i in 1 2 3 4 5; do echo wrong_pwd | sudo -S -p '' whoami 2>&1 | grep -v 'incorrect' || true; done" \
  "sudo|提权|privilege"
trigger_and_check "su root 失败" "$ROCKY_IP" \
  "echo wrong | su root -c whoami 2>&1 | head -1 || true" \
  "su|提权|privilege"
trigger_and_check "SUID 文件创建" "$ROCKY_IP" \
  "cp /bin/bash /tmp/mxcwpp-suid-test; sudo -n chmod u+s /tmp/mxcwpp-suid-test 2>/dev/null; rm -f /tmp/mxcwpp-suid-test" \
  "suid|提权|privilege"
trigger_and_check "capability 添加" "$ROCKY_IP" \
  "cp /bin/bash /tmp/mxcwpp-cap; sudo -n setcap cap_net_admin+ep /tmp/mxcwpp-cap 2>/dev/null; rm -f /tmp/mxcwpp-cap" \
  "cap|capability|提权"

# === 4. 横向 4 种 ===
trigger_and_check "ssh 链式登录" "$ROCKY_IP" \
  "ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 -o BatchMode=yes nobody@127.0.0.1 'whoami' 2>&1 | head -1 || true" \
  "ssh|横向|lateral"
trigger_and_check "wget+exec" "$ROCKY_IP" \
  "wget -q -O /tmp/mxcwpp-wget-test http://127.0.0.1:1/ 2>&1; rm -f /tmp/mxcwpp-wget-test" \
  "wget|download|横向"
trigger_and_check "curl+pipe-bash" "$ROCKY_IP" \
  "curl -s http://127.0.0.1:1/ 2>&1 | head -1 || true" \
  "curl|download|管道"
trigger_and_check "scp 反弹" "$ROCKY_IP" \
  "scp -o StrictHostKeyChecking=no -o ConnectTimeout=2 -o BatchMode=yes /etc/hosts nobody@127.0.0.1:/tmp/ 2>&1 | head -1 || true" \
  "scp|横向|lateral"

# === 5. 信息收集 3 种 ===
trigger_and_check "用户枚举" "$ROCKY_IP" \
  "id; whoami; w; last | head -5; cat /etc/passwd | wc -l" \
  "信息|discover|recon|enumerate"
trigger_and_check "网络枚举" "$ROCKY_IP" \
  "netstat -tunlp 2>/dev/null | head; ss -tunlp | head; route -n; arp -a 2>/dev/null | head" \
  "netstat|信息|网络|discover"
trigger_and_check "kernel info" "$ROCKY_IP" \
  "uname -a; cat /proc/version; cat /etc/os-release; lsmod | head" \
  "kernel|信息|discover"

# === 6. 内存 / 进程 3 种 ===
trigger_and_check "memfd_exec 模拟" "$ROCKY_IP" \
  "python3 -c 'import os,subprocess; fd=os.memfd_create(\"mxcwpp\"); os.write(fd, b\"#!/bin/sh\necho test\"); os.execve(\"/proc/self/fd/{}\".format(fd), [\"mxcwpp\"], os.environ)' 2>&1 | head -1 || true" \
  "memfd|内存|hollow"
trigger_and_check "fork bomb (受控)" "$ROCKY_IP" \
  "(for i in 1 2 3 4 5; do (sleep 0.1 &) ; done; wait) 2>&1 | head -1 || true" \
  "fork|进程|进程异常"
trigger_and_check "kthread 伪装" "$ROCKY_IP" \
  "(exec -a '[kworker/0:1H]' sleep 1) &" \
  "kworker|进程伪装|masquerade"

# === 7. DKOM Rootkit 模拟 2 种 ===
trigger_and_check "隐藏端口模拟" "$ROCKY_IP" \
  "python3 -c 'import socket; s=socket.socket(); s.bind((\"127.0.0.1\",0)); s.listen(1); s.close()' 2>&1" \
  "port|端口|hidden|rootkit"
trigger_and_check "lsmod 异常 module" "$ROCKY_IP" \
  "lsmod | tail; cat /proc/modules | tail" \
  "module|内核|rootkit"

# === 8. WebShell 写入 3 种 ===
trigger_and_check "PHP webshell 写" "$ROCKY_IP" \
  "echo '<?php @eval(\$_POST[\"cmd\"]); ?>' > /tmp/mxcwpp-shell.php; rm -f /tmp/mxcwpp-shell.php" \
  "webshell|php|文件"
trigger_and_check "JSP webshell 写" "$ROCKY_IP" \
  "echo '<%@ page import=\"java.util.*,java.io.*\"%><% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>' > /tmp/mxcwpp-shell.jsp; rm -f /tmp/mxcwpp-shell.jsp" \
  "webshell|jsp|文件"
trigger_and_check "WebShell 大马 (wso)" "$ROCKY_IP" \
  "echo 'wso25_marker_eval base64_decode str_rot13 system' > /tmp/mxcwpp-wso.php; rm -f /tmp/mxcwpp-wso.php" \
  "wso|webshell|文件"

# === 9. DNS / 网络异常 2 种 ===
trigger_and_check "DNS 隧道模拟" "$ROCKY_IP" \
  "for i in 1 2 3 4 5 6 7 8 9 10; do dig +short +timeout=1 mxcwpp-test-\$i.invalid 2>/dev/null || true; done" \
  "dns|tunnel|隧道|信息"
trigger_and_check "ICMP 大包" "$ROCKY_IP" \
  "ping -c 3 -s 1400 127.0.0.1 2>&1 | head -2 || true" \
  "icmp|ping|network"

# === 10. 横向 SSH 弱口令尝试 ===
trigger_and_check "SSH 弱口令暴破" "$ROCKY_IP" \
  "for p in 123456 admin password root abc123; do sshpass -p \$p ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 -o BatchMode=no root@127.0.0.1 'whoami' 2>&1 | head -1 || true; done" \
  "ssh|brute|弱口令|登录失败"

# === centos7 1 个 (核心反弹 shell 复测) ===
trigger_and_check "centos7 bash /dev/tcp" "$CENTOS_IP" \
  "bash -c '(bash -i >/dev/tcp/127.0.0.1/1 0>&1) &' ; sleep 1; pkill -f 'bash -i' || true" \
  "反弹|reverse|bash"

# === 报告 ===
{
  echo "# L1 EDR 检测覆盖测试 (2026-06-08)"
  echo
  echo "rocky9 (kernel 5.14, cgroup_skb eBPF) + centos7 (kernel 3.10, AF_PACKET fallback)"
  echo
  echo "**触发样本: $((PASS+FAIL)) / PASS: $PASS / FAIL: $FAIL / 命中率: $((PASS*100/(PASS+FAIL)))%**"
  echo
  echo "| 样本 | 主机 | 结果 | 命中规则 |"
  echo "|---|---|---|---|"
  for r in "${ROWS[@]}"; do echo "$r"; done
} > "$REPORT"

echo
echo "==== L1 EDR 完成 PASS=$PASS FAIL=$FAIL ===="
echo "报告: $REPORT"
