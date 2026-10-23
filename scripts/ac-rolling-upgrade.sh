#!/usr/bin/env bash
# AgentCenter 主备升级：把连接挪到备 AC → 升级主 AC → 分批切回主 AC → 备 AC 恢复待命。
#
# 用法：
#   scripts/ac-rolling-upgrade.sh -p <主AC管理地址> -s <备AC管理地址> -k <AC管理密钥文件> -- <升级主AC的命令...>
# 例：
#   scripts/ac-rolling-upgrade.sh -p 127.0.0.1:8081 -s 10.0.0.12:8081 -k /root/.ac-secret -- \
#     docker compose -p mxcwpp-control -f docker-compose.control.yml up -d --no-deps --force-recreate agentcenter
#
# 前置：前面有 deploy/config/haproxy-agentcenter-ha.cfg 那样的主备转发。
# -k 的文件里放 AC 的 server.ac_admin_secret（不是 internal_secret，排空接口不认后者），
# 只给 root 读，用完删掉。
# 从不认 ac_admin_secret 的旧版本升上来的那一次不能用本脚本（主备认的不是同一把），要手工分步做。
# 任何一步失败或超时都停在原地并打印当前状态，不自动回滚——这时连接通常都在备 AC 上，服务不中断。
set -euo pipefail

BATCH=20
INTERVAL_MS=2000
DRAIN_TIMEOUT=600   # 等连接清零的上限（秒）
READY_TIMEOUT=300   # 等主 AC 就绪的上限（秒）
RECOVER_TIMEOUT=300 # 等 agent 全部回到主 AC 的上限（秒），应大于两个心跳周期

usage() { sed -n '2,10p' "$0" >&2; exit 2; }

PRIMARY="" STANDBY="" SECRET_FILE=""
while getopts "p:s:k:b:i:h" opt; do
  case "$opt" in
    p) PRIMARY=$OPTARG ;;
    s) STANDBY=$OPTARG ;;
    k) SECRET_FILE=$OPTARG ;;
    b) BATCH=$OPTARG ;;
    i) INTERVAL_MS=$OPTARG ;;
    *) usage ;;
  esac
done
shift $((OPTIND - 1))
[ "${1:-}" = "--" ] && shift
[ -n "$PRIMARY" ] && [ -n "$STANDBY" ] && [ -r "$SECRET_FILE" ] && [ $# -gt 0 ] || usage
# 密钥经 curl 的配置文件（-K）传入，不放进命令行参数——参数对同机其他账号的 ps 可见。
# 不用 -H @文件：老版本 curl 不支持。
HDR=$(mktemp)
chmod 600 "$HDR"
trap 'rm -f "$HDR"' EXIT
printf 'header = "X-Internal-Secret: %s"\n' "$(tr -d '\n' < "$SECRET_FILE")" > "$HDR"

log() { printf '%s %s\n' "$(date +%T)" "$*"; }

# ready <addr>：/ready 返回 200 即就绪
ready() { [ "$(curl -s -o /dev/null -m 5 -w '%{http_code}' "http://$1/ready")" = 200 ]; }

# conns <addr>：当前 TCP 连接数（含已建流、还没发首包的）；接口不通返回非 0。
# 不用已登记连接数：agent 建流后最长隔一个心跳周期才发首包，只看登记数会在连接还挂着时误判已排空。
conns() {
  local body
  body=$(curl -sf -m 5 -K "$HDR" "http://$1/admin/drain") || return 1
  printf '%s' "$body" | sed -n 's/.*"tcp_connections":\([0-9]*\).*/\1/p'
}

post() { # post <addr> <path>，2xx 或 409（已在排空中）算成功
  local code
  code=$(curl -s -o /dev/null -m 5 -w '%{http_code}' -X POST -K "$HDR" "http://$1$2")
  case "$code" in 2??|409) return 0 ;; *) log "POST $1$2 返回 $code"; return 1 ;; esac
}

wait_drained() { # wait_drained <addr>
  local deadline=$((SECONDS + DRAIN_TIMEOUT)) n
  while :; do
    n=$(conns "$1") || { log "读取 $1 连接数失败"; return 1; }
    log "$1 剩余连接 $n"
    [ "$n" = 0 ] && return 0
    [ $SECONDS -ge $deadline ] && { log "等待 $1 连接清零超时"; return 1; }
    sleep 5
  done
}

fail() {
  log "中止：$*"
  log "当前状态：主 $PRIMARY 连接 $(conns "$PRIMARY" || echo '?')，备 $STANDBY 连接 $(conns "$STANDBY" || echo '?')"
  log "主 AC 恢复后，手动执行：POST $STANDBY/admin/drain 切回，再 POST $STANDBY/admin/undrain"
  exit 1
}

log "1/4 检查备 AC 就绪"
ready "$STANDBY" || fail "备 AC $STANDBY 未就绪，不能把连接挪过去"
BEFORE=$(conns "$PRIMARY") || fail "读取主 AC 连接数失败"
log "主 AC 当前 TCP 连接 $BEFORE"

log "2/4 排空主 AC，连接分批转到备 AC"
post "$PRIMARY" "/admin/drain?batch=$BATCH&interval_ms=$INTERVAL_MS" || fail "主 AC 排空请求失败"
wait_drained "$PRIMARY" || fail "主 AC 未排空"

log "3/4 升级主 AC：$*"
"$@" || fail "升级命令退出码 $?"
# 升级命令若没有真正重启进程（镜像未变等），主 AC 会一直停在排空状态：30 秒后仍未就绪就显式恢复。
deadline=$((SECONDS + READY_TIMEOUT)); undrained=0
until ready "$PRIMARY"; do
  [ $SECONDS -ge $deadline ] && fail "主 AC 升级后未就绪"
  if [ $undrained = 0 ] && [ $SECONDS -ge $((deadline - READY_TIMEOUT + 30)) ]; then
    post "$PRIMARY" /admin/undrain && undrained=1 || log "主 AC 恢复接入的请求未成功，继续等待就绪"
  fi
  sleep 3
done

log "4/4 排空备 AC，连接分批切回主 AC"
post "$STANDBY" "/admin/drain?batch=$BATCH&interval_ms=$INTERVAL_MS" || fail "备 AC 排空请求失败"
wait_drained "$STANDBY" || fail "备 AC 未排空"
post "$STANDBY" /admin/undrain || fail "备 AC 恢复待命失败"

# 被断开的 agent 要等下一次发送失败才重连（空闲主机最长一个心跳周期），等主 AC 回到升级前的连接数再报完成。
deadline=$((SECONDS + RECOVER_TIMEOUT))
while :; do
  # 读不到连接数不能当成「已恢复」：那样接口不通或密钥不对时会直接报完成
  n=$(conns "$PRIMARY") || fail "读取主 AC 连接数失败，无法确认 agent 是否已回到主 AC"
  [ "${n:-0}" -ge "$BEFORE" ] && break
  [ $SECONDS -ge $deadline ] && { log "警告：主 AC 连接 ${n}，未恢复到升级前的 ${BEFORE}，请检查未回来的 agent"; exit 1; }
  log "等待 agent 回到主 AC：$n/$BEFORE"
  sleep 10
done
log "完成：主 $PRIMARY TCP 连接 ${n}（升级前 ${BEFORE}），备 AC 已恢复待命"
