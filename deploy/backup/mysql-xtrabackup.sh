#!/usr/bin/env bash
# mxcwpp MySQL 物理备份脚本 (Percona XtraBackup, 全量 + 增量)
#
# 调用:
#   ./mysql-xtrabackup.sh full       # 全量备份
#   ./mysql-xtrabackup.sh incremental # 增量备份 (基于最近一次全量)
#
# 输出: BACKUP_DIR/{date}-full/  或  BACKUP_DIR/{date}-incr/
# 自动: 7 天本地保留 + 30 天 OSS 异地保留 + Prometheus 上报
#
# 前置:
#   apt install percona-xtrabackup-80
#   或 dnf install percona-xtrabackup
#   或 mxcwpp-agent 自带二进制
#
# 部署: deploy/systemd/timers/mxcwpp-mysql-backup.timer

set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/var/lib/mxcwpp-backup/mysql}"
MYSQL_USER="${MYSQL_USER:-mxcwpp_backup}"
MYSQL_PASSWORD="${MYSQL_PASSWORD?MYSQL_PASSWORD env required}"
MYSQL_DATA_DIR="${MYSQL_DATA_DIR:-/var/lib/mysql}"
RETENTION_DAYS="${RETENTION_DAYS:-7}"
OSS_BUCKET="${OSS_BUCKET:-}"        # 例 oss://mxcwpp-backups/mysql/
OSS_TOOL="${OSS_TOOL:-aws s3}"      # aws s3 / gsutil / ossutil
PROM_PUSHGATEWAY="${PROM_PUSHGATEWAY:-}"
LOG_FILE="${LOG_FILE:-/var/log/mxcwpp-backup/mysql.log}"

mode="${1:-full}"
date_tag="$(date +%Y%m%d-%H%M%S)"
target_dir="$BACKUP_DIR/$date_tag-${mode}"

mkdir -p "$BACKUP_DIR" "$(dirname "$LOG_FILE")"

log() {
  echo "$(date '+%F %T') $*" | tee -a "$LOG_FILE"
}

trap 'log "ERROR exited with code $?"; metric_push status=error' ERR

metric_push() {
  if [[ -z "$PROM_PUSHGATEWAY" ]]; then
    return
  fi
  cat <<EOF | curl --data-binary @- --silent "$PROM_PUSHGATEWAY/metrics/job/mxcwpp_mysql_backup/instance/$(hostname)" || true
mxcwpp_backup_started_at $(date +%s)
mxcwpp_backup_mode{mode="$mode"} 1
mxcwpp_backup_size_bytes $(du -sb "$target_dir" | awk '{print $1}')
$@
EOF
}

case "$mode" in
  full)
    log "starting full backup → $target_dir"
    xtrabackup --backup \
      --target-dir="$target_dir" \
      --user="$MYSQL_USER" --password="$MYSQL_PASSWORD" \
      --datadir="$MYSQL_DATA_DIR" \
      --slave-info --safe-slave-backup 2>&1 | tee -a "$LOG_FILE"
    ;;
  incremental)
    latest_full=$(ls -dt "$BACKUP_DIR"/*-full 2>/dev/null | head -1)
    if [[ -z "$latest_full" ]]; then
      log "no previous full backup found; fallback to full"
      mode=full
      target_dir="$BACKUP_DIR/$date_tag-full"
      exec "$0" full
    fi
    log "starting incremental backup → $target_dir (base: $latest_full)"
    xtrabackup --backup \
      --target-dir="$target_dir" \
      --incremental-basedir="$latest_full" \
      --user="$MYSQL_USER" --password="$MYSQL_PASSWORD" \
      --datadir="$MYSQL_DATA_DIR" 2>&1 | tee -a "$LOG_FILE"
    ;;
  *)
    echo "usage: $0 full|incremental" >&2
    exit 2
    ;;
esac

log "compressing $target_dir"
tar -I 'pigz -9' -cf "${target_dir}.tar.gz" -C "$BACKUP_DIR" "$(basename "$target_dir")"
rm -rf "$target_dir"

if [[ -n "$OSS_BUCKET" ]]; then
  log "uploading to $OSS_BUCKET"
  $OSS_TOOL cp "${target_dir}.tar.gz" "$OSS_BUCKET/" || log "OSS upload failed (non-fatal)"
fi

log "cleaning local backups older than ${RETENTION_DAYS} days"
find "$BACKUP_DIR" -name "*.tar.gz" -mtime "+$RETENTION_DAYS" -delete

metric_push "status=success"
log "DONE mode=$mode target=${target_dir}.tar.gz"
