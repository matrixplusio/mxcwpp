#!/usr/bin/env bash
# mxcwpp ClickHouse 备份脚本 (BACKUP DATABASE 内置命令)
#
# 调用:
#   ./clickhouse-backup.sh
#
# 备份 mxcwpp 库全表到 BACKUP_DIR + 上传 OSS。
# CH 用 BACKUP TO Disk('backups',...) 内置命令, 不阻塞读写。

set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/var/lib/mxcwpp-backup/clickhouse}"
CH_HOST="${CH_HOST:-127.0.0.1}"
CH_PORT="${CH_PORT:-9000}"
CH_USER="${CH_USER:-default}"
CH_PASSWORD="${CH_PASSWORD:-}"
CH_DB="${CH_DB:-mxcwpp}"
RETENTION_DAYS="${RETENTION_DAYS:-7}"
OSS_BUCKET="${OSS_BUCKET:-}"
OSS_TOOL="${OSS_TOOL:-aws s3}"
LOG_FILE="${LOG_FILE:-/var/log/mxcwpp-backup/clickhouse.log}"

mkdir -p "$BACKUP_DIR" "$(dirname "$LOG_FILE")"

log() {
  echo "$(date '+%F %T') $*" | tee -a "$LOG_FILE"
}

trap 'log "ERROR exited with code $?"' ERR

date_tag="$(date +%Y%m%d-%H%M%S)"
backup_name="${CH_DB}_${date_tag}.zip"
backup_path="$BACKUP_DIR/$backup_name"

log "starting CH backup → $backup_path"

clickhouse-client \
  --host="$CH_HOST" --port="$CH_PORT" \
  --user="$CH_USER" ${CH_PASSWORD:+--password="$CH_PASSWORD"} \
  --query "BACKUP DATABASE $CH_DB TO File('$backup_path')" 2>&1 | tee -a "$LOG_FILE"

log "backup file size: $(du -h "$backup_path" | awk '{print $1}')"

if [[ -n "$OSS_BUCKET" ]]; then
  log "uploading to $OSS_BUCKET"
  $OSS_TOOL cp "$backup_path" "$OSS_BUCKET/" || log "OSS upload failed"
fi

log "cleaning local backups older than ${RETENTION_DAYS} days"
find "$BACKUP_DIR" -name "*.zip" -mtime "+$RETENTION_DAYS" -delete

log "DONE backup=$backup_path"
