#!/usr/bin/env bash

set -euo pipefail

SUDO=""
if [[ "$(id -u)" -ne 0 ]]; then
  SUDO="sudo"
fi

log() {
  echo "[prod] $*"
}

install_debian() {
  export DEBIAN_FRONTEND=noninteractive
  $SUDO apt-get update
  $SUDO apt-get install -y ca-certificates curl gnupg jq openssl git lsb-release

  if ! command -v docker >/dev/null 2>&1; then
    $SUDO install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/$(. /etc/os-release && echo "$ID")/gpg | $SUDO gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    $SUDO chmod a+r /etc/apt/keyrings/docker.gpg
    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$(. /etc/os-release && echo \"$ID\") $(. /etc/os-release && echo \"$VERSION_CODENAME\") stable" \
      | $SUDO tee /etc/apt/sources.list.d/docker.list >/dev/null
    $SUDO apt-get update
    $SUDO apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  fi
}

install_rhel() {
  $SUDO dnf install -y dnf-plugins-core ca-certificates curl jq openssl git
  if ! command -v docker >/dev/null 2>&1; then
    $SUDO dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
    $SUDO dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  fi
}

main() {
  if [[ ! -f /etc/os-release ]]; then
    echo "不支持的系统: 缺少 /etc/os-release" >&2
    exit 1
  fi
  . /etc/os-release
  case "$ID" in
    ubuntu|debian)
      install_debian
      ;;
    rocky|rhel|centos|almalinux|ol)
      install_rhel
      ;;
    *)
      echo "暂不支持的发行版: $ID" >&2
      exit 1
      ;;
  esac

  # 配置 docker 容器日志轮转（全局默认）：防止任一容器 stdout 无限增长撑满磁盘。
  # 历史教训：Kafka 不可用时 agentcenter 高频刷 WARN，单容器 json 日志涨到 89G 撑爆根盘。
  # 仅在不存在时写入，避免覆盖运维自定义配置。
  if [ ! -f /etc/docker/daemon.json ]; then
    $SUDO mkdir -p /etc/docker
    printf '%s\n' '{' '  "log-driver": "json-file",' '  "log-opts": { "max-size": "100m", "max-file": "5" }' '}' | $SUDO tee /etc/docker/daemon.json >/dev/null
    log "已写入 /etc/docker/daemon.json（容器日志 100m x 5 轮转）"
  fi

  $SUDO systemctl enable --now docker
  log "依赖安装完成"
  docker --version
  docker compose version
}

main "$@"
