#!/bin/bash
# 用于 Air 热重载的 Agent 构建脚本
# 环境变量由 docker-compose 传递：SERVER_HOST, VERSION

set -e

SERVER_HOST="${SERVER_HOST:-agentcenter:6751}"
VERSION="${VERSION:-dev}"
BUILD_TIME=$(date -u +'%Y-%m-%dT%H:%M:%SZ')

mkdir -p tmp

go build \
  -ldflags "-X main.serverHost=${SERVER_HOST} -X main.buildVersion=${VERSION} -X main.buildTime=${BUILD_TIME}" \
  -o ./tmp/agent \
  ./cmd/agent
