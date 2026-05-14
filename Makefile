.PHONY: proto test test-ui test-all test-race security clean help build-server build-consumer package-agent package-agent-all package-plugins package-plugins-all package-all package-all-arch dev-docker-up dev-docker-up-d dev-docker-down dev-docker-logs dev-docker-restart pret-docker-up pret-docker-up-d pret-docker-down

# 默认变量
VERSION ?= 1.0.0
SERVER_HOST ?= localhost:6751
GOARCH ?= amd64
GOOS ?= linux

# ============ 代码生成 ============

proto:
	@echo "Generating Protobuf Go code..."
	@if ! command -v protoc &> /dev/null; then \
		echo "Error: protoc not found. Please install protoc first."; \
		echo "macOS: brew install protobuf"; \
		echo "Ubuntu/Debian: sudo apt-get install protobuf-compiler"; \
		exit 1; \
	fi
	@if ! command -v protoc-gen-go &> /dev/null; then \
		echo "Installing protoc-gen-go..."; \
		go install google.golang.org/protobuf/cmd/protoc-gen-go@latest; \
	fi
	@if ! command -v protoc-gen-go-grpc &> /dev/null; then \
		echo "Installing protoc-gen-go-grpc..."; \
		go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest; \
	fi
	@./scripts/generate-proto.sh

# ============ 开发环境 ============

dev-docker-up:
	@echo "Starting Docker development environment..."
	@./scripts/dev-docker-start.sh

dev-docker-up-d:
	@echo "Starting Docker development environment in background..."
	@./scripts/dev-docker-start.sh --detach

dev-docker-down:
	@echo "Stopping Docker development environment..."
	@cd deploy && docker compose -f docker-compose.dev.yml down

dev-docker-logs:
	@cd deploy && docker compose -f docker-compose.dev.yml logs -f

dev-docker-restart:
	@echo "Restarting services..."
	@cd deploy && docker compose -f docker-compose.dev.yml restart manager ui

pret-docker-up:
	@echo "Starting Docker pret environment..."
	@./scripts/pret-docker-start.sh --foreground

pret-docker-up-d:
	@echo "Starting Docker pret environment in background..."
	@./scripts/pret-docker-start.sh --detach

pret-docker-down:
	@echo "Stopping Docker pret environment..."
	@cd deploy && docker compose -f docker-compose.pret.yml down --remove-orphans

# ============ 构建打包 ============

build-server:
	@echo "Building server..."
	@mkdir -p dist/server
	@go build -ldflags "-s -w" -o dist/server/agentcenter ./cmd/server/agentcenter
	@go build -ldflags "-s -w" -o dist/server/manager ./cmd/server/manager
	@echo "Server binaries built: dist/server/"

build-consumer:
	@echo "Building consumer..."
	@mkdir -p dist/server
	@go build -ldflags "-s -w" -o dist/server/consumer ./cmd/server/consumer
	@echo "Consumer binary built: dist/server/consumer"

package-agent:
	@./scripts/build.sh agent --arch=$(GOARCH) --version=$(VERSION) --server=$(SERVER_HOST)

package-agent-all:
	@./scripts/build.sh agent --arch=all --version=$(VERSION) --server=$(SERVER_HOST)

package-plugins:
	@./scripts/build.sh plugins --arch=$(GOARCH) --version=$(VERSION)

package-plugins-all:
	@./scripts/build.sh plugins --arch=all --version=$(VERSION)

package-all:
	@./scripts/build.sh all --arch=$(GOARCH) --version=$(VERSION) --server=$(SERVER_HOST)

package-all-arch:
	@./scripts/build.sh all --arch=all --version=$(VERSION) --server=$(SERVER_HOST)

# ============ 测试与质量 ============

test:
	go test ./...

test-ui:
	cd ui && npm run test

test-all: test test-ui

test-race:
	go test -race -short ./...

security:
	@echo "=== 依赖漏洞扫描 (govulncheck) ==="
	@if command -v govulncheck &> /dev/null; then \
		govulncheck ./...; \
	else \
		echo "govulncheck not found, installing..."; \
		go install golang.org/x/vuln/cmd/govulncheck@latest && govulncheck ./...; \
	fi
	@echo ""
	@echo "=== 静态安全分析 (gosec) ==="
	@if command -v gosec &> /dev/null; then \
		gosec -quiet ./...; \
	else \
		echo "gosec not found, installing..."; \
		go install github.com/securego/gosec/v2/cmd/gosec@latest && gosec -quiet ./...; \
	fi
	@echo ""
	@echo "=== go vet ==="
	go vet ./...

fmt:
	go fmt ./...

lint:
	@if command -v golangci-lint &> /dev/null; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not found, skipping lint"; \
	fi

# ============ 工具 ============

deps:
	go mod download
	go mod tidy

clean:
	find . -name "*.pb.go" -delete
	rm -rf dist/ bin/ tmp/
	rm -f agent agentcenter manager baseline collector baseline-plugin collector-plugin

certs:
	@echo "Generating certificates..."
	@./scripts/generate-certs.sh

# ============ 帮助 ============

help:
	@echo "MxSec Platform - Makefile Commands"
	@echo ""
	@echo "代码生成:"
	@echo "  make proto                  - 生成 Protobuf Go 代码"
	@echo ""
	@echo "开发环境 (Docker Compose):"
	@echo "  make dev-docker-up          - 启动开发环境 (前台，带日志)"
	@echo "  make dev-docker-up-d        - 启动开发环境 (后台)"
	@echo "  make dev-docker-down        - 停止开发环境"
	@echo "  make dev-docker-logs        - 查看日志"
	@echo "  make dev-docker-restart     - 重启服务 (manager + ui)"
	@echo "  make pret-docker-up         - 启动压测环境 (前台, 带日志)"
	@echo "  make pret-docker-up-d       - 启动压测环境 (后台)"
	@echo "  make pret-docker-down       - 停止压测环境"
	@echo ""
	@echo "构建打包:"
	@echo "  make build-server           - 构建 Server 二进制 (本地开发)"
	@echo "  make package-agent          - 打包 Agent (单架构 RPM/DEB)"
	@echo "  make package-agent-all      - 打包 Agent (amd64 + arm64)"
	@echo "  make package-plugins        - 构建所有插件 (单架构)"
	@echo "  make package-plugins-all    - 构建所有插件 (amd64 + arm64)"
	@echo "  make package-all            - 构建全部 (单架构)"
	@echo "  make package-all-arch       - 构建全部 (amd64 + arm64)"
	@echo ""
	@echo "测试与质量:"
	@echo "  make test                   - 运行后端测试"
	@echo "  make test-ui                - 运行前端测试"
	@echo "  make test-all               - 运行全部测试"
	@echo "  make test-race              - 运行竞态检测测试"
	@echo "  make security               - 安全扫描 (govulncheck + gosec + vet)"
	@echo "  make fmt                    - 格式化代码"
	@echo "  make lint                   - 代码检查"
	@echo ""
	@echo "工具:"
	@echo "  make deps                   - 下载依赖"
	@echo "  make clean                  - 清理构建产物"
	@echo "  make certs                  - 生成 mTLS 证书"
	@echo ""
	@echo "示例:"
	@echo "  make package-agent-all VERSION=1.0.5 SERVER_HOST=10.0.0.1:6751"
	@echo "  make package-all-arch VERSION=1.0.5 SERVER_HOST=10.0.0.1:6751"
	@echo ""
	@echo "输出目录:"
	@echo "  Agent RPM/DEB:  dist/packages/"
	@echo "  插件二进制:     dist/plugins/"
