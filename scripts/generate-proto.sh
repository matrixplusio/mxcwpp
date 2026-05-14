#!/bin/bash

# 生成 Protobuf Go 代码的脚本

set -e

# 颜色输出
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Generating Protobuf Go code...${NC}"

# 检查 protoc 是否安装
if ! command -v protoc &> /dev/null; then
    echo -e "${YELLOW}Warning: protoc not found. Please install protoc first.${NC}"
    echo "Installation: https://grpc.io/docs/protoc-installation/"
    exit 1
fi

# 检查 protoc-gen-go 是否安装
GOPATH_BIN="$(go env GOPATH)/bin"
if [ ! -f "${GOPATH_BIN}/protoc-gen-go" ]; then
    echo -e "${YELLOW}Installing protoc-gen-go...${NC}"
    go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
fi

# 将 GOPATH/bin 添加到 PATH（如果不在 PATH 中）
if [[ ":$PATH:" != *":${GOPATH_BIN}:"* ]]; then
    export PATH="${GOPATH_BIN}:${PATH}"
fi

# 项目根目录
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROTO_DIR="${ROOT_DIR}/api/proto"
OUT_DIR="${ROOT_DIR}/api/proto"

# 生成 bridge.proto
echo -e "${GREEN}Generating bridge.proto...${NC}"
protoc \
    --go_out=${OUT_DIR}/bridge \
    --go_opt=paths=source_relative \
    -I=${PROTO_DIR} \
    ${PROTO_DIR}/bridge.proto

# 生成 grpc.proto
echo -e "${GREEN}Generating grpc.proto...${NC}"
protoc \
    --go_out=${OUT_DIR}/grpc \
    --go_opt=paths=source_relative \
    --go-grpc_out=${OUT_DIR}/grpc \
    --go-grpc_opt=paths=source_relative \
    -I=${PROTO_DIR} \
    ${PROTO_DIR}/grpc.proto

echo -e "${GREEN}Protobuf code generation completed!${NC}"
