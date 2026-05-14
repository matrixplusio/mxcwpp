#!/bin/bash

# 证书生成脚本
# 用于生成 mTLS 所需的 CA 证书、Server 证书和 Agent 证书

set -e

# 颜色输出
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# 配置
# 默认生成到 deploy/certs 目录（用于Docker Compose和本地开发）
CERT_DIR="${CERT_DIR:-deploy/certs}"
CA_KEY="${CERT_DIR}/ca.key"
CA_CERT="${CERT_DIR}/ca.crt"
SERVER_KEY="${CERT_DIR}/server.key"
SERVER_CERT="${CERT_DIR}/server.crt"
SERVER_CSR="${CERT_DIR}/server.csr"
AGENT_KEY="${CERT_DIR}/agent.key"
AGENT_CERT="${CERT_DIR}/agent.crt"
AGENT_CSR="${CERT_DIR}/agent.csr"

# 证书有效期（天）
VALIDITY_DAYS="${VALIDITY_DAYS:-3650}"  # 默认 10 年

# 额外的 IP 地址（用于外部访问，如 192.168.8.140）
EXTRA_IPS="${EXTRA_IPS:-}"  # 逗号分隔的 IP 列表，如 "192.168.8.140,10.0.0.1"

# 额外的域名（用于域名访问）
EXTRA_DOMAINS="${EXTRA_DOMAINS:-}"  # 逗号分隔的域名列表，如 "agent.example.com,*.example.com"

# 创建证书目录
mkdir -p "${CERT_DIR}"

echo -e "${GREEN}开始生成 mTLS 证书...${NC}"

# 检查 openssl
if ! command -v openssl &> /dev/null; then
    echo -e "${RED}错误: openssl 未安装${NC}"
    echo "请先安装 openssl:"
    echo "  macOS: brew install openssl"
    echo "  Ubuntu/Debian: sudo apt-get install openssl"
    exit 1
fi

# 1. 生成 CA 私钥
echo -e "${GREEN}[1/6] 生成 CA 私钥...${NC}"
openssl genrsa -out "${CA_KEY}" 4096

# 2. 生成 CA 证书
echo -e "${GREEN}[2/6] 生成 CA 证书...${NC}"
openssl req -new -x509 -days "${VALIDITY_DAYS}" \
    -key "${CA_KEY}" \
    -out "${CA_CERT}" \
    -subj "/C=CN/ST=Beijing/L=Beijing/O=Matrix Cloud Security Platform/OU=CA/CN=mxsec-ca"

# 3. 生成 Server 私钥
echo -e "${GREEN}[3/6] 生成 Server 私钥...${NC}"
openssl genrsa -out "${SERVER_KEY}" 4096

# 4. 生成 Server 证书签名请求（CSR）
echo -e "${GREEN}[4/6] 生成 Server 证书签名请求...${NC}"
openssl req -new \
    -key "${SERVER_KEY}" \
    -out "${SERVER_CSR}" \
    -subj "/C=CN/ST=Beijing/L=Beijing/O=Matrix Cloud Security Platform/OU=Server/CN=mxsec-server"

# 5. 使用 CA 签名 Server 证书
echo -e "${GREEN}[5/6] 使用 CA 签名 Server 证书...${NC}"

# 构建额外 IP 配置
EXTRA_IP_CONFIG=""
if [ -n "$EXTRA_IPS" ]; then
    IP_INDEX=3
    IFS=',' read -ra IPS <<< "$EXTRA_IPS"
    for ip in "${IPS[@]}"; do
        ip=$(echo "$ip" | xargs)  # 去除空格
        if [ -n "$ip" ]; then
            EXTRA_IP_CONFIG="${EXTRA_IP_CONFIG}
IP.${IP_INDEX} = ${ip}"
            IP_INDEX=$((IP_INDEX + 1))
            echo -e "${GREEN}  → 添加 IP: ${ip}${NC}"
        fi
    done
fi

# 构建额外域名配置
EXTRA_DNS_CONFIG=""
if [ -n "$EXTRA_DOMAINS" ]; then
    DNS_INDEX=5
    IFS=',' read -ra DOMAINS <<< "$EXTRA_DOMAINS"
    for domain in "${DOMAINS[@]}"; do
        domain=$(echo "$domain" | xargs)  # 去除空格
        if [ -n "$domain" ]; then
            EXTRA_DNS_CONFIG="${EXTRA_DNS_CONFIG}
DNS.${DNS_INDEX} = ${domain}"
            DNS_INDEX=$((DNS_INDEX + 1))
            echo -e "${GREEN}  → 添加域名: ${domain}${NC}"
        fi
    done
fi

openssl x509 -req -days "${VALIDITY_DAYS}" \
    -in "${SERVER_CSR}" \
    -CA "${CA_CERT}" \
    -CAkey "${CA_KEY}" \
    -CAcreateserial \
    -out "${SERVER_CERT}" \
    -extensions v3_req \
    -extfile <(
        cat <<EOF
[v3_req]
keyUsage = digitalSignature, keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = *.local
DNS.3 = agentcenter
DNS.4 = agentcenter.mxsec-network${EXTRA_DNS_CONFIG}
IP.1 = 127.0.0.1
IP.2 = ::1${EXTRA_IP_CONFIG}
EOF
    )

# 6. 生成 Agent 私钥和证书
echo -e "${GREEN}[6/6] 生成 Agent 私钥和证书...${NC}"
openssl genrsa -out "${AGENT_KEY}" 4096
openssl req -new \
    -key "${AGENT_KEY}" \
    -out "${AGENT_CSR}" \
    -subj "/C=CN/ST=Beijing/L=Beijing/O=Matrix Cloud Security Platform/OU=Agent/CN=mxsec-agent"

openssl x509 -req -days "${VALIDITY_DAYS}" \
    -in "${AGENT_CSR}" \
    -CA "${CA_CERT}" \
    -CAkey "${CA_KEY}" \
    -CAcreateserial \
    -out "${AGENT_CERT}" \
    -extensions v3_req \
    -extfile <(
        cat <<EOF
[v3_req]
keyUsage = digitalSignature, keyEncipherment, dataEncipherment
extendedKeyUsage = clientAuth
EOF
    )

# 同时创建 client.crt 和 client.key（Agent 代码使用的文件名）
CLIENT_CERT="${CERT_DIR}/client.crt"
CLIENT_KEY="${CERT_DIR}/client.key"
cp "${AGENT_CERT}" "${CLIENT_CERT}"
cp "${AGENT_KEY}" "${CLIENT_KEY}"
chmod 644 "${CLIENT_CERT}"
chmod 600 "${CLIENT_KEY}"

# 清理临时文件
rm -f "${SERVER_CSR}" "${AGENT_CSR}" "${CERT_DIR}/ca.srl"

# 设置权限
chmod 600 "${CA_KEY}" "${SERVER_KEY}" "${AGENT_KEY}"
chmod 644 "${CA_CERT}" "${SERVER_CERT}" "${AGENT_CERT}"

echo -e "${GREEN}证书生成完成！${NC}"
echo ""
echo -e "${YELLOW}生成的证书文件：${NC}"
echo "  CA 证书:     ${CA_CERT}"
echo "  CA 私钥:     ${CA_KEY}"
echo "  Server 证书: ${SERVER_CERT}"
echo "  Server 私钥: ${SERVER_KEY}"
echo "  Agent 证书:  ${AGENT_CERT}"
echo "  Agent 私钥:  ${AGENT_KEY}"
echo ""
echo -e "${YELLOW}使用说明：${NC}"
echo "  1. Server 端配置（configs/server.yaml）："
echo "     mtls:"
echo "       ca_cert: ${CERT_DIR}/ca.crt"
echo "       server_cert: ${CERT_DIR}/server.crt"
echo "       server_key: ${CERT_DIR}/server.key"
echo ""
echo "  2. Agent 端需要："
echo "     - CA 证书: ${CA_CERT}"
echo "     - Agent 证书: ${AGENT_CERT}"
echo "     - Agent 私钥: ${AGENT_KEY}"
echo ""
echo -e "${YELLOW}注意：${NC}"
echo "  - 生产环境建议使用更安全的证书管理方式"
echo "  - 可以为每个 Agent 生成独立的证书（使用不同的 CN）"
echo "  - 证书有效期：${VALIDITY_DAYS} 天"
