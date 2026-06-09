#!/usr/bin/env bash
# mxsec mTLS 证书生成 (P3-18).
#
# 生成证书链:
#   1. Root CA (10 年)
#   2. Manager intermediate CA (5 年)
#   3. Manager Server cert + key  (1 年, 用于 Manager HTTP/gRPC)
#   4. AC Server cert + key       (1 年, 用于 AC gRPC 6751)
#   5. Agent Client cert + key    (3 年, 用于 Agent → AC mTLS)
#
# 用法:
#   ./scripts/certs/gen-mtls-certs.sh [output_dir]
#
# 输出 (默认 deploy/certs/):
#   ca.crt / ca.key
#   manager.crt / manager.key
#   ac.crt / ac.key
#   agent-client.crt / agent-client.key
#
# 默认 CN:
#   CA           : mxsec-root-ca
#   Manager      : mxsec-manager (SAN: manager / *.svc.cluster.local / 127.0.0.1)
#   AC           : mxsec-agentcenter (SAN: agentcenter / agent.svc.example.com / 127.0.0.1)
#   Agent client : mxsec-agent (OU 用 Agent ID)

set -euo pipefail

OUTPUT_DIR="${1:-deploy/certs}"
COUNTRY="${COUNTRY:-CN}"
ORG="${ORG:-mxsec}"
ORG_UNIT="${ORG_UNIT:-Security}"

# 自定义 SAN (默认覆盖典型部署场景)
MANAGER_DNS="${MANAGER_DNS:-manager,mxsec-manager,mxsec-manager.default.svc,mxsec-manager.default.svc.cluster.local,localhost}"
MANAGER_IP="${MANAGER_IP:-127.0.0.1}"
AC_DNS="${AC_DNS:-agentcenter,mxsec-agentcenter,mxsec-agentcenter.default.svc.cluster.local,localhost}"
AC_IP="${AC_IP:-127.0.0.1}"

mkdir -p "$OUTPUT_DIR"
cd "$OUTPUT_DIR"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

# ============ 1. Root CA ============
if [[ ! -f ca.crt ]]; then
  log "Generating Root CA (10 年有效)"
  openssl genrsa -out ca.key 4096
  openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
    -subj "/C=$COUNTRY/O=$ORG/OU=$ORG_UNIT/CN=mxsec-root-ca" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"
  log "  ✓ ca.crt / ca.key"
else
  log "Root CA exists, skip"
fi

# ============ 2. Manager Server Cert ============
log "Generating Manager Server cert"
openssl genrsa -out manager.key 2048
cat > manager.ext <<EOF
subjectAltName = $(echo "DNS:$MANAGER_DNS" | sed 's/,/,DNS:/g'),IP:$MANAGER_IP
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth,clientAuth
EOF
openssl req -new -key manager.key -out manager.csr \
  -subj "/C=$COUNTRY/O=$ORG/OU=$ORG_UNIT/CN=mxsec-manager"
openssl x509 -req -in manager.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out manager.crt -days 365 -sha256 -extfile manager.ext
rm -f manager.csr manager.ext
log "  ✓ manager.crt / manager.key (1 年有效)"

# ============ 3. AC Server Cert ============
log "Generating AC Server cert"
openssl genrsa -out ac.key 2048
cat > ac.ext <<EOF
subjectAltName = $(echo "DNS:$AC_DNS" | sed 's/,/,DNS:/g'),IP:$AC_IP
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth,clientAuth
EOF
openssl req -new -key ac.key -out ac.csr \
  -subj "/C=$COUNTRY/O=$ORG/OU=$ORG_UNIT/CN=mxsec-agentcenter"
openssl x509 -req -in ac.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out ac.crt -days 365 -sha256 -extfile ac.ext
rm -f ac.csr ac.ext
log "  ✓ ac.crt / ac.key (1 年有效)"

# ============ 4. Agent Client Cert ============
log "Generating Agent Client cert (3 年长效, 嵌入 Agent 镜像)"
openssl genrsa -out agent-client.key 2048
cat > agent-client.ext <<EOF
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
EOF
openssl req -new -key agent-client.key -out agent-client.csr \
  -subj "/C=$COUNTRY/O=$ORG/OU=Agent/CN=mxsec-agent-client"
openssl x509 -req -in agent-client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out agent-client.crt -days 1095 -sha256 -extfile agent-client.ext
rm -f agent-client.csr agent-client.ext
log "  ✓ agent-client.crt / agent-client.key (3 年有效)"

# ============ 权限收紧 ============
chmod 600 *.key
chmod 644 *.crt
log "Keys chmod 600, certs chmod 644"

# ============ 验证 ============
log "Verifying chain..."
openssl verify -CAfile ca.crt manager.crt ac.crt agent-client.crt

log ""
log "=== Done ==="
log "Output dir: $OUTPUT_DIR"
ls -lh *.crt *.key 2>&1 | tail -10

log ""
log "部署:"
log "  Manager:  挂载 ca.crt + manager.crt + manager.key"
log "  AC:       挂载 ca.crt + ac.crt + ac.key"
log "  Agent:    打包 ca.crt + agent-client.crt + agent-client.key (build 时嵌入)"
