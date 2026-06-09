#!/usr/bin/env bash
# 构建加固版 Agent 二进制 (M1-6):
#   - garble 混淆 (字符串/符号名)
#   - UPX 压缩 + --best --ultra-brute
#   - go build -trimpath -buildmode=pie
#   - -ldflags '-s -w' 移除调试符号
#
# 输出: dist/agent/mxsec-agent-hardened-<arch>
#
# 用法:
#   ./scripts/build-agent-hardened.sh amd64        # 单架构
#   ./scripts/build-agent-hardened.sh all          # amd64 + arm64
#
# 依赖:
#   go install mvdan.cc/garble@latest
#   apt install upx-ucl  或  brew install upx

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

OUTPUT_DIR="${OUTPUT_DIR:-dist/agent-hardened}"
VERSION="${VERSION:-$(cat VERSION 2>/dev/null || echo dev)}"
BUILD_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

ARCH="${1:-amd64}"

declare -a ARCHS
case "$ARCH" in
  all) ARCHS=(amd64 arm64) ;;
  amd64|arm64) ARCHS=("$ARCH") ;;
  *) echo "usage: $0 [amd64|arm64|all]" >&2; exit 2 ;;
esac

if ! command -v garble >/dev/null 2>&1; then
  echo "→ installing garble..."
  go install mvdan.cc/garble@latest
fi
GARBLE_BIN="${GARBLE_BIN:-$(command -v garble || echo "$HOME/go/bin/garble")}"
if [[ ! -x "$GARBLE_BIN" ]]; then
  echo "garble not found, please run: go install mvdan.cc/garble@latest" >&2
  exit 1
fi

if ! command -v upx >/dev/null 2>&1; then
  echo "warning: upx not found, skipping compression" >&2
  UPX_BIN=""
else
  UPX_BIN="$(command -v upx)"
fi

mkdir -p "$OUTPUT_DIR"

LDFLAGS=(
  "-s" "-w"
  "-X" "main.buildVersion=$VERSION"
  "-X" "main.buildTime=$BUILD_TIME"
)

for arch in "${ARCHS[@]}"; do
  bin="$OUTPUT_DIR/mxsec-agent-hardened-$arch"
  echo ""
  echo "=== Building hardened agent for linux/$arch ==="

  # garble 编译 + 混淆字符串/符号
  CGO_ENABLED=0 GOOS=linux GOARCH=$arch \
    "$GARBLE_BIN" -literals -tiny -seed=random \
      build \
      -trimpath \
      -buildmode=pie \
      -ldflags "${LDFLAGS[*]}" \
      -o "$bin" \
      ./cmd/agent

  orig_size=$(stat -c%s "$bin" 2>/dev/null || stat -f%z "$bin")
  echo "  garble + go build OK ($(numfmt --to=iec-i --suffix=B "$orig_size" 2>/dev/null || echo "${orig_size}B"))"

  if [[ -n "$UPX_BIN" ]]; then
    echo "  → UPX compressing..."
    "$UPX_BIN" --best --ultra-brute -q "$bin" >/dev/null
    new_size=$(stat -c%s "$bin" 2>/dev/null || stat -f%z "$bin")
    echo "  UPX OK ($(numfmt --to=iec-i --suffix=B "$new_size" 2>/dev/null || echo "${new_size}B"))"
  fi

  sha=$(sha256sum "$bin" | awk '{print $1}')
  echo "  SHA256: $sha"
  echo "$sha  $(basename "$bin")" > "$bin.sha256"
done

echo ""
echo "=== Done ==="
ls -lh "$OUTPUT_DIR/"
