#!/bin/bash
#
# 生成 CycloneDX 格式的 SBOM（软件物料清单）。
#
# 为什么需要：客户合规审计要求知道产品里装了哪些第三方组件、什么版本。
# 出现 Log4Shell 这类事件时，SBOM 决定的是"十分钟内答出有没有受影响"
# 还是"翻源码翻两天"。
#
# 刻意只用 Go 自带的 `go list -m`，不依赖 cyclonedx-gomod 等外部工具：
# 离线环境与客户现场装不上额外工具的情况很常见，多一个依赖就多一处装不上的理由。
#
# 用法: ./scripts/gen-sbom.sh [输出文件]
set -euo pipefail

OUT="${1:-dist/sbom.cdx.json}"
mkdir -p "$(dirname "$OUT")"

VERSION="${VERSION:-$(git describe --tags --always 2>/dev/null || echo dev)}"
COMMIT="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
# 时间戳取提交时间，保证同一 commit 生成的 SBOM 也是可复现的。
TS="$(git log -1 --format=%cI 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)"

PY_SCRIPT="$(mktemp)"
trap 'rm -f "$PY_SCRIPT"' EXIT
cat > "$PY_SCRIPT" <<'PYEOF'
import hashlib, json, sys

out_path, version, commit, ts = sys.argv[1:5]

# go list -m -json 输出的是连续的 JSON 对象流，不是数组。
decoder = json.JSONDecoder()
raw = sys.stdin.read()
mods, idx = [], 0
while idx < len(raw):
    while idx < len(raw) and raw[idx].isspace():
        idx += 1
    if idx >= len(raw):
        break
    obj, idx = decoder.raw_decode(raw, idx)
    mods.append(obj)

components = []
for m in mods:
    if m.get("Main"):
        continue                      # 主模块是产品本身，不算第三方组件
    if m.get("Replace"):
        m = m["Replace"]
    name, ver = m.get("Path"), m.get("Version")
    if not name or not ver:
        continue                      # 无版本的本地替换无法计入物料清单
    comp = {
        "type": "library",
        "bom-ref": "pkg:golang/%s@%s" % (name, ver),
        "name": name,
        "version": ver,
        "purl": "pkg:golang/%s@%s" % (name, ver),
        "scope": "required",
    }
    # go.sum 校验和作为完整性依据，让 SBOM 可被验证而不只是罗列。
    if m.get("Sum"):
        comp["properties"] = [{"name": "go:mod:sum", "value": m["Sum"]}]
    components.append(comp)

components.sort(key=lambda c: c["bom-ref"])   # 排序保证同一输入产出同一文件

bom = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "version": 1,
    "metadata": {
        "timestamp": ts,
        "component": {
            "type": "application",
            "name": "mxcwpp",
            "version": version,
            "properties": [{"name": "git:commit", "value": commit}],
        },
    },
    "components": components,
}
body = json.dumps(bom, indent=2, ensure_ascii=False, sort_keys=False)
# serialNumber 由内容派生：同一份物料清单永远得到同一个编号，便于比对。
digest = hashlib.sha256(body.encode()).hexdigest()
bom["serialNumber"] = "urn:uuid:%s-%s-%s-%s-%s" % (
    digest[:8], digest[8:12], digest[12:16], digest[16:20], digest[20:32])
with open(out_path, "w", encoding="utf-8") as fh:
    json.dump(bom, fh, indent=2, ensure_ascii=False)
    fh.write("\n")
if not components:
    sys.exit("SBOM 生成失败：未解析出任何依赖组件")
print("SBOM: %s  组件数 %d" % (out_path, len(components)))
PYEOF

go list -m -json all | python3 "$PY_SCRIPT" "$OUT" "$VERSION" "$COMMIT" "$TS"
