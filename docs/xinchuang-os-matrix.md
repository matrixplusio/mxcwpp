# mxcwpp 信创 OS 适配矩阵 (M1-7)

## 覆盖范围

| OS / 厂商 | 版本 | 架构 | 内核 | 支持级别 |
|---|---|---|---|---|
| 麒麟软件 银河麒麟 V10 | SP1 / SP2 / SP3 | amd64 / arm64 / loong64 | 4.19 / 5.4 / 5.10 | **GA** |
| 麒麟软件 中标麒麟 V7 | U6 | amd64 / arm64 | 3.10 | Beta (老内核) |
| 统信 UOS 1050/1060 | 1060 LTS | amd64 / arm64 / loong64 | 5.10 / 5.15 | **GA** |
| openEuler | 20.03 LTS / 22.03 LTS | amd64 / arm64 | 4.19 / 5.10 | **GA** |
| openEuler | 24.03 LTS | amd64 / arm64 | 6.6 | **GA** |
| 龙蜥 Anolis OS | 8.6 / 8.8 / 23 | amd64 / arm64 / loong64 | 4.19 / 5.10 / 6.6 | **GA** |
| 欧拉 EulerOS 2.x | 2.9 / 2.10 | amd64 / arm64 | 4.19 / 5.10 | GA |
| 红旗 Asianux | 7 / 8 | amd64 / arm64 | 3.10 / 4.18 | Beta |
| AIX | 7.2 | power | - | 未支持 (留 M2 评估) |

## 构建命令

```sh
# 单 OS 单架构
./scripts/build.sh agent --arch=loong64

# 信创全架构 (amd64 + arm64 + loong64)
./scripts/build.sh all --arch=xc

# 单架构所有产物
./scripts/build.sh all --arch=arm64
```

## 信创内核兼容矩阵 (eBPF 支持)

| 内核版本 | OS 举例 | eBPF CO-RE | sched_process_exec | privilege.c (M1-1) | rasp 全栈 |
|---|---|---|---|---|---|
| 3.10 | 中标麒麟 V7 U6 / Asianux 7 | ❌ | ❌ | ❌ | userspace fallback |
| 4.18 | Asianux 8 | ⚠️ 部分 | ✓ | commit_creds/setuid OK | partial |
| 4.19 | Kylin V10 SP1 / openEuler 20.03 / Anolis 8.6 | ⚠️ | ✓ | 4/6 hook OK | partial |
| 5.4  | Kylin V10 SP2 | ✓ | ✓ | 5/6 hook OK | full |
| 5.10 | UOS 1060 / openEuler 22.03 / Anolis 8.8 | ✓ | ✓ | **6/6 hook OK** | **full** |
| 5.15 | UOS 1060 LTS | ✓ | ✓ | 6/6 hook OK | full |
| 6.6  | openEuler 24.03 / Anolis 23 | ✓ | ✓ | 6/6 + fentry | full |

降级策略:
- 内核 < 5.4: 用户态 fallback (procfs + netlink + cnproc)
- 内核 < 4.18: 仅采集 + 基线检查, 不上 EDR 实时

## RPM/DEB 包元数据 (针对 OS 优化)

```yaml
# nfpm.yaml (针对 Kylin V10 ARM64)
name: mxcwpp-agent
arch: arm64
platform: linux
version: 2.0.0
section: security
priority: optional
maintainer: mxcwpp dev team
description: |
  Matrix Cloud Security Platform Agent
  适配 Kylin V10 / UOS / openEuler / Anolis 信创 OS
depends:
  - libc6 | glibc >= 2.17
  - libssl3 | openssl-libs
recommends:
  - libbpf
  - clamav-daemon
```

## 测试覆盖

每发布版本需通过以下信创环境冒烟测试:

- [ ] 银河麒麟 V10 SP2 ARM64 (4.19): Agent 启动 + 心跳 + 进程采集
- [ ] 统信 UOS 1060 LoongArch64: Agent 启动 + eBPF 4 hook (process/network/file/dns)
- [ ] openEuler 22.03 LTS amd64 (5.10): 全功能 + 6 privilege hook
- [ ] 龙蜥 Anolis 23 amd64 (6.6): 全功能 + RASP

## 信创合规清单

- [x] 国家安全部安全可控
- [x] 鲲鹏/飞腾 ARM 性能优化 (GOARCH=arm64 + ARM-specific OpenSSL backend)
- [x] 龙芯 LoongArch64 (GOARCH=loong64)
- [ ] 商用密码 (SM2/SM3/SM4) 替换 (TLS 国密套件, Sprint 5)
- [ ] 国密 HSM 集成 (商用密码模块, Sprint 5)

## 后续

- M2: 信创 OS 验收报告 (按客户实测)
- M2: 等保 2.0 三级认证 ←→ 中标麒麟 SP3 / UOS 1060
- M2: 龙芯 LoongArch64 性能对标 amd64 (CPU/IO benchmark)
