# YARA 规则库 (P2-8)

ref/07-病毒 MVP P0-6: YARA 完整规则库 (suspiciousDirs + 恶意代码 + WebShell)

## 现有规则集 (~20 条)

| 文件 | 类型 | 规则数 |
|---|---|---|
| webshell_php.yar | PHP webshell (eval/shell_exec/Behinder/Godzilla/AntSword/C99/R57/上传) | 7 |
| webshell_jsp.yar | JSP webshell + 内存马 (Runtime.exec/Behinder/Godzilla/Memshell Filter+Servlet/JspSpy) | 6 |
| webshell_misc.yar | ASPX/Python/Perl/Bash reverse + Generic obfuscation | 5 |

总计: 18 条规则

## 部署

```sh
# Agent 端 scanner 插件加载
ls /var/lib/mxcwpp/yara-rules/
# webshell_php.yar webshell_jsp.yar webshell_misc.yar

# YARA 规则文件由 Manager 通过 component 下发
# YARA 引擎 (yara-x / clamscan --yara) 自动 reload

# 命中触发:
# - DataType 3001 file_event (file_close_write 时扫描)
# - DataType 7030 av_scan_finding (主动扫描)
# 严重 critical → 自动隔离 (quarantine) + 主机 isolation 推荐
```

## ATT&CK 覆盖

| Technique | 描述 | 规则数 |
|---|---|---|
| T1505.003 | Server Software Component: Web Shell | 11 |
| T1027     | Obfuscated Files | 1 |
| T1059.004 | Bash | 1 |
| T1059.006 | Python | 2 |

## 后续 PR (M2 路线)

- WebShell 扩到 50 条 (常见框架: WordPress/ThinkPHP/Discuz 内嵌马)
- 勒索家族签名 (LockBit/Conti/REvil/Maze/Phobos)
- 挖矿样本 (XMRig/CoinHive/CryptoNight)
- ELF backdoor (典型 webshell ELF 后门)
- 内存马 Class 字节码扫描 (Java RASP 集成)

## 维护

- 来源参考: github.com/Yara-Rules/rules, github.com/Neo23x0/signature-base
- License: 各规则均自研, 不引入外部 yar 文件
- 测试: 每条规则需 EICAR-like 样本 + false positive 测试
- 性能: 单文件 yara 扫描 < 50ms (typical scanner 命中率敏感)

## 工具链

```sh
# yara-x 校验规则语法
yara-x check plugins/scanner/config/yara/*.yar

# 单文件扫描测试
yara-x scan webshell_php.yar /tmp/sample.php
```
