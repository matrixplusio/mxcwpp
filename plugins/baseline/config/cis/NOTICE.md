# mxsec baseline 规则来源说明

本目录 (`plugins/baseline/config/cis/`) 的基线规则集 **借鉴自 Elkeid 项目** (字节跳动开源):

- 上游: <https://github.com/bytedance/Elkeid>
- 上游路径: `Elkeid/plugins/baseline/config/linux/{1200,1300,1400,5000}.yaml`
- License: Apache License 2.0
- 借鉴方式: YAML 转 JSON (`cmd/tools/baseline-import`), schema 适配 mxsec, 中文字段保留
- 借鉴日期: 2026-06-07

## 转换映射

| Elkeid 字段 | mxsec 字段 |
|---|---|
| baseline_id | Policy.ID |
| baseline_name + baseline_name_en | Policy.Name + Description |
| system | Policy.OSFamily |
| check_id | Rule.RuleID 后缀 |
| title_cn / title | Rule.Title |
| description_cn / description | Rule.Description |
| solution_cn / solution | Rule.Fix.Suggestion |
| security | Rule.Severity |
| type_cn / type | Rule.Category |
| check.rules[].type=file_line_check | CheckRule.Type=file_line_expr |
| check.rules[].type=command_check | CheckRule.Type=command_exec |
| check.rules[].type=file_permission | CheckRule.Type=file_permission |
| filter | CheckRule.Param[1] |
| result | CheckRule.Result |

## file_line_expr 表达式语法 (兼容 Elkeid)

| 表达式 | 含义 |
|---|---|
| `$(<=)N` `$(>=)N` `$(=)N` `$(!=)N` `$(<)N` `$(>)N` | 数值比较 (filter group1) |
| `$(not)REGEX` | 文件不含此正则 |
| `$(EXPR1)$(&&)$(EXPR2)` | 与 |
| `$(EXPR1)$(\|\|)$(EXPR2)` | 或 |

实现见 `plugins/baseline/engine/checker_file_line_expr.go`。

## 规则数量

| 文件 | OS | 规则数 |
|---|---|---|
| centos.json | centos / rocky / almalinux / oracle / rhel | 16 |
| debian.json | debian | 17 |
| ubuntu.json | ubuntu | 17 |
| weakpassword.json | (跨 OS, 弱口令 detector 占位) | 0 (后端 detector 实现) |
| **合计** | | **50** |

## 后续

- MVP-2b: 补足 150 条手写规则覆盖等保 2.0 三级 + CIS RHEL L1, 总计 200+
- M1: Windows Server / 信创 OS (Kylin / UOS / openEuler) 基线
- M1: 中间件基线 (Nginx / Apache / Tomcat / MySQL, 各 40 条)

## License

引用规则正文受 Apache License 2.0 保护, 请勿删除本 NOTICE 与各 JSON 文件的 description 字段中的 "借鉴 Elkeid" 标注。
