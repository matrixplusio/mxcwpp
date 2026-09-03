// Package sanitize 提供事件字段脱敏功能
// 在事件数据写入存储前，对 cmdline 等敏感字段进行凭据遮蔽
package sanitize

import (
	"regexp"
	"strings"
)

// sensitiveFlags 需要脱敏的命令行参数名（小写匹配）
var sensitiveFlags = []string{
	"password", "passwd", "pass",
	"token", "secret", "key", "apikey", "api_key", "api-key",
	"auth", "authorization",
	"credential", "credentials",
	"private-key", "private_key",
	"access-key", "access_key",
	"secret-key", "secret_key",
	"db-password", "db_password",
	"mysql-password", "mysql_password",
}

const maskValue = "***"

// flagValueRe 匹配 --flag=value 和 -flag=value 模式
var flagValueRe *regexp.Regexp

// flagSpaceRe 匹配 --flag value 和 -flag value 模式（flag 后跟空格再跟值）
var flagSpaceRe *regexp.Regexp

func init() {
	// 构建正则：匹配 --password=xxx 或 -password=xxx
	flagNames := strings.Join(sensitiveFlags, "|")
	flagValueRe = regexp.MustCompile(`(?i)(-{1,2}(?:` + flagNames + `))=(\S+)`)
	flagSpaceRe = regexp.MustCompile(`(?i)(-{1,2}(?:` + flagNames + `))\s+(\S+)`)
}

// envKeyValueRe 匹配 KEY=value 形式的环境变量泄漏
var envKeyValueRe = regexp.MustCompile(`(?i)\b((?:` +
	strings.Join([]string{
		"PASSWORD", "PASSWD", "TOKEN", "SECRET", "API_KEY", "APIKEY",
		"AUTH", "PRIVATE_KEY", "ACCESS_KEY", "SECRET_KEY",
		"DB_PASSWORD", "MYSQL_PASSWORD", "AWS_SECRET_ACCESS_KEY",
	}, "|") +
	`)=)(\S+)`)

// Cmdline 对命令行字符串进行凭据脱敏
// 规则：
//  1. --password=xxx → --password=***
//  2. --password xxx → --password ***
//  3. PASSWORD=xxx → PASSWORD=***（环境变量泄漏）
func Cmdline(cmdline string) string {
	if cmdline == "" {
		return cmdline
	}
	result := flagValueRe.ReplaceAllString(cmdline, "${1}="+maskValue)
	result = flagSpaceRe.ReplaceAllString(result, "${1} "+maskValue)
	result = envKeyValueRe.ReplaceAllString(result, "${1}"+maskValue)
	return result
}

// Fields 对事件字段 map 中的敏感字段进行脱敏（原地修改）
// 目前只处理 cmdline 字段
func Fields(fields map[string]string) {
	if v, ok := fields["cmdline"]; ok && v != "" {
		fields["cmdline"] = Cmdline(v)
	}
}
