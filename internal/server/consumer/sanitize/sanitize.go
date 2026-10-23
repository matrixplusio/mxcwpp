// Package sanitize 提供事件字段脱敏功能
// 在事件数据写入存储前，对 cmdline 等敏感字段进行凭据遮蔽
//
// 脱敏只作用于落库、写 ClickHouse、外发 SIEM 的副本；检测与白名单用的是原始字段，不受影响。
package sanitize

import (
	"bytes"
	"encoding/json"
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

// valuePat 一个参数值：引号包住的整段（可含空格），或到空白与 ; | & 引号为止。
// 不在 ; | & 处截断的话，「X_TOKEN=1;curl …|sh」整条载荷会被当成值抹掉，研判与回溯都看不到。
const valuePat = `(?:'[^']*'|"[^"]*"|[^\s;|&'"]+)`

var (
	// flagValueRe 匹配 --flag=value 和 -flag=value
	flagValueRe *regexp.Regexp
	// flagSpaceRe 匹配 --flag value 和 -flag value
	flagSpaceRe *regexp.Regexp
)

func init() {
	flagNames := strings.Join(sensitiveFlags, "|")
	flagValueRe = regexp.MustCompile(`(?i)(-{1,2}(?:` + flagNames + `))=` + valuePat)
	flagSpaceRe = regexp.MustCompile(`(?i)(-{1,2}(?:` + flagNames + `))\s+` + valuePat)
}

// envKeyValueRe 匹配 KEY=value 形式的环境变量泄漏。变量名允许带前缀（PGPASSWORD、REDIS_TOKEN），
// 否则 PGPASSWORD=… 这种最常见的写法因为前面没有单词边界而漏过。
// 不收单独的 PWD：sudo 日志里的「PWD=/home/…」是当前目录，不是口令。
var envKeyValueRe = regexp.MustCompile(`(?i)\b([A-Z0-9_]*(?:` +
	strings.Join([]string{
		"PASSWORD", "PASSWD", "TOKEN", "SECRET", "API_KEY", "APIKEY",
		"PRIVATE_KEY", "ACCESS_KEY", "SECRET_KEY",
	}, "|") +
	`)=|(?:AUTH|MYSQL_PWD|REDISCLI_AUTH)=)` + valuePat)

// urlCredRe 连接串里的 user:password@host（mysql://、redis://:pass@、amqp://…）。
// 用户名可以为空（redis://:pass@ 是 Redis 的标准写法）；口令可以含 / 与 @，取到最后一个 @。
var urlCredRe = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://[^/\s:@]*:)([^\s'"]*)@([A-Za-z0-9._\[\]-]+)`)

// portPathRe 「host:8080/path@x」里冒号后面是端口加路径，不是口令。
// 必须带路径：纯数字（123456）恰恰是最常见的弱口令，不能当端口放过。
var portPathRe = regexp.MustCompile(`^[0-9]+/`)

// 按程序分段处理的规则：同一个短参数在别的程序里意思不同（ssh -p 是端口、find -perm、cp -p），
// 只遮「这个程序所在的那段命令」——从程序名起，到引号外的下一个 ; | & 或换行为止。
//
// 程序名只要是一个独立的词就算出现，不要求在命令位置：docker exec、kubectl exec --、ssh 主机、
// sudo -u x、xargs、watch 这些包装五花八门，按命令位置列举总有漏的。
// 带路径的：bin/sbin/libexec 目录下的在哪都算；其它目录（./mysql、/tmp/.x/mysqldump，解压即用的发行包、
// 投放的客户端）只在命令位置才算——否则 find /var/lib/mysql -perm 里的数据目录也成了程序名。
type progRule struct {
	hint      string // 小写子串预筛，没有就不跑正则
	prog      *regexp.Regexp
	flags     *regexp.Regexp
	mask      func(m []string) string
	firstOnly bool // 只遮这段里的第一处（sshpass 后面的 ssh -p 是端口）
}

const cmdPos = `(?:(?:^|[\s;|&(` + "`" + `'"=])(?:\S*/(?:s?bin|libexec)/)?|(?:^|[;|&(\n` + "`" + `'"]|-[a-z]*c\s)\s*\S*/)`

var progRules = []progRule{
	{
		hint: "mysql|mariadb",
		prog: regexp.MustCompile(cmdPos + `(?:mysql|mysqldump|mysqladmin|mysqlimport|mysqlshow|mysqlcheck|mysqlpump|mysqlbinlog|mysqlsh|mariadb|mariadb-dump|mariadb-admin|mariadb-import|mariadb-check)(?:\s|$)`),
		// mysql 的 -p 紧跟口令（-pSecret、-p'Secret'），中间没有空格。-P（大写）是端口，不动。
		flags: regexp.MustCompile(`(\s)-p(` + valuePat + `)`),
		mask: func(m []string) string {
			v := m[2]
			// -password / -pass 这类是参数名本身（值已由通用规则遮过），不是紧跟的口令。
			if v == maskValue || isSensitiveFlag("p"+v) {
				return m[0]
			}
			return m[1] + "-p" + maskValue
		},
	},
	{
		hint:  "redis-cli",
		prog:  regexp.MustCompile(cmdPos + `redis-cli(?:\s|$)`),
		flags: regexp.MustCompile(`(\s)-a\s+(` + valuePat + `)`),
		mask:  func(m []string) string { return m[1] + "-a " + maskValue },
	},
	{
		hint:      "sshpass",
		prog:      regexp.MustCompile(cmdPos + `sshpass(?:\s|$)`),
		flags:     regexp.MustCompile(`(\s)-p\s*(` + valuePat + `)`),
		mask:      func(m []string) string { return m[1] + "-p " + maskValue },
		firstOnly: true,
	},
}

// Cmdline 对命令行字符串进行凭据脱敏
// 规则：
//  1. --password=xxx → --password=***；--password xxx → --password ***
//  2. PASSWORD=xxx、PGPASSWORD=xxx → …=***（环境变量泄漏）
//  3. scheme://user:xxx@host → scheme://user:***@host
//  4. 只在对应程序的那段命令里：mysql 一族 -pxxx、redis-cli -a xxx、sshpass -p xxx
//
// 每条规则先用子串预筛，命令行里没有相关字样就不跑正则：这在每条进程事件上执行。
func Cmdline(cmdline string) string {
	if cmdline == "" {
		return cmdline
	}
	result := cmdline
	hasEq := strings.IndexByte(result, '=') >= 0
	if hasEq {
		result = flagValueRe.ReplaceAllStringFunc(result, func(m string) string {
			return m[:strings.IndexByte(m, '=')+1] + maskValue
		})
	}
	if strings.Contains(result, "-") {
		result = flagSpaceRe.ReplaceAllStringFunc(result, func(m string) string {
			sm := flagSpaceRe.FindStringSubmatch(m)
			return sm[1] + " " + maskValue
		})
	}
	if hasEq {
		result = envKeyValueRe.ReplaceAllStringFunc(result, func(m string) string {
			return m[:strings.IndexByte(m, '=')+1] + maskValue
		})
	}
	if strings.Contains(result, "://") {
		result = urlCredRe.ReplaceAllStringFunc(result, func(m string) string {
			sm := urlCredRe.FindStringSubmatch(m)
			if sm[2] == "" || sm[2] == maskValue || portPathRe.MatchString(sm[2]) {
				return m
			}
			return sm[1] + maskValue + "@" + sm[3]
		})
	}
	lower := strings.ToLower(result)
	for _, r := range progRules {
		if !containsAny(lower, r.hint) {
			continue
		}
		result = maskProgSegments(result, r)
	}
	return result
}

// maskProgSegments 在程序所在的每一段命令里套用它的参数规则。
func maskProgSegments(s string, r progRule) string {
	locs := r.prog.FindAllStringIndex(s, -1)
	if locs == nil {
		return s
	}
	var b strings.Builder
	prev := 0
	for _, loc := range locs {
		start := loc[1] - 1 // 程序名后面那个空白字符，flags 规则要求以空白开头
		if loc[1] == len(s) || start < prev {
			continue
		}
		// 程序名前面紧挨着的引号是 sh -c '…' 的外层引号，它的另一半也是段尾。
		var outer byte
		if loc[0] < len(s) && (s[loc[0]] == '\'' || s[loc[0]] == '"') {
			outer = s[loc[0]]
		}
		end := segmentEnd(s, loc[1], outer)
		b.WriteString(s[prev:start])
		seg := s[start:end]
		done := false
		b.WriteString(r.flags.ReplaceAllStringFunc(seg, func(m string) string {
			if done {
				return m
			}
			done = r.firstOnly
			return r.mask(r.flags.FindStringSubmatch(m))
		}))
		prev = end
	}
	b.WriteString(s[prev:])
	return b.String()
}

// segmentEnd 从 from 起找这段命令的结尾：引号外的 ; | & 或换行，或者外层引号的另一半。
// 引号里的分隔符不算（mysql -e "use db; show tables" -pX 的口令在分号后面）；
// 反斜杠转义的字符不算（日志原文里的 \"）。引号到行尾都没闭合时，按忽略引号的第一个分隔符截断，
// 免得一直延伸到行尾、把后面别的程序的 -p 也遮掉。
func segmentEnd(s string, from int, outer byte) int {
	var q byte
	for i := from; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && outer == '"' && q != '\'' && i+1 < len(s) && s[i+1] == '"':
			// 外层双引号里的 \" 是内层命令的一对引号：sh -c "mysql -e \"use db;\" -pX"
			i++
			if q == 'e' {
				q = 0
			} else if q == 0 {
				q = 'e'
			}
		case c == '\\' && q != '\'':
			i++
		case q == 'e':
			// 内层（转义）引号里，等对应的 \" 收尾，其余一律不算分隔
		case q != 0:
			if c == q {
				q = 0
			}
		case outer != 0 && c == outer:
			return i
		case c == '\'' || c == '"':
			q = c
		case c == ';' || c == '|' || c == '&' || c == '\n':
			return i
		}
	}
	if q != 0 {
		if i := strings.IndexAny(s[from:], ";|&\n"); i >= 0 {
			return from + i
		}
	}
	return len(s)
}

func containsAny(lower, hints string) bool {
	for _, h := range strings.Split(hints, "|") {
		if strings.Contains(lower, h) {
			return true
		}
	}
	return false
}

func isSensitiveFlag(name string) bool {
	name = strings.ToLower(name)
	for _, f := range sensitiveFlags {
		if f == name {
			return true
		}
	}
	return false
}

// commandFields 会装着命令行的字段。入侵检测类告警把命令行放在 content，认证事件放在 command，
// 只处理 cmdline 的话这些都原样落库。
var commandFields = map[string]bool{"cmdline": true, "command": true, "content": true, "parent_cmdline": true}

// Fields 对事件字段 map 中装着命令行的字段脱敏（原地修改）。
func Fields(fields map[string]string) {
	for k, v := range fields {
		if commandFields[k] && v != "" {
			fields[k] = Cmdline(v)
		}
	}
}

// JSON 对任意 JSON 里（任意层级）装着命令行的字段脱敏，返回重新编码的结果。
//
// 检测阶段的告警详情常带数字、数组、嵌套对象，解不成 map[string]string；只处理扁平结构的话，
// 这类详情会原样落库。解不开（不是合法 JSON）时 ok 为 false，调用方自行决定怎么办。
func JSON(raw []byte) (out []byte, ok bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber() // 数字原样保留，不变成 float
	var v any
	if err := dec.Decode(&v); err != nil {
		return raw, false
	}
	walk(v)
	b, err := json.Marshal(v)
	if err != nil {
		return raw, false
	}
	return b, true
}

func walk(v any) {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			if s, isStr := x.(string); isStr && commandFields[k] && s != "" {
				t[k] = Cmdline(s)
				continue
			}
			walk(x)
		}
	case []any:
		for _, x := range t {
			walk(x)
		}
	}
}
