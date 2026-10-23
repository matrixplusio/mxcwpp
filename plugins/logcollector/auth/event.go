// Package auth 采集并解析主机的系统认证日志（登录、sudo、su、账号变更）。
package auth

import (
	"strconv"
	"time"
)

// DataTypeAuthEvent 认证事件的 DataType。
//
// 放在内核事件段（3000-3099）里是有意的：agent 的发送缓冲满时，只有这一段的数据会
// 落盘、重连后补发，其它插件数据直接丢弃。认证日志在被爆破时量最大、最容易挤满缓冲，
// 而那正是最不能丢的时候。
const DataTypeAuthEvent int32 = 3020

// 事件类型。写进 event_type 字段，与内核事件的 event_type 同一个命名空间。
const (
	KindLoginSuccess  = "auth_login_success"
	KindLoginFailed   = "auth_login_failed"
	KindPreauthClose  = "auth_preauth_close" // 认证完成前断开：密钥探测、扫描器
	KindSessionOpen   = "auth_session_open"
	KindSessionClose  = "auth_session_close"
	KindSudo          = "auth_sudo"
	KindSudoDenied    = "auth_sudo_denied"
	KindSuSuccess     = "auth_su_success"
	KindSuFailed      = "auth_su_failed"
	KindAccountChange = "auth_account_change"
	KindStats         = "auth_collector_stats" // 插件自身的丢弃统计
	KindHeartbeat     = "auth_collector_heartbeat"
)

// 来源可信度。
const (
	// TrustJournal 来自 journald，且写入进程的程序路径与身份经校验（这部分由内核填写，伪造不了）。
	TrustJournal = "journal"
	// TrustFile 来自日志文件。本机任何用户都能用 logger 往里写任意内容，包括伪造进程名。
	TrustFile = "file"
)

// Entry 一条待解析的日志记录，与来源无关。
type Entry struct {
	Time    time.Time
	Ident   string // 写入进程的名字：sshd / sudo / su / useradd …
	PID     int
	Message string
	Trust   string
}

// Event 一条结构化的认证事件。
type Event struct {
	Kind    string
	Time    time.Time
	Service string // sshd / sudo / su / useradd …
	PID     int
	Trust   string

	Username   string // 行为主体：登录的账号、执行 sudo 的人、被创建的账号
	TargetUser string // sudo / su 的目标身份
	SourceIP   string
	SourcePort string
	Method     string // password / publickey / keyboard-interactive …
	KeyFP      string // 登录所用公钥的指纹
	Reason     string // 失败原因；账号变更的具体动作
	Invalid    bool   // 登录失败时该账号在本机并不存在
	TTY        string
	Cwd        string
	Command    string
	Detail     string // 账号变更的补充信息（用户组等）
	Raw        string // 原始内容，截断后保留供取证

	// Count 合并上报时本条代表的次数，未合并为 1。
	Count int

	// Extra 只有心跳用：读取位置与计数。不覆盖上面的同名字段。
	Extra map[string]string
}

const rawMaxLen = 512

// DetailAmbiguousFields sudo 日志里出现了重复的字段名，解析出的目录、目标用户、命令不可信。
const DetailAmbiguousFields = "ambiguous_fields"

// Fields 转成上报用的字段表。空值不写，减小体积。
func (e *Event) Fields() map[string]string {
	f := map[string]string{
		"event_type": e.Kind,
		"service":    e.Service,
		"trust":      e.Trust,
		"timestamp":  strconv.FormatInt(e.Time.Unix(), 10),
	}
	put := func(k, v string) {
		if v != "" {
			f[k] = v
		}
	}
	if e.PID > 0 {
		f["pid"] = strconv.Itoa(e.PID)
	}
	put("username", e.Username)
	put("target_user", e.TargetUser)
	put("source_ip", e.SourceIP)
	put("source_port", e.SourcePort)
	put("auth_method", e.Method)
	put("key_fingerprint", e.KeyFP)
	put("reason", e.Reason)
	put("tty", e.TTY)
	put("cwd", e.Cwd)
	put("command", e.Command)
	put("detail", e.Detail)
	if e.Invalid {
		f["invalid_user"] = "true"
	}
	count := e.Count
	if count < 1 {
		count = 1
	}
	f["count"] = strconv.Itoa(count)
	raw := e.Raw
	if len(raw) > rawMaxLen {
		raw = raw[:rawMaxLen]
	}
	put("raw", raw)
	for k, v := range e.Extra {
		if _, taken := f[k]; !taken {
			f[k] = v
		}
	}
	return f
}
