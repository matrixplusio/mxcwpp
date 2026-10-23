package notify

import (
	"errors"
	"net/url"
	"path"
	"regexp"
	"strings"
)

// 通知渠道的地址本身就是凭据：飞书、钉钉这类机器人 webhook 的令牌在 URL 路径或查询串里。
// 发送失败的错误文本会进投递记录、事件表、日志，还会经接口返回，所以其中不能带完整地址。

// urlPattern 匹配文本里的 http(s) 地址，含大写协议名与 JSON 里转义过斜杠的写法（https:\/\/）。
// RE2 语法、无回溯，输入长度不构成风险。
var urlPattern = regexp.MustCompile(`(?i)https?:(?://|\\/\\/)[^\s"'<>]+`)

// RedactURLs 把文本里的地址换成「协议://主机/…」：留下主机便于排查是哪个渠道，路径与查询串一律去掉。
func RedactURLs(s string) string {
	return urlPattern.ReplaceAllStringFunc(s, func(raw string) string {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return "<地址已隐藏>"
		}
		return u.Scheme + "://" + u.Host + "/…"
	})
}

// sendErrorText 取发送失败的原因。
//
// http.Client 返回的是 *url.Error，Error() 的格式是「Post "<完整地址>": <原因>」；
// 只取原因那一半，再整体过一遍 RedactURLs 兜底（原因里偶尔也会带地址，如重定向失败）。
func sendErrorText(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) && ue.Err != nil {
		err = ue.Err
	}
	return RedactURLs(err.Error())
}

// redactFor 处理对端的响应体：先把这个渠道地址里的路径、末段与查询值按字面量抹掉，再过 RedactURLs。
//
// 只靠通用正则不够：对端常常只回显路径（Cannot POST /hook/<令牌>）或单独回显查询参数，
// 里面没有协议头，正则认不出那是地址的一部分。
func redactFor(webhookURL, s string) string {
	u, err := url.Parse(webhookURL)
	if err != nil {
		return RedactURLs(s)
	}
	var lits []string
	if len(u.Path) > 1 {
		lits = append(lits, u.Path, u.EscapedPath(), strings.ReplaceAll(u.Path, "/", `\/`), url.QueryEscape(u.Path))
		// 末段通常就是令牌，可能脱离路径被单独回显；太短的不替换，免得把正文打碎
		if seg := path.Base(u.Path); len(seg) >= 8 {
			lits = append(lits, seg)
		}
	}
	for _, vs := range u.Query() {
		for _, v := range vs {
			if len(v) >= 8 {
				lits = append(lits, v, url.QueryEscape(v))
			}
		}
	}
	for _, l := range lits {
		if l != "" {
			s = strings.ReplaceAll(s, l, "…")
		}
	}
	return RedactURLs(s)
}
