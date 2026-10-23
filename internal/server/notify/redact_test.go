package notify

import (
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

const fakeHookToken = "0f1e2d3c-token-must-not-leak"

// TestRedactURLs 地址只留协议和主机，路径与查询串里的令牌全部去掉。
func TestRedactURLs(t *testing.T) {
	in := `Post "https://open.example.com/open-apis/bot/v2/hook/` + fakeHookToken + `?key=` + fakeHookToken + `": dial tcp: i/o timeout`
	got := RedactURLs(in)
	if strings.Contains(got, fakeHookToken) || strings.Contains(got, "/hook/") {
		t.Fatalf("脱敏后仍含令牌或路径: %s", got)
	}
	if !strings.Contains(got, "https://open.example.com/…") || !strings.Contains(got, "i/o timeout") {
		t.Fatalf("应保留主机与失败原因: %s", got)
	}
	if RedactURLs("webhook 500") != "webhook 500" {
		t.Fatal("没有地址的文本不应被改动")
	}
}

// TestPostWith_ErrorOmitsWebhookURL 真实的连接失败：http.Client 返回的错误文本自带完整地址，
// 包装后的错误里不能再有它。这段文本会进投递记录、日志并经接口返回。
func TestPostWith_ErrorOmitsWebhookURL(t *testing.T) {
	// 占一个端口再关掉，保证连接被拒绝
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()

	s := NewNotificationService(nil, zap.NewNop())
	err = s.postWith(&http.Client{Timeout: 2 * time.Second},
		"http://"+addr+"/open-apis/bot/v2/hook/"+fakeHookToken, map[string]interface{}{"k": "v"})
	if err == nil {
		t.Fatal("应连接失败")
	}
	if strings.Contains(err.Error(), fakeHookToken) || strings.Contains(err.Error(), "/hook/") {
		t.Fatalf("错误文本泄露了 webhook 地址: %v", err)
	}
	if !strings.Contains(err.Error(), "refused") {
		t.Fatalf("应保留失败原因: %v", err)
	}
}

// TestRedactURLs_EscapedAndUppercase JSON 里转义过斜杠的地址、大写协议名同样要认出来。
func TestRedactURLs_EscapedAndUppercase(t *testing.T) {
	for _, in := range []string{
		`{"url":"https:\/\/open.example.com\/hook\/` + fakeHookToken + `"}`,
		`HTTPS://open.example.com/hook/` + fakeHookToken,
	} {
		if got := RedactURLs(in); strings.Contains(got, fakeHookToken) {
			t.Errorf("脱敏后仍含令牌: %s", got)
		}
	}
}

// TestRedactFor_BodyEchoesPathOrToken 对端只回显路径、末段令牌或查询参数时没有协议头，
// 通用正则认不出来，要靠这个渠道自己的地址按字面量抹掉。
func TestRedactFor_BodyEchoesPathOrToken(t *testing.T) {
	hook := "https://open.example.com/open-apis/bot/v2/hook/" + fakeHookToken + "?access_token=" + fakeHookToken + "x"
	for _, body := range []string{
		"Cannot POST /open-apis/bot/v2/hook/" + fakeHookToken,
		`{"status":404,"path":"\/open-apis\/bot\/v2\/hook\/` + fakeHookToken + `"}`,
		"invalid token " + fakeHookToken,
		"bad access_token=" + fakeHookToken + "x",
		"%2Fopen-apis%2Fbot%2Fv2%2Fhook%2F" + fakeHookToken,
	} {
		if got := redactFor(hook, body); strings.Contains(got, fakeHookToken) {
			t.Errorf("响应体脱敏后仍含令牌: %q → %q", body, got)
		}
	}
	if got := redactFor(hook, `{"code":19001,"msg":"param invalid"}`); got != `{"code":19001,"msg":"param invalid"}` {
		t.Errorf("不含地址的响应体不应被改动: %s", got)
	}
}
