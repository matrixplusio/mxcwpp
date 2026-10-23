package writer

import (
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/matrixplusio/mxcwpp/api/proto/bridge"
	"github.com/matrixplusio/mxcwpp/internal/server/common/kafka"
)

func authMsg(t *testing.T, fields map[string]string) *kafka.MQMessage {
	t.Helper()
	body, err := proto.Marshal(&bridge.Record{DataType: 3020, Data: &bridge.Payload{Fields: fields}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return &kafka.MQMessage{DataType: 3020, AgentID: "h1", Hostname: "web-01", AgentTime: 1760009999, Body: body}
}

func TestParseAuthEvent(t *testing.T) {
	row, ok := parseAuthEvent(authMsg(t, map[string]string{
		"event_type": "auth_login_failed", "service": "sshd", "trust": "journal",
		"username": "admin", "source_ip": "203.0.113.9", "source_port": "4022",
		"auth_method": "password", "reason": "password", "invalid_user": "true",
		"count": "37", "timestamp": "1760000000", "pid": "4321",
	}))
	if !ok {
		t.Fatal("应解析成功")
	}
	if row.HostID != "h1" || row.Hostname != "web-01" || row.EventType != "auth_login_failed" ||
		row.Username != "admin" || row.SourceIP != "203.0.113.9" || row.InvalidUser != 1 || row.Count != 37 {
		t.Fatalf("字段不符：%+v", row)
	}
	// 时间取事件在主机上发生的时间，不是到达时间：补发的事件会晚到很久。
	if row.Timestamp.Unix() != 1760000000 {
		t.Errorf("时间应取事件自带的：%v", row.Timestamp)
	}
}

// sudo 命令行里的口令入库前要遮掉，原文那一列也一样。
func TestParseAuthEventMasksSecrets(t *testing.T) {
	row, ok := parseAuthEvent(authMsg(t, map[string]string{
		"event_type": "auth_sudo", "username": "alice", "target_user": "root",
		"command": "/usr/bin/mysql -uroot --password=hunter2 -e status",
		"raw":     "alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/mysql -uroot --password=hunter2 -e status",
	}))
	if !ok {
		t.Fatal("应解析成功")
	}
	for name, v := range map[string]string{"command": row.Command, "raw": row.Raw} {
		if contains(v, "hunter2") {
			t.Errorf("%s 里的口令没有被遮掉：%s", name, v)
		}
	}
}

func TestParseAuthEventDefaultsAndLimits(t *testing.T) {
	row, ok := parseAuthEvent(authMsg(t, map[string]string{"event_type": "auth_sudo", "count": "0"}))
	if !ok || row.Count != 1 || row.Timestamp.Unix() != 1760009999 {
		t.Fatalf("缺省值不对：%+v", row)
	}
	long := make([]byte, authFieldMaxLen*3)
	for i := range long {
		long[i] = 'a'
	}
	row, _ = parseAuthEvent(authMsg(t, map[string]string{"event_type": "auth_sudo", "cwd": string(long)}))
	if len(row.Cwd) != authFieldMaxLen {
		t.Errorf("超长字段应截断到 %d，得 %d", authFieldMaxLen, len(row.Cwd))
	}
	if _, ok := parseAuthEvent(authMsg(t, map[string]string{"username": "x"})); ok {
		t.Error("没有事件类型的记录不该入库")
	}
	if _, ok := parseAuthEvent(&kafka.MQMessage{DataType: 3020}); ok {
		t.Error("空消息不该入库")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// received_at 取 AgentCenter 收到消息的时间，不是主机自报的 timestamp。
func TestParseAuthEventKeepsServerReceiveTime(t *testing.T) {
	msg := authMsg(t, map[string]string{"event_type": "auth_login_success", "timestamp": "1000"})
	recv := time.Date(2026, 10, 22, 8, 0, 0, 0, time.UTC)
	msg.ReceivedAt = recv
	row, ok := parseAuthEvent(msg)
	if !ok || !row.ReceivedAt.Equal(recv) || row.Timestamp.Unix() != 1000 {
		t.Fatalf("got ok=%v received_at=%v timestamp=%v", ok, row.ReceivedAt, row.Timestamp)
	}

	// 加列之前转存的数据回放时没有接收时间，不能写成 1970 年。
	old := authEventRow{EventType: "auth_sudo"}
	old.normalize()
	if old.ReceivedAt.IsZero() {
		t.Fatal("回放的旧数据应补上接收时间")
	}
}

// auth_events 改用只写账号后，其它表仍走主连接；没配时沿用主连接。
func TestAuthEventsUseDedicatedConn(t *testing.T) {
	w := &ClickHouseWriter{}
	if w.connFor("auth_events") != nil {
		t.Fatal("没配独立连接时沿用主连接")
	}
	auth := &fakeConn{}
	w.WithAuthConn(auth)
	if w.connFor("auth_events") != auth {
		t.Fatal("auth_events 应走独立连接")
	}
	if w.connFor("ebpf_events") == auth {
		t.Fatal("其它表不该走认证事件的写入账号")
	}
}
