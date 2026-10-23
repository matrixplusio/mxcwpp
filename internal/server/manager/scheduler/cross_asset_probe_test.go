package scheduler

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func src(addr string) probeSource {
	return probeSource{Addr: addr, Hosts: 4, Roles: 2, Pairs: 12, Conns: 20, HostID: "h1", Hostnames: []string{"web-01", "db-01"}}
}

// 内网与白名单来源不出告警；零散来源各一条；达标网段一条，网段里的地址不再单独出。
// 不按网段归并的话，同一拨人换着地址来，就会变成几十条互不相干的告警。
func TestBuildProbeAlerts(t *testing.T) {
	_, trusted, _ := net.ParseCIDR("198.51.100.0/24")
	sources := []probeSource{
		src("10.0.0.5"),      // 内网
		src("198.51.100.20"), // 白名单
		src("203.0.113.9"),   // 零散外部来源
		src("192.0.2.7"),     // 落在达标网段里
	}
	nets := []probeSource{
		{Addr: "192.0.2.0/24", Addrs: 36, Hosts: 16, Roles: 12, Pairs: 93, Conns: 169, HostID: "h1", Hostnames: []string{"web-01"}},
		{Addr: "198.51.100.0/24", Addrs: 9, Hosts: 5, Roles: 4, Pairs: 20, Conns: 40, HostID: "h1"}, // 白名单网段
	}

	alerts := buildProbeAlerts(sources, nets, []*net.IPNet{trusted}, model.ToLocalTime(time.Now()))

	byID := map[string]model.Alert{}
	for _, a := range alerts {
		byID[a.ResultID] = a
		if a.RuleID != ProbeRuleID || a.Severity != "medium" || a.HostID != "h1" {
			t.Errorf("告警字段不对: %+v", a)
		}
	}
	if len(alerts) != 2 {
		t.Fatalf("应得 2 条（一条网段、一条单地址），得 %d: %v", len(alerts), byID)
	}
	if a, ok := byID["scan-probe-net-192.0.2.0/24"]; !ok || !strings.Contains(a.Title, "36 个地址") {
		t.Errorf("达标网段应出一条网段告警: %v", byID)
	}
	if _, ok := byID["scan-probe-203.0.113.9"]; !ok {
		t.Errorf("零散来源应单独一条: %v", byID)
	}
}

// 查询里的问号必须恰好等于传入的参数个数。
// 驱动连字符串字面量里的问号也当占位符：多一个，查询在运行时整条失败，而编译与其它测试都看不出来。
func TestProbeQueriesPlaceholderCount(t *testing.T) {
	for name, c := range map[string]struct {
		query string
		args  int
	}{
		"source": {probeSourceQuery, 3},
		"net":    {probeNetQuery, 4},
	} {
		if got := strings.Count(c.query, "?"); got != c.args {
			t.Errorf("%s 查询有 %d 个问号，但只传 %d 个参数", name, got, c.args)
		}
	}
}
