package collector

import "testing"

// buildQuestion 组装一段 DNS 报文：12 字节头部 + 单个 question。
func buildQuestion(flags uint16, labels []string, qtype uint16) []byte {
	p := []byte{
		0x12, 0x34, // ID
		byte(flags >> 8), byte(flags), // Flags
		0x00, 0x01, // QDCount = 1
		0x00, 0x00, // ANCount
		0x00, 0x00, // NSCount
		0x00, 0x00, // ARCount
	}
	for _, l := range labels {
		p = append(p, byte(len(l)))
		p = append(p, []byte(l)...)
	}
	p = append(p, 0x00)                        // root label
	p = append(p, byte(qtype>>8), byte(qtype)) // QTYPE
	p = append(p, 0x00, 0x01)                  // QCLASS = IN
	return p
}

func TestParseDNS_QueryAndResponse(t *testing.T) {
	cases := []struct {
		name     string
		payload  []byte
		wantNil  bool
		domain   string
		qtype    string
		rcode    int
		rcodeStr string
		isQuery  bool
	}{
		{
			name:     "标准 A 查询",
			payload:  buildQuestion(0x0100, []string{"example", "com"}, 1),
			domain:   "example.com",
			qtype:    "A",
			rcode:    0,
			rcodeStr: "NOERROR",
			isQuery:  true,
		},
		{
			name:     "AAAA 响应 NXDOMAIN",
			payload:  buildQuestion(0x8183, []string{"no", "such"}, 28),
			domain:   "no.such",
			qtype:    "AAAA",
			rcode:    3,
			rcodeStr: "NXDOMAIN",
			isQuery:  false,
		},
		{
			name:    "报文过短",
			payload: []byte{0x00, 0x01, 0x02},
			wantNil: true,
		},
		{
			name: "QDCount 为 0",
			payload: []byte{
				0x12, 0x34, 0x01, 0x00,
				0x00, 0x00, // QDCount = 0
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
			wantNil: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ParseDNS(c.payload)
			if c.wantNil {
				if got != nil {
					t.Fatalf("期望 nil，得到 %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatalf("期望非 nil 结果")
			}
			if got.Domain != c.domain || got.QType != c.qtype ||
				got.RCode != c.rcode || got.RCodeStr != c.rcodeStr || got.IsQuery != c.isQuery {
				t.Fatalf("结果不符: got %+v want domain=%s qtype=%s rcode=%d rcodeStr=%s isQuery=%v",
					got, c.domain, c.qtype, c.rcode, c.rcodeStr, c.isQuery)
			}
		})
	}
}

func TestParseDomainName_Compression(t *testing.T) {
	// 目标名 "com" 放在偏移 0，随后 "www" + 指向偏移 0 的压缩指针。
	payload := []byte{
		0x03, 'c', 'o', 'm', 0x00, // offset 0: "com"
		0x03, 'w', 'w', 'w', 0xC0, 0x00, // offset 5: "www" + pointer→0
	}
	domain, next := parseDomainName(payload, 5)
	if domain != "www.com" {
		t.Fatalf("压缩解析: got %q want www.com", domain)
	}
	// 压缩场景下应返回指针之后的偏移（跳过 2 字节指针），而非跳转目标处。
	if next != 11 {
		t.Fatalf("压缩后偏移: got %d want 11", next)
	}
}

func TestParseDomainName_PointerLoop(t *testing.T) {
	// 指针指向自身，必须检测循环并返回错误偏移，而不是死循环。
	payload := []byte{0xC0, 0x00}
	domain, next := parseDomainName(payload, 0)
	if domain != "" || next != -1 {
		t.Fatalf("循环指针应返回 (\"\", -1)，得到 (%q, %d)", domain, next)
	}
}

func TestQtypeToString(t *testing.T) {
	cases := map[uint16]string{
		1:   "A",
		5:   "CNAME",
		15:  "MX",
		28:  "AAAA",
		255: "ANY",
		999: "TYPE999", // 未知类型走默认分支
	}
	for in, want := range cases {
		if got := qtypeToString(in); got != want {
			t.Errorf("qtypeToString(%d)=%q want %q", in, got, want)
		}
	}
}

func TestRcodeToString(t *testing.T) {
	cases := map[int]string{
		0:  "NOERROR",
		2:  "SERVFAIL",
		3:  "NXDOMAIN",
		5:  "REFUSED",
		11: "RCODE11", // 未知 rcode 走默认分支
	}
	for in, want := range cases {
		if got := rcodeToString(in); got != want {
			t.Errorf("rcodeToString(%d)=%q want %q", in, got, want)
		}
	}
}
