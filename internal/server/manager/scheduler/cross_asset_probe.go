package scheduler

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// 低频跨资产探测：端口扫描检测按「单主机 60 秒内的不同端口数」判定，
// 一个来源每台主机只碰几个端口、拉长到一天，或者把动作分散到同一网段的几十个地址上，
// 每一条都在阈值以下，于是完全没有告警。这里把最近一天的入站连接按来源汇总，
// 补上这一类。
const (
	probeInterval = 10 * time.Minute
	probeWindow   = 24 * time.Hour
	// probeMinRoles 来源至少碰到几种角色的主机才算跨资产。
	//
	// 不能用主机数：对外服务通常是几台同构节点一组，真实用户会把一组里的每台都连上。
	// 用户停在一组服务里，探测暴露面的来源才会跨到不同角色的主机上。
	// 角色按主机名去掉末尾编号粗略推得，命名不规范的主机会各算一种。
	probeMinRoles = 2
	// probeMinPairs 来源至少碰到几个不同的「主机:端口」。
	probeMinPairs = 10
	// 网段一路的门槛。分散到几十个地址上的探测，单个地址一天碰不到 probeMinPairs 个端口，
	// 走不到单地址那一路，所以按 /24 另行汇总；门槛比单地址高，挡掉偶然落在同一网段的零星来源。
	probeNetMinAddrs = 5
	probeNetMinRoles = 3
	probeNetMinPairs = 15
	// ProbeRuleID 低频跨资产探测告警的规则 ID。
	ProbeRuleID = "scan-probe"
)

// 两条汇总查询。驱动按位置替换 SQL 里的每一个问号，字符串字面量里的也算——
// 正则里不能出现问号（"可有可无"写成 {0,1}），否则参数个数对不上，查询整条失败。
const (
	probeSourceQuery = `
		SELECT remote_addr,
			uniqExact(host_id) AS hosts,
			uniqExact(replaceRegexpOne(hostname, '-{0,1}[0-9]+$', '')) AS roles,
			uniqExact(host_id, local_port) AS pairs,
			count() AS conns,
			min(host_id) AS hid,
			arraySlice(arraySort(groupUniqArray(hostname)), 1, 12) AS names
		FROM ebpf_events
		WHERE timestamp > now() - INTERVAL ? HOUR
			AND event_type = 'tcp_accept' AND remote_addr != ''
			AND NOT match(remote_addr, '^(10\\.|127\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|169\\.254\\.)')
		GROUP BY remote_addr
		HAVING roles >= ? AND pairs >= ?`
	probeNetQuery = `
		SELECT concat(arrayStringConcat(arraySlice(splitByChar('.', remote_addr), 1, 3), '.'), '.0/24') AS net,
			uniqExact(remote_addr) AS addrs,
			uniqExact(host_id) AS hosts,
			uniqExact(replaceRegexpOne(hostname, '-{0,1}[0-9]+$', '')) AS roles,
			uniqExact(host_id, local_port) AS pairs,
			count() AS conns,
			min(host_id) AS hid,
			arraySlice(arraySort(groupUniqArray(hostname)), 1, 12) AS names
		FROM ebpf_events
		WHERE timestamp > now() - INTERVAL ? HOUR
			AND event_type = 'tcp_accept' AND remote_addr != '' AND position(remote_addr, ':') = 0
			AND NOT match(remote_addr, '^(10\\.|127\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|169\\.254\\.)')
		GROUP BY net
		HAVING addrs >= ? AND roles >= ? AND pairs >= ?`
)

// probeSource 是一个外部来源在窗口内的入站汇总。
type probeSource struct {
	Addr      string // 单地址一路是 IP，网段一路是 a.b.c.0/24
	Addrs     uint64 // 网段一路：网段内的不同地址数
	Hosts     uint64
	Roles     uint64
	Pairs     uint64
	Conns     uint64
	HostID    string   // 用来挂告警的主机（取最小 host_id，保证每轮落到同一台）
	Hostnames []string // 碰到的主机名，仅用于文案
}

// StartCrossAssetProbeScheduler 启动低频跨资产探测调度器。ch 为 nil（未启用 ClickHouse）时不启动。
func StartCrossAssetProbeScheduler(db *gorm.DB, ch chdriver.Conn, logger *zap.Logger) {
	if ch == nil {
		logger.Info("未启用 ClickHouse，低频跨资产探测调度器不启动")
		return
	}
	ticker := time.NewTicker(probeInterval)
	defer ticker.Stop()
	logger.Info("低频跨资产探测调度器已启动", zap.Duration("interval", probeInterval))

	processCrossAssetProbe(db, ch, logger)
	for range ticker.C {
		processCrossAssetProbe(db, ch, logger)
	}
}

func processCrossAssetProbe(db *gorm.DB, ch chdriver.Conn, logger *zap.Logger) {
	sources, err := queryProbeSources(ch)
	if err != nil {
		logger.Warn("查询跨资产探测来源失败", zap.Error(err))
		return
	}
	nets, err := queryProbeNets(ch)
	if err != nil {
		logger.Warn("查询跨资产探测网段失败", zap.Error(err))
		return
	}
	now := model.ToLocalTime(time.Now())
	alerts := buildProbeAlerts(sources, nets, loadTrustedCIDRs(db, logger), now)
	for _, a := range alerts {
		alert := a
		if _, err := model.UpsertGroupedAlert(db, alert.ResultID, func() model.Alert {
			return alert
		}, func(existing *model.Alert) error {
			// 每轮都会重新命中同一来源，只刷新内容，不累加 hit_count：轮数不是命中次数。
			return db.Model(existing).Updates(map[string]any{
				"last_seen_at": now,
				"title":        alert.Title,
				"description":  alert.Description,
			}).Error
		}); err != nil {
			logger.Warn("写入跨资产探测告警失败", zap.String("result_id", alert.ResultID), zap.Error(err))
		}
	}
}

// queryProbeSources 取最近一天满足条件的外部来源。内网与环回在查询里先滤掉，减小分组基数。
func queryProbeSources(ch chdriver.Conn) ([]probeSource, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	rows, err := ch.Query(ctx, probeSourceQuery,
		int(probeWindow.Hours()), probeMinRoles, probeMinPairs)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []probeSource
	for rows.Next() {
		var s probeSource
		if err := rows.Scan(&s.Addr, &s.Hosts, &s.Roles, &s.Pairs, &s.Conns, &s.HostID, &s.Hostnames); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// queryProbeNets 按 /24 汇总最近一天的外部入站，取地址数、角色数、端口数都达标的网段。只看 IPv4。
func queryProbeNets(ch chdriver.Conn) ([]probeSource, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	rows, err := ch.Query(ctx, probeNetQuery,
		int(probeWindow.Hours()), probeNetMinAddrs, probeNetMinRoles, probeNetMinPairs)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []probeSource
	for rows.Next() {
		var s probeSource
		if err := rows.Scan(&s.Addr, &s.Addrs, &s.Hosts, &s.Roles, &s.Pairs, &s.Conns, &s.HostID, &s.Hostnames); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// loadTrustedCIDRs 读取此刻生效的来源白名单（alert_whitelists.source_ip_cidr），与端口扫描检测共用同一份。
func loadTrustedCIDRs(db *gorm.DB, logger *zap.Logger) []*net.IPNet {
	var rows []model.AlertWhitelist
	if err := db.Select("id, source_ip_cidr, enabled, expires_at").
		Where("source_ip_cidr <> ''").Find(&rows).Error; err != nil {
		logger.Warn("加载来源白名单失败，本轮不做白名单过滤", zap.Error(err))
		return nil
	}
	now := time.Now()
	var out []*net.IPNet
	for i := range rows {
		if !rows[i].Active(now) {
			continue
		}
		if _, n, err := net.ParseCIDR(strings.TrimSpace(rows[i].SourceIPCIDR)); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// buildProbeAlerts 把来源汇总转成告警：滤掉内网与白名单来源；地址已被达标网段覆盖的不再单独出。
//
// 网段优先是为了把「几十个地址各出一条」还原成它本来的样子——同一拨人从一个网段轮换着来。
func buildProbeAlerts(sources, nets []probeSource, trusted []*net.IPNet, now model.LocalTime) []model.Alert {
	var alerts []model.Alert
	var covered []*net.IPNet

	sort.Slice(nets, func(i, j int) bool { return nets[i].Addr < nets[j].Addr })
	for _, n := range nets {
		ip, ipnet, err := net.ParseCIDR(n.Addr)
		if err != nil || !externalUntrusted(ip, trusted) {
			continue
		}
		covered = append(covered, ipnet)
		alerts = append(alerts, probeNetAlert(n, now))
	}

	sort.Slice(sources, func(i, j int) bool { return sources[i].Addr < sources[j].Addr })
	for _, s := range sources {
		ip := net.ParseIP(s.Addr)
		if ip == nil || !externalUntrusted(ip, trusted) || inAnyCIDR(ip, covered) {
			continue
		}
		alerts = append(alerts, probeAddrAlert(s, now))
	}
	return alerts
}

// externalUntrusted 是否为白名单之外的外网地址。
func externalUntrusted(ip net.IP, trusted []*net.IPNet) bool {
	return !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !inAnyCIDR(ip, trusted)
}

func inAnyCIDR(ip net.IP, cidrs []*net.IPNet) bool {
	for _, n := range cidrs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func probeAddrAlert(s probeSource, now model.LocalTime) model.Alert {
	return newProbeAlert("scan-probe-"+s.Addr, s.HostID,
		fmt.Sprintf("低频跨资产探测 - 来自 %s（%d 台主机）", s.Addr, s.Hosts),
		fmt.Sprintf("外部来源 %s 在 %d 小时内连接了 %d 台主机（%d 种角色）的 %d 个不同端口，共 %d 次连接。"+
			"每台主机上的动作都低于端口扫描阈值，合起来是在摸暴露面。涉及主机：%s。",
			s.Addr, int(probeWindow.Hours()), s.Hosts, s.Roles, s.Pairs, s.Conns, strings.Join(s.Hostnames, "、")),
		now)
}

func probeNetAlert(n probeSource, now model.LocalTime) model.Alert {
	return newProbeAlert("scan-probe-net-"+n.Addr, n.HostID,
		fmt.Sprintf("分布式跨资产探测 - 来自 %s（%d 个地址）", n.Addr, n.Addrs),
		fmt.Sprintf("网段 %s 里有 %d 个地址在 %d 小时内连接了 %d 台主机（%d 种角色）的 %d 个不同端口，共 %d 次连接。"+
			"单个地址的量都很小，合起来覆盖了大片暴露面。涉及主机：%s。",
			n.Addr, n.Addrs, int(probeWindow.Hours()), n.Hosts, n.Roles, n.Pairs, n.Conns, strings.Join(n.Hostnames, "、")),
		now)
}

func newProbeAlert(resultID, hostID, title, desc string, now model.LocalTime) model.Alert {
	return model.Alert{
		ResultID:       resultID,
		HostID:         hostID,
		RuleID:         ProbeRuleID,
		Source:         model.AlertSourceDetection,
		Severity:       "medium",
		Category:       "port_scan",
		ATTCKTechnique: "T1046",
		ATTCKTactic:    "TA0007",
		Title:          title,
		Description:    desc,
		Status:         model.AlertStatusActive,
		FirstSeenAt:    now,
		LastSeenAt:     now,
	}
}
