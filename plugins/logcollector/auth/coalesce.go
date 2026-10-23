package auth

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// coalesceWindow 同一来源同一账号的失败在这段时间内合并成一条。
	coalesceWindow = 10 * time.Second
	// coalesceMaxKeys 合并表里每类事件的上限。分布式爆破时来源可以有几万个，表不能跟着无限长。
	// 按类分开算：连接提前断开不需要任何凭据就能造，共用一张表的话它能把登录失败、sudo 被拒的位置占光。
	coalesceMaxKeys = 5000
	// rateLimitPerMinute 每类事件每分钟最多上报的条数。超出的丢弃并计数，丢弃数随后单独上报。
	//
	// 限额按事件类型各算各的，不共用一个总数。共用的话，谁能大量制造某一类便宜的事件
	// （循环执行 sudo、反复登录失败），谁就能把这一分钟里的登录成功、新建账号一起挤掉——
	// 例如并发的 sudo 循环十几秒就能用完总额，随后的公钥登录、建账号、root 口令失败会全部丢弃。
	// 分开之后，洪泛只淹得掉它自己那一类。
	rateLimitPerMinute = 1200
)

// coalescer 合并高频的失败事件，并给总上报量封顶。
//
// 对外的主机被爆破时一分钟可以有几千行失败登录，逐条上报会占满 agent 的发送缓冲，
// 把别的数据挤掉。每个（来源、账号、原因）的第一条立即放行——检测要靠它尽早知道，
// 「先失败后成功」的先后顺序也靠它——之后窗口内的只累计，窗口结束时补一条汇总。
type coalescer struct {
	mu      sync.Mutex
	pending map[string]*Event // 窗口内被压下的次数累计在这里，Count 为被压下的条数
	opened  map[string]time.Time

	openByKind map[string]int // opened 里各类事件的条目数

	minute  time.Time
	sent    map[string]int // 本分钟各类事件已放行的条数
	dropped map[string]int // 尚未上报的丢弃数，按事件类型
	// statsAt 上次上报丢弃统计的时间。单独计时，不跟着限额的分钟走：
	// 持续洪泛时限额的分钟每到点就被下一条事件重新起算，跟着它判断的话统计永远发不出去。
	statsAt time.Time
}

func newCoalescer() *coalescer {
	return &coalescer{pending: make(map[string]*Event), opened: make(map[string]time.Time),
		openByKind: make(map[string]int), sent: make(map[string]int), dropped: make(map[string]int)}
}

// kindOfKey 取出合并键里的事件类型（键以它开头）。
func kindOfKey(key string) string {
	if i := strings.IndexByte(key, 0); i >= 0 {
		return key[:i]
	}
	return key
}

func coalescable(kind string) bool {
	return kind == KindLoginFailed || kind == KindPreauthClose || kind == KindSudoDenied || kind == KindSuFailed
}

func coalesceKey(e *Event) string {
	return e.Kind + "\x00" + e.SourceIP + "\x00" + e.Username + "\x00" + e.Reason
}

// Offer 交入一条事件，返回现在应当上报的事件（可能为空）。
func (c *coalescer) Offer(e *Event, now time.Time) []*Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !coalescable(e.Kind) {
		out := []*Event{e}
		if e.Kind == KindLoginSuccess && e.SourceIP != "" {
			// 登录成功之前，先把同一来源还压着没报的失败报出去。否则服务端看到的顺序是
			// 「失败 1 次、成功、失败 4 次」，成功那一刻只数得到 1 次失败——
			// 十秒内爆破得手正好被合并藏了起来。
			out = append(c.takePendingFrom(e.SourceIP), e)
		}
		return c.admit(out, now)
	}
	key := coalesceKey(e)
	if start, ok := c.opened[key]; ok && now.Sub(start) < coalesceWindow {
		if p := c.pending[key]; p != nil {
			p.Count += e.Count
			p.Time = e.Time
		} else {
			cp := *e
			c.pending[key] = &cp
		}
		return nil
	}
	if c.openByKind[e.Kind] >= coalesceMaxKeys {
		// 这一类的表满了：不再为新的来源开窗口，这条也不上报，记入丢弃数。
		c.noteDropped(e.Kind, e.Count, now)
		return nil
	}
	if _, reopened := c.opened[key]; !reopened {
		c.openByKind[e.Kind]++
	}
	c.opened[key] = now
	return c.admit([]*Event{e}, now)
}

// takePendingFrom 取走某个来源压着没报的汇总，窗口照常保留。调用方须持有 c.mu。
func (c *coalescer) takePendingFrom(sourceIP string) []*Event {
	var out []*Event
	for key, p := range c.pending {
		if p.SourceIP == sourceIP {
			out = append(out, p)
			delete(c.pending, key)
		}
	}
	return out
}

// noteDropped 记一笔丢弃。调用方须持有 c.mu。
func (c *coalescer) noteDropped(kind string, n int, now time.Time) {
	if len(c.dropped) == 0 && c.statsAt.IsZero() {
		c.statsAt = now
	}
	c.dropped[kind] += n
}

// Flush 取出窗口已结束的汇总事件，以及需要上报的丢弃统计。应当周期调用。
func (c *coalescer) Flush(now time.Time) []*Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []*Event
	for key, start := range c.opened {
		if now.Sub(start) < coalesceWindow {
			continue
		}
		if p := c.pending[key]; p != nil {
			out = append(out, p)
			delete(c.pending, key)
		}
		delete(c.opened, key)
		if k := kindOfKey(key); c.openByKind[k] > 1 {
			c.openByKind[k]--
		} else {
			delete(c.openByKind, k)
		}
	}
	out = c.admit(out, now)
	if len(c.dropped) > 0 && now.Sub(c.statsAt) >= time.Minute {
		// 统计事件不占限额：正是限额用完的时候才需要它。Detail 里写明各类各丢了多少。
		kinds := make([]string, 0, len(c.dropped))
		total := 0
		for k, n := range c.dropped {
			kinds = append(kinds, k)
			total += n
		}
		sort.Strings(kinds)
		parts := make([]string, 0, len(kinds))
		for _, k := range kinds {
			parts = append(parts, fmt.Sprintf("%s=%d", k, c.dropped[k]))
		}
		out = append(out, &Event{Kind: KindStats, Service: "logcollector", Time: now, Trust: TrustJournal,
			Reason: "rate_limited", Count: total, Detail: strings.Join(parts, ",")})
		c.dropped = make(map[string]int)
		c.statsAt = now
	}
	return out
}

// admit 按每分钟每类的限额放行，超出的计入丢弃数。调用方须持有 c.mu。
func (c *coalescer) admit(events []*Event, now time.Time) []*Event {
	if now.Sub(c.minute) >= time.Minute {
		c.minute, c.sent = now, make(map[string]int)
	}
	out := events[:0]
	for _, e := range events {
		if c.sent[e.Kind] >= rateLimitPerMinute {
			c.noteDropped(e.Kind, e.Count, now)
			continue
		}
		c.sent[e.Kind]++
		out = append(out, e)
	}
	return out
}
