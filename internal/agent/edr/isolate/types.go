package isolate

import "time"

// Level describes the isolation strategy.
type Level string

const (
	LevelNone      Level = "none"      // no isolation active
	LevelSelective Level = "selective" // individual IP:port blocks only
	LevelStandard  Level = "standard"  // block all except management + DNS
	LevelComplete  Level = "complete"  // block all except management only
)

// BlockRule is a single selective IP block entry tracked in memory.
type BlockRule struct {
	RuleID    uint   // Server-side rule ID for correlation
	IP        string // target IP or CIDR
	Port      int    // 0 = all ports
	Protocol  string // tcp/udp
	Direction string // inbound/outbound
	CreatedAt time.Time
}
