//go:build !linux

package metrics

func readRSS() uint64  { return 0 }
func readFDCount() int { return 0 }
