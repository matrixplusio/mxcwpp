package auth

import (
	"bufio"
	"io"
	"strings"
	"testing"
)

// 超长的一行被跳过，后面的行照常读到。
//
// 原先用 Scanner：遇到超长行直接停止读取，而 journalctl 还在往管道里写，采集就此永久卡住；
// 游标停在这条之前，重启之后还是卡在同一处。
func TestReadJournalLineSkipsOversized(t *testing.T) {
	const max = 1024
	in := "first\n" + strings.Repeat("x", max*5) + "\n" + "third\n" + strings.Repeat("y", max) + "\n"
	r := bufio.NewReaderSize(strings.NewReader(in), 64)

	line, tooLong, err := readJournalLine(r, max)
	if err != nil || tooLong || string(line) != "first" {
		t.Fatalf("第一行：%q tooLong=%v err=%v", line, tooLong, err)
	}
	line, tooLong, err = readJournalLine(r, max)
	if err != nil || !tooLong || len(line) != 0 {
		t.Fatalf("超长行应被整行丢弃：len=%d tooLong=%v err=%v", len(line), tooLong, err)
	}
	line, tooLong, err = readJournalLine(r, max)
	if err != nil || tooLong || string(line) != "third" {
		t.Fatalf("超长行之后的一行应照常读到：%q tooLong=%v err=%v", line, tooLong, err)
	}
	// 含换行符在内刚好超过上限一个字节：也算超长。恰好等于上限的能读到。
	if _, tooLong, err = readJournalLine(r, max); err != nil || !tooLong {
		t.Fatalf("超出上限一个字节应算超长：tooLong=%v err=%v", tooLong, err)
	}
	if _, _, err = readJournalLine(r, max); err != io.EOF {
		t.Fatalf("读完应返回 EOF，得 %v", err)
	}
}
