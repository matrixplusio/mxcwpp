package celengine

import "testing"

func TestOpenFlagsTrunc(t *testing.T) {
	cases := map[string]bool{
		"0x241":  true,  // O_WRONLY|O_CREAT|O_TRUNC：dd of=、cp、": >"
		"0x8241": true,  // 再带 O_LARGEFILE
		"0x441":  false, // O_WRONLY|O_CREAT|O_APPEND：rsyslog 追加
		"0x2":    false,
		"":       false,
		"junk":   false,
	}
	for in, want := range cases {
		if got := openFlagsTrunc(in); got != want {
			t.Errorf("openFlagsTrunc(%q) = %v, want %v", in, got, want)
		}
	}
}
