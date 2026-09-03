package strutil

import "testing"

func TestTruncate(t *testing.T) {
	cases := []struct {
		in   string
		max  int
		want string
	}{
		{"hello", 10, "hello"},
		{"hello world", 5, "he..."},
		{"hello world", 3, "hel"},
		{"hello world", 0, ""},
		{"abc", 3, "abc"},
	}
	for _, c := range cases {
		if got := Truncate(c.in, c.max); got != c.want {
			t.Errorf("Truncate(%q,%d)=%q want %q", c.in, c.max, got, c.want)
		}
	}
}

func TestMaskMiddle(t *testing.T) {
	if got := MaskMiddle("ak_abcdef1234", 2, 2); got != "ak***34" {
		t.Errorf("MaskMiddle ak_abcdef1234 = %q", got)
	}
	if got := MaskMiddle("abc", 2, 2); got != "***" {
		t.Errorf("MaskMiddle short = %q", got)
	}
}

func TestHasPrefixAny(t *testing.T) {
	if !HasPrefixAny("kms.kek", "kms.", "secret.") {
		t.Fatal("expected match")
	}
	if HasPrefixAny("foo", "kms.", "secret.") {
		t.Fatal("expected no match")
	}
}
