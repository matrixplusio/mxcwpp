package biz

import "testing"

func TestCompareVersionStrings(t *testing.T) {
	tests := []struct {
		v1       string
		v2       string
		expected int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.1", "1.0.0", 1},
		{"1.0.0", "1.0.1", -1},
		{"2.0.0", "1.9.9", 1},
		{"1.25.1", "1.25.0", 1},
		{"1.25.0", "1.25.1", -1},
		// epoch: 相同 epoch 比较主版本
		{"1:1.2.3", "1:1.2.3", 0},
		{"1:1.2.4", "1:1.2.3", 1},
		// epoch: 高 epoch 优先，即使主版本号更小
		{"1:1.0.0", "2.0.0", 1},
		{"1:1.0.0", "0:999.0.0", 1},
		{"2:1.0.0", "1:9.0.0", 1},
		// epoch: 无 epoch 等同于 epoch 0
		{"0:1.0.0", "1.0.0", 0},
		// release suffix 参与比较
		{"1.1.1k-2.el7", "1.1.1k-1.el7", 1},
		{"1.25.1-1ubuntu1", "1.25.0", 1},
		{"1.0.0-1", "1.0.0", 1},
		{"1.0.0", "1.0.0-1", -1},
		// 不同长度
		{"1.0", "1.0.0", 0},
		{"1.1", "1.0.9", 1},
	}

	for _, tt := range tests {
		result := compareVersionStrings(tt.v1, tt.v2)
		if result != tt.expected {
			t.Errorf("compareVersionStrings(%q, %q) = %d, want %d", tt.v1, tt.v2, result, tt.expected)
		}
	}
}

func TestSplitEpoch(t *testing.T) {
	tests := []struct {
		input         string
		expectedEpoch int
		expectedRest  string
	}{
		{"1:2.3.4", 1, "2.3.4"},
		{"0:1.0.0", 0, "1.0.0"},
		{"1.0.0", 0, "1.0.0"},
		{"", 0, ""},
	}
	for _, tt := range tests {
		epoch, rest := splitEpoch(tt.input)
		if epoch != tt.expectedEpoch || rest != tt.expectedRest {
			t.Errorf("splitEpoch(%q) = (%d, %q), want (%d, %q)",
				tt.input, epoch, rest, tt.expectedEpoch, tt.expectedRest)
		}
	}
}

func TestSplitRelease(t *testing.T) {
	tests := []struct {
		input       string
		expectedVer string
		expectedRel string
	}{
		{"1.2.3-4.el7", "1.2.3", "4.el7"},
		{"1.0.0", "1.0.0", ""},
		{"1.25.1-1ubuntu1", "1.25.1", "1ubuntu1"},
	}
	for _, tt := range tests {
		ver, rel := splitRelease(tt.input)
		if ver != tt.expectedVer || rel != tt.expectedRel {
			t.Errorf("splitRelease(%q) = (%q, %q), want (%q, %q)",
				tt.input, ver, rel, tt.expectedVer, tt.expectedRel)
		}
	}
}

func TestParseVersionPart(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"123", 123},
		{"1k", 1},
		{"25p1", 25},
		{"0", 0},
		{"abc", 0},
		{"", 0},
	}

	for _, tt := range tests {
		result := parseVersionPart(tt.input)
		if result != tt.expected {
			t.Errorf("parseVersionPart(%q) = %d, want %d", tt.input, result, tt.expected)
		}
	}
}
