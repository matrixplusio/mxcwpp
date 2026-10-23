package scheduler

import (
	"testing"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func TestIsAutoUpdateCandidate(t *testing.T) {
	s := &AgentUpdateScheduler{}

	tests := []struct {
		name    string
		version string
		want    bool
	}{
		{name: "empty version", version: "", want: true},
		{name: "release version", version: "1.0.5", want: true},
		{name: "dev version", version: "dev", want: false},
		{name: "dev version uppercase with spaces", version: " DEV ", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host := model.Host{AgentVersion: tt.version}
			if got := s.isAutoUpdateCandidate(host); got != tt.want {
				t.Fatalf("isAutoUpdateCandidate(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}
