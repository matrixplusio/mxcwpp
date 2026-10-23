package cluster

import (
	"reflect"
	"testing"
)

func TestExpandRoles(t *testing.T) {
	cases := []struct {
		in      []string
		want    []string
		wantErr bool
	}{
		{in: []string{"control"}, want: []string{"manager", "agentcenter", "consumer", "engine", "vulnsync", "llmproxy", "ui"}},
		{in: []string{"storage"}, want: []string{"mysql", "redis", "clickhouse"}},
		{in: []string{"kafka"}, want: []string{"kafka"}},
		{in: []string{"control", "ui"}, want: []string{"manager", "agentcenter", "consumer", "engine", "vulnsync", "llmproxy", "ui"}}, // ui 去重
		{in: []string{"agentcenter"}, want: []string{"agentcenter"}},
		{in: []string{"bogus"}, wantErr: true},
	}
	for _, c := range cases {
		got, err := ExpandRoles(c.in)
		if c.wantErr {
			if err == nil {
				t.Fatalf("ExpandRoles(%v) expected error", c.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("ExpandRoles(%v) err: %v", c.in, err)
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Fatalf("ExpandRoles(%v)=%v want %v", c.in, got, c.want)
		}
	}
}
