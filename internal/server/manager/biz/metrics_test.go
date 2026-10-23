package biz

import (
	"context"
	"errors"
	"testing"

	"go.uber.org/zap"
)

func TestGetHostMetricsRequiresPrometheusDatasource(t *testing.T) {
	service := NewMetricsService(nil, nil, nil, zap.NewNop())

	_, err := service.GetHostMetrics(context.Background(), "host-1", nil, nil)
	if !errors.Is(err, ErrPrometheusDatasourceNotConfigured) {
		t.Fatalf("expected ErrPrometheusDatasourceNotConfigured, got %v", err)
	}
}

func TestLatestMetricsHasData(t *testing.T) {
	var latest LatestMetrics
	if latest.hasData() {
		t.Fatal("expected empty latest metrics to report no data")
	}

	cpu := 12.5
	latest.CPUUsage = &cpu
	if !latest.hasData() {
		t.Fatal("expected latest metrics with cpu data to report data")
	}
}

func TestTimeSeriesMetricsHasData(t *testing.T) {
	var ts TimeSeriesMetrics
	if ts.hasData() {
		t.Fatal("expected empty time series to report no data")
	}

	ts.CPUUsage = []TimeSeriesPoint{{}}
	if !ts.hasData() {
		t.Fatal("expected time series with cpu points to report data")
	}
}
