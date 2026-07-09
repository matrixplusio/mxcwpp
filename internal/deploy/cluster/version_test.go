package cluster

import "testing"

func TestServiceVersion(t *testing.T) {
	c := &Config{}
	c.Release.Version = "v1.0.0"
	c.Components = map[string]ComponentSpec{"manager": {Version: "v1.0.2"}}
	if got := c.ServiceVersion("manager"); got != "v1.0.2" {
		t.Fatalf("manager=%s want v1.0.2", got)
	}
	if got := c.ServiceVersion("engine"); got != "v1.0.0" {
		t.Fatalf("engine=%s want v1.0.0 (fallback)", got)
	}
}

func TestImageRefPerComponent(t *testing.T) {
	c := &Config{}
	c.Release.Version = "v1.0.0"
	c.Registry.Domain = "harbor.example.com"
	c.Registry.Namespace = "mxcwpp"
	c.Components = map[string]ComponentSpec{"manager": {Version: "v1.0.2"}}
	if got := c.ImageRef("mxcwpp-manager"); got != "harbor.example.com/mxcwpp/mxcwpp-manager:v1.0.2" {
		t.Fatalf("manager image=%s", got)
	}
	if got := c.ImageRef("mxcwpp-engine"); got != "harbor.example.com/mxcwpp/mxcwpp-engine:v1.0.0" {
		t.Fatalf("engine image=%s", got)
	}
}
