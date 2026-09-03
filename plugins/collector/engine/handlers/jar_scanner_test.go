package handlers

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestHasJarExtension(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"foo.jar", true},
		{"foo.war", true},
		{"foo.ear", true},
		{"foo.JAR", true},
		{"foo.WAR", true},
		{"foo.zip", false},
		{"jar", false},
		{"", false},
		{"/path/to/spring-boot.jar", true},
	}
	for _, c := range cases {
		if got := hasJarExtension(c.in); got != c.want {
			t.Errorf("hasJarExtension(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestIsAcceptableJar(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"/opt/app/myapp.jar", true},
		{"/data/G02/G02_agent_api/g02_agent_api.jar", true},
		{"/opt/jdk1.8/jre/lib/rt.jar", false}, // JDK 路径片段 + rt.jar
		{"/opt/jdk1.8/lib/tools.jar", false},
		{"/usr/lib/jvm/java-11-openjdk/lib/jrt-fs.jar", false},
		{"/opt/zulu11/lib/charsets.jar", false},
		{"/opt/graalvm-jdk-21/lib/svm.jar", false},
		{"/var/lib/myapp/rt.jar", false}, // basename 兜底
		{"", false},
	}
	for _, c := range cases {
		if got := isAcceptableJar(c.in); got != c.want {
			t.Errorf("isAcceptableJar(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestStripProcRootForJar(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"/proc/1234/root/opt/app/foo.jar", "/opt/app/foo.jar"},
		{"/opt/app/foo.jar", "/opt/app/foo.jar"},
		{"/proc/abc/root/x", "/proc/abc/root/x"},
		{"/proc/123/cwd", "/proc/123/cwd"},
	}
	for _, c := range cases {
		if got := stripProcRootForJar(c.in); got != c.want {
			t.Errorf("stripProcRootForJar(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestParseManifestAttrs(t *testing.T) {
	data := []byte("Manifest-Version: 1.0\r\n" +
		"Implementation-Title: spring-boot\r\n" +
		"Implementation-Version: 3.1.0\r\n" +
		"Bundle-SymbolicName: org.example.foo;singleton:=true\r\n" +
		"Bundle-Version: 1.2.3\r\n" +
		"Long-Value: line1\r\n" +
		" continuation\r\n" +
		"\r\n" +
		"Name: ignored/per/entry\r\n" +
		"Implementation-Title: should-not-appear\r\n")

	attrs := parseManifestAttrs(data)
	if attrs["Implementation-Title"] != "spring-boot" {
		t.Errorf("Implementation-Title = %q", attrs["Implementation-Title"])
	}
	if attrs["Implementation-Version"] != "3.1.0" {
		t.Errorf("Implementation-Version = %q", attrs["Implementation-Version"])
	}
	if attrs["Bundle-SymbolicName"] != "org.example.foo;singleton:=true" {
		t.Errorf("Bundle-SymbolicName = %q", attrs["Bundle-SymbolicName"])
	}
	if attrs["Long-Value"] != "line1continuation" {
		t.Errorf("续行未拼接：Long-Value = %q", attrs["Long-Value"])
	}
	// per-entry 段不应被解析（空行后停止）
	if attrs["Name"] != "" {
		t.Errorf("per-entry 段被误解析：Name = %q", attrs["Name"])
	}
}

func TestParseJarBOM_PomProperties(t *testing.T) {
	tmp, err := os.MkdirTemp("", "jartest")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmp)

	jarPath := filepath.Join(tmp, "fake-spring.jar")
	if err := writeFakeJar(jarPath, map[string]string{
		"META-INF/maven/org.springframework.boot/spring-boot/pom.properties": "groupId=org.springframework.boot\nartifactId=spring-boot\nversion=3.1.0\n",
		"META-INF/maven/io.netty/netty-common/pom.properties":                "groupId=io.netty\nartifactId=netty-common\nversion=4.1.115.Final\n",
	}); err != nil {
		t.Fatal(err)
	}

	pkgs, err := parseJarBOM(jarPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(pkgs))
	}

	names := map[string]bool{}
	for _, p := range pkgs {
		names[p["name"].(string)] = true
	}
	if !names["org.springframework.boot:spring-boot"] {
		t.Errorf("missing spring-boot")
	}
	if !names["io.netty:netty-common"] {
		t.Errorf("missing netty-common")
	}
}

func TestParseJarBOM_ManifestFallback(t *testing.T) {
	tmp, err := os.MkdirTemp("", "jartest")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmp)

	jarPath := filepath.Join(tmp, "manifest-only.jar")
	mf := "Manifest-Version: 1.0\nImplementation-Title: mymodule\nImplementation-Version: 9.9.9\n\n"
	if err := writeFakeJar(jarPath, map[string]string{
		"META-INF/MANIFEST.MF": mf,
	}); err != nil {
		t.Fatal(err)
	}

	pkgs, err := parseJarBOM(jarPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("expected 1 package, got %d", len(pkgs))
	}
	if pkgs[0]["name"] != "mymodule" || pkgs[0]["version"] != "9.9.9" {
		t.Errorf("manifest parse mismatch: %v", pkgs[0])
	}
}

// writeFakeJar 写一个 zip 文件，每个 entry name → 内容
func writeFakeJar(path string, files map[string]string) error {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		f, err := zw.Create(name)
		if err != nil {
			return err
		}
		if _, err := f.Write([]byte(content)); err != nil {
			return err
		}
	}
	if err := zw.Close(); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0644)
}
