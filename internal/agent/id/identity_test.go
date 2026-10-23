package id

import (
	"os"
	"path/filepath"
	"testing"
)

// fakeMachine 把派生与指纹来源指向临时文件，模拟一台机器。
func fakeMachine(t *testing.T, machineID, productUUID string) string {
	t.Helper()
	dir := t.TempDir()
	mid := filepath.Join(dir, "machine-id")
	puuid := filepath.Join(dir, "product_uuid")
	if err := os.WriteFile(mid, []byte(machineID), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(puuid, []byte(productUUID), 0644); err != nil {
		t.Fatal(err)
	}
	oldStable, oldFP, oldRoot := stableIDSources, fingerprintSources, rootfsUUID
	stableIDSources = []string{mid}
	fingerprintSources = map[string][]string{"machine_id": {mid}, "product_uuid": {puuid}}
	rootfsUUID = func() string { return "" }
	t.Cleanup(func() { stableIDSources, fingerprintSources, rootfsUUID = oldStable, oldFP, oldRoot })
	return dir
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

// 新装机器仍按最早的规则派生：已有主机重装后 ID 不变。
func TestFreshInstallKeepsLegacyDerivation(t *testing.T) {
	dir := fakeMachine(t, "mid-1", "uuid-1")
	r, err := Resolve(filepath.Join(dir, "agent_id"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.ID != deriveStableID() || r.Cloned {
		t.Fatalf("新装应沿用最早规则派生，实际 %+v", r)
	}
}

// 旧版本升级上来：沿用 ID，补记指纹基线。
func TestUpgradeRecordsBaseline(t *testing.T) {
	dir := fakeMachine(t, "mid-1", "uuid-1")
	idFile := filepath.Join(dir, "agent_id")
	write(t, idFile, "old-id")

	r, err := Resolve(idFile, nil)
	if err != nil || r.ID != "old-id" || r.Cloned {
		t.Fatalf("升级应沿用原 ID，实际 %+v err=%v", r, err)
	}
	if got, _ := os.ReadFile(fingerprintFile(idFile)); string(got) != Fingerprint() {
		t.Fatal("应补记指纹基线")
	}
}

// ID 文件随镜像复制到另一台机器：丢弃它和证书，重新派生。
func TestCopiedIDFileIsDiscarded(t *testing.T) {
	dir := fakeMachine(t, "mid-1", "uuid-clone")
	idFile := filepath.Join(dir, "agent_id")
	cert := filepath.Join(dir, "client.crt")
	write(t, idFile, "image-baked-id")
	write(t, fingerprintFile(idFile), "fingerprint-of-the-template-machine")
	write(t, cert, "cert-of-the-template-machine")

	r, err := Resolve(idFile, []string{cert})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Cloned || r.ID == "image-baked-id" {
		t.Fatalf("应识别为克隆并换 ID，实际 %+v", r)
	}
	if _, err := os.Stat(cert); !os.IsNotExist(err) {
		t.Fatal("旧身份的证书应被删除")
	}
}

// 同一台机器重启：指纹不变，ID 不变。
func TestSameMachineKeepsID(t *testing.T) {
	dir := fakeMachine(t, "mid-1", "uuid-1")
	idFile := filepath.Join(dir, "agent_id")
	first, _ := Resolve(idFile, nil)
	again, _ := Resolve(idFile, nil)
	if first.ID != again.ID || again.Cloned {
		t.Fatalf("同一台机器 ID 应稳定: %q vs %q", first.ID, again.ID)
	}
}

// 共享 machine-id 的克隆：指纹仍不同，冲突后各自落到不同的组合指纹 ID。
func TestResetAfterConflictMovesToComposite(t *testing.T) {
	dirA := fakeMachine(t, "shared-mid", "uuid-A")
	idA := filepath.Join(dirA, "agent_id")
	a, _ := Resolve(idA, nil)
	nextA, err := Reset(idA, nil)
	if err != nil {
		t.Fatal(err)
	}
	if nextA == a.ID || nextA != compositeID(Fingerprint()) {
		t.Fatalf("从最早规则的 ID 冲突后应换成组合指纹 ID，实际 %q", nextA)
	}

	dirB := fakeMachine(t, "shared-mid", "uuid-B")
	idB := filepath.Join(dirB, "agent_id")
	b, _ := Resolve(idB, nil)
	if b.ID != a.ID {
		t.Fatal("前提：两台克隆按最早规则派生出同一个 ID")
	}
	nextB, _ := Reset(idB, nil)
	if nextB == nextA {
		t.Fatal("硬件 UUID 不同的克隆冲突后必须得到不同的 ID")
	}
}

// 组合指纹也相同的完全克隆：再次冲突时退到随机 ID。
func TestSecondConflictFallsBackToRandom(t *testing.T) {
	dir := fakeMachine(t, "mid", "uuid")
	idFile := filepath.Join(dir, "agent_id")
	_, _ = Resolve(idFile, nil)
	composite, _ := Reset(idFile, nil)
	random, _ := Reset(idFile, nil)
	if random == composite || len(random) != 64 {
		t.Fatalf("组合指纹冲突后应换随机 ID，实际 %q", random)
	}
}
