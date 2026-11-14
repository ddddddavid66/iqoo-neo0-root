package stage

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"ghostlock/internal/device"
)

// buildMockAdb 编译仓库里的假 adb（tools/mockadb）。
func buildMockAdb(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go 不在 PATH")
	}
	src := filepath.Join("..", "..", "..", "tools", "mockadb")
	if _, err := os.Stat(filepath.Join(src, "go.mod")); err != nil {
		t.Skipf("找不到假 adb 源码：%s", src)
	}
	bin := filepath.Join(t.TempDir(), "mockadb.exe")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = src
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("构建假 adb 失败: %v\n%s", err, out)
	}
	return bin
}

func newMock(t *testing.T, root bool) *device.ADB {
	t.Helper()
	bin := buildMockAdb(t)
	state := filepath.Join(t.TempDir(), "mock-state.txt")
	boot := strconv.FormatInt(time.Now().Unix()-30, 10)
	r := 0
	if root {
		r = 1
	}
	if err := os.WriteFile(state, []byte("present=1 root="+strconv.Itoa(r)+" boot_unix="+boot+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MOCK_STATE", state)
	return &device.ADB{Bin: bin, Serial: "MOCKSERIAL"}
}

// 有缓存（.gl_ksu_pkg）+ 管理器在装：必须几步就命中，不能靠重试。
func TestFindManagerFastPath(t *testing.T) {
	a := newMock(t, false)
	started := time.Now()
	pkg, ksud := findManager(a)
	elapsed := time.Since(started)
	if pkg != "com.sukisu.ultra" {
		t.Fatalf("pkg = %q, want com.sukisu.ultra", pkg)
	}
	if ksud == "" {
		t.Fatal("ksud 路径为空")
	}
	if elapsed > 3*time.Second {
		t.Fatalf("缓存命中却用了 %s", elapsed)
	}
}

// 没有管理器（也没缓存）：探测必须被总预算压住，不能把开机窗口吃掉。
// 旧写法在此路径上要 9 个包名 × 5 次 × 515ms ≈ 24s。
func TestFindManagerBoundedWhenAbsent(t *testing.T) {
	a := newMock(t, false)
	t.Setenv("MOCK_NO_MANAGER", "1")
	started := time.Now()
	pkg, ksud := findManager(a)
	elapsed := time.Since(started)
	if pkg != "" || ksud != "" {
		t.Fatalf("不该找到管理器，实际 %q / %q", pkg, ksud)
	}
	if elapsed > 12*time.Second {
		t.Fatalf("无管理器时探测耗时 %s，超出预算（应 <=12s）", elapsed)
	}
	t.Logf("无管理器探测耗时 %s", elapsed.Round(time.Millisecond))
}
