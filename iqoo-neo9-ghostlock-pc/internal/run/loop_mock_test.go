package run

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"ghostlock/internal/assets"
	"ghostlock/internal/device"
	"ghostlock/internal/stage"
)

// buildMockAdb 编译仓库里的假 adb（tools/mockadb）。它同时是 mockadb 与
// mockghostlock 两种人格的源码，这里只需要 adb 那面。
func buildMockAdb(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go 不在 PATH，跳过假 adb 测试")
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

// TestLoopAgainstMockAdb 用假 adb 跑真实的 Loop：覆盖 probe → profile → stage →
// 窗口判断 → fire → 判胜这条完整链路。真机没插上时，这是唯一能证明 Go 侧重试机
// 器没坏的办法。
func TestLoopAgainstMockAdb(t *testing.T) {
	started := time.Now()
	mock := buildMockAdb(t)
	t.Logf("假 adb 就绪：%s（耗时 %s）", mock, time.Since(started))

	state := filepath.Join(t.TempDir(), "mock-state.txt")
	boot := strconv.FormatInt(time.Now().Unix()-30, 10)
	if err := os.WriteFile(state, []byte("present=1 root=0 boot_unix="+boot+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MOCK_STATE", state)
	t.Logf("状态写入：boot=%s（uptime≈30s），已过 %s", boot, time.Since(started))

	a := &device.ADB{Bin: mock, Serial: "MOCKSERIAL"}
	o := &Options{ADB: a, Loader: assets.New(""), Remote: stage.RemoteDir}
	lo := &LoopOptions{Base: o, Rounds: 1, PerBoot: 1, Window: 90, Timeout: 30}
	if os.Getenv("GHOSTLOCK_TEST_VERBOSE") != "" {
		o.Out = os.Stdout
		lo.Out = os.Stdout
	}

	res, err := Loop(lo)
	if err != nil {
		t.Fatalf("Loop: %v", err)
	}
	if res == nil || !res.KsuLoaded {
		t.Fatalf("期望 KsuLoaded=true，实际 %+v", res)
	}
}

// TestLoopWinsOnlyAfterWindow 确认窗口下沿真的被守住：设备刚重启（uptime 很小）时
// Loop 必须先等，不能抢早发射。
func TestLoopWinsOnlyAfterWindow(t *testing.T) {
	mock := buildMockAdb(t)

	state := filepath.Join(t.TempDir(), "mock-state.txt")
	boot := strconv.FormatInt(time.Now().Unix(), 10) // uptime = 0
	if err := os.WriteFile(state, []byte("present=1 root=0 boot_unix="+boot+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MOCK_STATE", state)

	a := &device.ADB{Bin: mock, Serial: "MOCKSERIAL"}
	o := &Options{ADB: a, Loader: assets.New(""), Remote: stage.RemoteDir}
	lo := &LoopOptions{Base: o, Rounds: 1, PerBoot: 1, Window: 90, MinUptime: 25, Timeout: 90}

	started := time.Now()
	res, err := Loop(lo)
	if err != nil {
		t.Fatalf("Loop: %v", err)
	}
	if res == nil || !res.KsuLoaded {
		t.Fatalf("期望最终成功，实际 %+v", res)
	}
	if elapsed := time.Since(started); elapsed < 20*time.Second {
		t.Fatalf("uptime≈0 时应该先等到窗口下沿，实际只用了 %s（抢早了）", elapsed)
	}
}
