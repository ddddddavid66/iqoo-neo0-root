package run

import (
	"strings"
	"testing"

	"ghostlock/internal/stage"
)

// The exact environment contract with the native binary: if this test changes,
// the payload no longer finds its ko / log / profile.
func TestBuildCommandContract(t *testing.T) {
	o := &Options{Remote: stage.RemoteDir}
	f := stage.Paths(stage.RemoteDir, true, "com.sukisu.ultra", "android13-5.15")
	cmd := buildCommand(o, f)

	for _, want := range []string{
		"cd " + stage.RemoteDir,
		"GHOSTLOCK_HOME=" + stage.RemoteDir,
		"TMPDIR=" + stage.RemoteDir,
		"HOME=" + stage.RemoteDir,
		"GHOSTLOCK_KSU_LOG=" + stage.RemoteDir + "/ksud.log",
		"GHOSTLOCK_KSU_ENFORCE=1",
		"GHOSTLOCK_VRPATCH_KO=" + stage.RemoteDir + "/vrpatch.ko",
		"./ghostlock --load-prebuilt-profile " + stage.RemoteDir + "/profile.bin",
	} {
		if !strings.Contains(cmd, want) {
			t.Errorf("command missing %q: %s", want, cmd)
		}
	}
	if strings.Contains(cmd, "--force-attack") {
		t.Error("--force-attack must be opt-in")
	}
}

func TestTempRootDropsKsuLoad(t *testing.T) {
	o := &Options{Remote: stage.RemoteDir, TempRoot: true}
	f := stage.Paths(stage.RemoteDir, true, "", "")
	if cmd := buildCommand(o, f); !strings.Contains(cmd, "GHOSTLOCK_KSU_ENFORCE=9") {
		t.Fatalf("temp-root must set 9: %s", cmd)
	}
}

func TestKsuEnforceSharedByLoopAndDirect(t *testing.T) {
	if got := ksuEnforce(&Options{TempRoot: true}); got != 9 {
		t.Fatalf("ksuEnforce(temp-root) = %d, want 9", got)
	}
	// Leaving SELinux enforcing is the default: permissive is what the boots
	// with `init` SIGABRT had in common.
	if got := ksuEnforce(&Options{}); got != 1 {
		t.Fatalf("ksuEnforce(default) = %d, want 1 (enforcing)", got)
	}
	if got := ksuEnforce(&Options{Permissive: true}); got != 0 {
		t.Fatalf("ksuEnforce(permissive) = %d, want 0", got)
	}
}

func TestNoVrPatchOmitsEnv(t *testing.T) {
	o := &Options{Remote: stage.RemoteDir}
	f := stage.Paths(stage.RemoteDir, false, "me.weishu.kernelsu", "android13-5.15")
	if cmd := buildCommand(o, f); strings.Contains(cmd, "GHOSTLOCK_VRPATCH_KO") {
		t.Fatalf("no-vrpatch must omit the env: %s", cmd)
	}
}

func TestInterpretMarkers(t *testing.T) {
	out := strings.Join([]string{
		"[+] child is root!",
		"[*] SELinux permissive",
		"[*] start finding collisions",
		"[!] KernelSU module load failed",
		"7",
	}, string([]byte{0x0a}))
	res := interpret(out, nil)
	if !res.TempRoot || !res.SelinuxOff {
		t.Fatalf("markers not detected: %+v", res)
	}
	if res.KsuLoaded {
		t.Fatal("KsuLoaded must stay false")
	}
	if res.ExitCode != 7 {
		t.Fatalf("exit code = %d", res.ExitCode)
	}
	if len(res.Notes) == 0 {
		t.Fatal("risks should be recorded")
	}
}
