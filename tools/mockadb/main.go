// Command mockadb 是一个假 adb，用来在没有真机的情况下跑通守护脚本的状态机。
//
// 同一个二进制有两种人格，按可执行文件名区分：
//
//	mockadb.exe      → 假 adb，响应 devices/get-state/shell/reboot/connect
//	mockghostlock.exe → 假 ghostlock 载荷，跑起来就把「已 root」写进状态文件
//
// 状态文件（默认 mock-state.txt）就一行：
//
//	present=1 root=0 boot_unix=1700000000
//
// uptime 由 boot_unix 推出来，所以 `reboot` 只要把 boot_unix 改成当前时间即可。
// 这让「关机窗口」「抢窗口重启」这类逻辑能被真正测到。
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const defaultState = "mock-state.txt"

type state struct {
	present  bool
	root     bool
	bootUnix int64
}

func statePath() string {
	if p := os.Getenv("MOCK_STATE"); p != "" {
		return p
	}
	// 相对路径会跟着调用者的工作目录跑，状态就写丢了；固定放在 exe 旁边。
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), defaultState)
	}
	return defaultState
}

func readState() state {
	s := state{present: true, bootUnix: time.Now().Unix() - 30}
	b, err := os.ReadFile(statePath())
	if err != nil {
		return s
	}
	for _, f := range strings.Fields(string(b)) {
		kv := strings.SplitN(f, "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "present":
			s.present = kv[1] == "1"
		case "root":
			s.root = kv[1] == "1"
		case "boot_unix":
			if v, err := strconv.ParseInt(kv[1], 10, 64); err == nil {
				s.bootUnix = v
			}
		}
	}
	return s
}

func writeState(s state) {
	b := "present=" + b2i(s.present) + " root=" + b2i(s.root) +
		" boot_unix=" + strconv.FormatInt(s.bootUnix, 10) + "\n"
	_ = os.WriteFile(statePath(), []byte(b), 0o644)
}

func b2i(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

// joinArgs 把 adb 的参数拼回来：去掉 -s SERIAL，剩下的才是真正的命令。
func joinArgs(args []string) (serial string, rest []string) {
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-s", "-t":
			if i+1 < len(args) {
				serial = args[i+1]
				i++
			}
		default:
			rest = append(rest, args[i])
		}
	}
	return
}

func main() {
	// MOCK_LOG 设了就逐条记调用（毫秒时间戳 + 参数），排查「哪条命令卡住」用。
	if lg := os.Getenv("MOCK_LOG"); lg != "" {
		f, err := os.OpenFile(lg, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err == nil {
			fmt.Fprintf(f, "%d %s\n", time.Now().UnixMilli(), strings.Join(os.Args[1:], " "))
			f.Close()
		}
	}
	self := strings.ToLower(filepath.Base(os.Args[0]))
	if strings.Contains(self, "ghostlock") {
		payload()
		return
	}
	adb(os.Args[1:])
}

// payload 模拟 ghostlock 载荷：被 fire 起来就立刻把 root 标成可用。
func payload() {
	s := readState()
	s.root = true
	writeState(s)
	fmt.Println("=== mock ghostlock: KernelSU module loaded")
	os.Exit(0)
}

func adb(args []string) {
	s := readState()
	serial, rest := joinArgs(args)
	if len(rest) == 0 {
		fmt.Println("usage: mockadb devices|get-state|shell <cmd>|reboot|connect")
		return
	}

	// 只认 MOCKSERIAL 和形如 ip:port 的无线序列号，其它一律当作不存在 ——
	// 这样「USB 不在、要切 Wi-Fi」的路径才能被真正测到。
	reachable := s.present && (serial == "" || serial == "MOCKSERIAL" || strings.Contains(serial, ":"))

	switch rest[0] {
	case "devices":
		fmt.Println("List of devices attached")
		if s.present {
			fmt.Println("MOCKSERIAL\tdevice")
		}
		return
	case "get-state":
		if reachable {
			fmt.Println("device")
		} else {
			fmt.Fprintf(os.Stderr, "error: device '%s' not found\n", serial)
			os.Exit(1)
		}
		return
	case "connect":
		if s.present {
			fmt.Println("connected to " + strings.Join(rest[1:], " "))
		} else {
			fmt.Fprintln(os.Stderr, "failed to connect: Connection refused")
			os.Exit(1)
		}
		return
	case "reboot":
		s.bootUnix = time.Now().Unix()
		s.root = false
		writeState(s)
		fmt.Println("rebooting")
		return
	case "push", "pull", "install":
		return
	case "shell":
		cmd := strings.Join(rest[1:], " ")
		shell(cmd, s, reachable)
		return
	}
}

func shell(cmd string, s state, reachable bool) {
	if !reachable {
		os.Exit(1)
	}
	up := int64(0)
	if s.present {
		up = time.Now().Unix() - s.bootUnix
		if up < 0 {
			up = 0
		}
	}
	switch {
	// fire() 通过 `setsid sh glrun.sh` 起载荷：模拟「载荷跑起来就成功」
	case strings.Contains(cmd, "glrun.sh") || strings.Contains(cmd, "setsid"):
		// MOCK_FIRE_FAIL=1 让发射「干净失手」：不置 root，也不出成功标记。
		// 用来验证「同一个 boot 绝不发射第二次」这条保护。
		if os.Getenv("MOCK_FIRE_FAIL") == "" {
			s.root = true
			writeState(s)
		}
		fmt.Println("go")
	// 管理器的探测要能立刻命中，否则 findManager 会对十几个包名各重试 5 次，
	// 每次 500ms —— 光探测就 20 秒，把测试拖成天。
	case strings.Contains(cmd, ".gl_ksu_pkg"):
		if os.Getenv("MOCK_NO_MANAGER") == "" {
			fmt.Println("com.sukisu.ultra")
		}
	case strings.Contains(cmd, "pm list packages"):
		if os.Getenv("MOCK_NO_MANAGER") == "" && strings.Contains(cmd, "com.sukisu.ultra") {
			fmt.Println("package:com.sukisu.ultra")
		}
	case strings.Contains(cmd, "pm path"):
		if os.Getenv("MOCK_NO_MANAGER") == "" && strings.Contains(cmd, "com.sukisu.ultra") {
			fmt.Println("package:/data/app/com.sukisu.ultra-1/base.apk")
		}
	case strings.Contains(cmd, "lib/arm64/libksud.so"):
		fmt.Println("/data/app/com.sukisu.ultra-1/lib/arm64/libksud.so")
	case strings.Contains(cmd, "ls -S"):
		fmt.Println("/data/app/com.sukisu.ultra-1/lib/arm64/libksud.so")
	case strings.Contains(cmd, "getprop ro.serialno"):
		fmt.Println("MOCKSERIAL")
	case strings.Contains(cmd, "getprop ro.product.model"):
		fmt.Println("V2338A")
	case strings.Contains(cmd, "getprop ro.product.device"):
		fmt.Println("PD2338")
	case strings.Contains(cmd, "getprop ro.build.version.release"):
		fmt.Println("14")
	case strings.Contains(cmd, "getprop ro.build.version.sdk"):
		fmt.Println("34")
	case strings.Contains(cmd, "getenforce"):
		fmt.Println("Enforcing")
	case strings.TrimSpace(cmd) == "id -u":
		fmt.Println("2000")
	case strings.Contains(cmd, "/proc/self/status"):
		fmt.Println("Name:\tsh")
		fmt.Println("Seccomp:\t0")
	// fire() 判胜靠读 ksu 日志：模拟载荷成功后让它出现成功标记
	case strings.Contains(cmd, "ksu-") && strings.Contains(cmd, "cat "):
		if s.root {
			fmt.Println("=== run mock uptime=30")
			fmt.Println("[+] KernelSU module loaded")
		}
	case strings.Contains(cmd, "echo up"):
		if !s.present {
			os.Exit(1)
		}
		fmt.Println("up")
	case strings.Contains(cmd, "/proc/uptime"):
		if !s.present {
			os.Exit(1)
		}
		fmt.Printf("%d.00 0.00\n", up)
	case strings.Contains(cmd, "uname -r"):
		if !s.present {
			os.Exit(1)
		}
		fmt.Println("5.15.137-g7cb3e06b062c-dirty")
	case strings.Contains(cmd, "boot_id"):
		fmt.Println("mock-boot-id")
	case strings.Contains(cmd, "grep -c kernelsu"):
		if s.root {
			fmt.Println("1")
		} else {
			fmt.Println("0")
			os.Exit(1)
		}
	case strings.Contains(cmd, "su -c id"):
		// MOCK_SU_BROKEN=1 模拟「kernelsu 加载了但 su 用不了」（SELinux 拦、ksud 没接管）
		if s.root && os.Getenv("MOCK_SU_BROKEN") == "" {
			fmt.Println("uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0")
		} else {
			fmt.Fprintln(os.Stderr, "/system/bin/sh: su: inaccessible or not found")
			os.Exit(127)
		}
	default:
		fmt.Println()
	}
}
