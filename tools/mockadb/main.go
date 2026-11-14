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
		if s.root {
			fmt.Println("uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0")
		} else {
			fmt.Fprintln(os.Stderr, "/system/bin/sh: su: inaccessible or not found")
			os.Exit(127)
		}
	default:
		fmt.Println()
	}
}
