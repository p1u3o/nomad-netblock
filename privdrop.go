package main

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
)

const (
	childEnv    = "NETBLOCK_CHILD"
	capNetAdmin = 12
)

// runAsChild re-executes this binary as run_as uid/gid with CAP_NET_ADMIN as the only
// (ambient) capability, forwards signals, and returns the child's exit code. The parent
// stays root only to wait; it does no other work.
func runAsChild(c Config) int {
	cmd := exec.Command("/proc/self/exe", os.Args[1:]...)
	cmd.Args[0] = os.Args[0]
	cmd.Env = append(os.Environ(), childEnv+"=1")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential:  &syscall.Credential{Uid: uint32(c.RunAsUID), Gid: uint32(c.RunAsGID), Groups: []uint32{}},
		AmbientCaps: []uintptr{capNetAdmin},
		Pdeathsig:   syscall.SIGKILL,
	}
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	if err := cmd.Start(); err != nil {
		logf("watch: cannot start as uid %d: %v", c.RunAsUID, err)
		return 1
	}
	logf("watch: started child pid %d as uid=%d gid=%d with ambient CAP_NET_ADMIN", cmd.Process.Pid, c.RunAsUID, c.RunAsGID)
	go func() {
		for s := range sigs {
			_ = cmd.Process.Signal(s)
		}
	}()
	err := cmd.Wait()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ee.ExitCode() >= 0 {
			return ee.ExitCode()
		}
		return 1
	}
	if err != nil {
		logf("watch: child: %v", err)
		return 1
	}
	return 0
}

func capsDesc() string {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return ""
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), ":"); ok && strings.HasPrefix(k, "Cap") {
			out = append(out, k+"="+strings.TrimSpace(v))
		}
	}
	return strings.Join(out, " ")
}
