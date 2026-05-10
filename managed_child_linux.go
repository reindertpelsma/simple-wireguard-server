//go:build linux

package main

import (
	"os/exec"
	"syscall"
)

func configureManagedChild(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	// SIGTERM (not SIGKILL) so children — notably uwgkm — can run cleanup on
	// parent death (delete WireGuard interface, flush nftables rules).
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
}
