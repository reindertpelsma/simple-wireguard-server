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
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}
