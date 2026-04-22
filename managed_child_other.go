//go:build !linux

package main

import "os/exec"

func configureManagedChild(cmd *exec.Cmd) {
	_ = cmd
}
