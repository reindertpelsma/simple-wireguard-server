//go:build !linux

package main

import "fmt"

func resolveRunAsIDs(spec string) (uid, gid int, err error) {
	return 0, 0, fmt.Errorf("--run-as is only supported on Linux")
}

func chownDataDir(dir string, uid, gid int) error {
	return fmt.Errorf("--run-as is only supported on Linux")
}

func dropPrivilegesKeepNetAdmin(uid, gid int) error {
	return fmt.Errorf("--run-as is only supported on Linux")
}

func dropNetAdmin() error {
	return nil
}
