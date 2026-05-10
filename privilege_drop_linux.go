//go:build linux

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// resolveRunAsIDs parses a "user:group" or "uid:gid" string.
// Both names and numeric IDs are accepted.
func resolveRunAsIDs(spec string) (uid, gid int, err error) {
	parts := strings.SplitN(spec, ":", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("--run-as must be user:group or uid:gid")
	}

	uid, err = resolveUserID(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("user %q: %w", parts[0], err)
	}
	gid, err = resolveGroupID(parts[1])
	if err != nil {
		return 0, 0, fmt.Errorf("group %q: %w", parts[1], err)
	}
	return uid, gid, nil
}

func resolveUserID(s string) (int, error) {
	if n, err := strconv.Atoi(s); err == nil {
		return n, nil
	}
	// Look up by name via /etc/passwd (avoids cgo dependency on getpwnam).
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) >= 3 && fields[0] == s {
			return strconv.Atoi(fields[2])
		}
	}
	return 0, fmt.Errorf("user not found")
}

func resolveGroupID(s string) (int, error) {
	if n, err := strconv.Atoi(s); err == nil {
		return n, nil
	}
	data, err := os.ReadFile("/etc/group")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) >= 3 && fields[0] == s {
			return strconv.Atoi(fields[2])
		}
	}
	return 0, fmt.Errorf("group not found")
}

// chownDataDir reassigns ownership of dataDir files to uid:gid so they remain
// accessible after we drop from root to the target user.
func chownDataDir(dir string, uid, gid int) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	if err := os.Chown(dir, uid, gid); err != nil {
		return fmt.Errorf("chown dir: %w", err)
	}
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		if err := os.Chown(p, uid, gid); err != nil {
			log.Printf("chown %s: %v (continuing)", p, err)
		}
	}
	return nil
}

// Linux capability header/data structures for capset(2).
const (
	linuxCapVersion3 = 0x20080522
	capNetAdmin      = 12
)

type capHeader struct {
	version uint32
	pid     int32
}

type capData struct {
	effective   uint32
	permitted   uint32
	inheritable uint32
}

func capsetRaw(hdr *capHeader, data *[2]capData) error {
	_, _, errno := syscall.Syscall(syscall.SYS_CAPSET,
		uintptr(unsafe.Pointer(hdr)),
		uintptr(unsafe.Pointer(&data[0])),
		0)
	if errno != 0 {
		return errno
	}
	return nil
}

// dropPrivilegesKeepNetAdmin drops from root to uid:gid while retaining
// CAP_NET_ADMIN in permitted/effective/inheritable and raising it as an
// ambient capability so child processes (uwgkm) inherit it without setuid.
//
// Call order matters (Linux semantics):
//  1. PR_SET_KEEPCAPS=1 — survive setuid
//  2. setgid / setgroups / setuid
//  3. restore effective caps from permitted
//  4. add CAP_NET_ADMIN to inheritable
//  5. raise CAP_NET_ADMIN as ambient
//  6. PR_SET_DUMPABLE=0 — prevent ptrace of privileged process
//  7. PR_SET_NO_NEW_PRIVS=1 — no further privilege escalation
func dropPrivilegesKeepNetAdmin(uid, gid int) error {
	// 1. Keep capabilities across uid change.
	if err := unix.Prctl(unix.PR_SET_KEEPCAPS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("PR_SET_KEEPCAPS: %w", err)
	}

	// 2. Drop supplemental groups, then set gid/uid.
	if err := syscall.Setgroups([]int{gid}); err != nil {
		return fmt.Errorf("setgroups: %w", err)
	}
	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("setgid(%d): %w", gid, err)
	}
	if err := syscall.Setuid(uid); err != nil {
		return fmt.Errorf("setuid(%d): %w", uid, err)
	}

	// 3+4. Restore CAP_NET_ADMIN in effective+permitted+inheritable.
	netAdminBit := uint32(1 << capNetAdmin)
	hdr := capHeader{version: linuxCapVersion3, pid: 0}
	data := [2]capData{
		{effective: netAdminBit, permitted: netAdminBit, inheritable: netAdminBit},
	}
	if err := capsetRaw(&hdr, &data); err != nil {
		return fmt.Errorf("capset: %w", err)
	}

	// 5. Raise ambient CAP_NET_ADMIN so exec'd children inherit it.
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_RAISE, capNetAdmin, 0, 0); err != nil {
		// Ambient caps require kernel 4.3. Warn but don't fatal — the user
		// can still grant NET_ADMIN to uwgkm via file capabilities.
		log.Printf("warning: could not raise ambient CAP_NET_ADMIN: %v (uwgkm may need file capabilities)", err)
	}

	// 6. Prevent ptrace of this process.
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		log.Printf("warning: PR_SET_DUMPABLE=0 failed: %v", err)
	}

	// 7. Prevent privilege re-escalation.
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("PR_SET_NO_NEW_PRIVS: %w", err)
	}

	log.Printf("Dropped to uid=%d gid=%d, retaining CAP_NET_ADMIN", uid, gid)
	return nil
}

// dropNetAdmin removes CAP_NET_ADMIN from the web server process after uwgkm
// has been launched.  The web server does not need kernel network privileges.
func dropNetAdmin() error {
	hdr := capHeader{version: linuxCapVersion3, pid: 0}
	data := [2]capData{} // all zeros — drop everything
	if err := capsetRaw(&hdr, &data); err != nil {
		return fmt.Errorf("capset (drop all): %w", err)
	}
	log.Printf("Dropped CAP_NET_ADMIN from web server process")
	return nil
}
