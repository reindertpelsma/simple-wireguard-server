package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var daemonState = struct {
	sync.Mutex
	cmd      *exec.Cmd
	done     chan error
	stopping atomic.Bool
}{}

// daemonCrashExit controls whether an unexpected daemon exit terminates this
// process via os.Exit(1). True in production; tests set it false so a daemon
// crash surfaces as a test failure rather than killing the test binary.
var daemonCrashExit = true

func startManagedDaemon() error {
	time.Sleep(1 * time.Second)

	cmd := buildDaemonCommand()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	log.Printf("Starting managed daemon: %s %s", cmd.Path, strings.Join(cmd.Args[1:], " "))
	if err := cmd.Start(); err != nil {
		return err
	}

	done := make(chan error, 1)
	daemonState.Lock()
	daemonState.cmd = cmd
	daemonState.done = done
	daemonState.Unlock()

	go func(started *exec.Cmd) {
		err := started.Wait()
		// Check stopping before acquiring the lock: stopManagedDaemon sets
		// stopping=true before SIGTERM so we always see it here even if
		// stopManagedDaemon has not yet received from `done`.
		intentional := daemonState.stopping.Load()
		done <- err
		daemonState.Lock()
		if daemonState.cmd == started {
			daemonState.cmd = nil
			daemonState.done = nil
		}
		daemonState.Unlock()
		if err != nil {
			log.Printf("Managed daemon exited: %v", err)
		}
		if !intentional && daemonCrashExit {
			log.Printf("Managed daemon exited unexpectedly; shutting down web server")
			os.Exit(1)
		}
	}(cmd)
	return nil
}

func buildDaemonCommand() *exec.Cmd {
	apiListen := daemonAPIListenAddress(*uwgsocksURL)
	if strings.HasPrefix(apiListen, "unix://") {
		socketPath := strings.TrimPrefix(apiListen, "unix://")
		if !filepath.IsAbs(socketPath) {
			apiListen = "unix://" + resolvePath(socketPath)
		}
	}
	var cmd *exec.Cmd
	if *systemMode {
		args := []string{"-config", resolvePath("uwg_canonical.yaml"), "-api-listen", apiListen}
		if *uwgsocksToken != "" {
			args = append(args, "-api-token", *uwgsocksToken)
		}
		cmd = exec.Command(*daemonPath, args...)
	} else {
		cmd = exec.Command(*daemonPath, "--config", resolvePath("uwg_canonical.yaml"))
	}
	configureManagedChild(cmd)
	return cmd
}

func stopManagedDaemon(timeout time.Duration) error {
	daemonState.Lock()
	cmd := daemonState.cmd
	done := daemonState.done
	daemonState.Unlock()
	if cmd == nil || cmd.Process == nil {
		return nil
	}

	// Mark as intentional before sending the signal so the watcher goroutine
	// does not treat this exit as a crash.
	daemonState.stopping.Store(true)
	defer daemonState.stopping.Store(false)

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil && !strings.Contains(err.Error(), "process already finished") {
		return err
	}

	select {
	case <-done:
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		<-done
	}

	daemonState.Lock()
	if daemonState.cmd == cmd {
		daemonState.cmd = nil
		daemonState.done = nil
	}
	daemonState.Unlock()
	return nil
}

func restartManagedDaemon() error {
	if !*manageDaemon {
		return fmt.Errorf("daemon management is disabled")
	}
	generateCanonicalYAML()
	if err := stopManagedDaemon(5 * time.Second); err != nil {
		return fmt.Errorf("stop daemon: %w", err)
	}
	if err := startManagedDaemon(); err != nil {
		return fmt.Errorf("start daemon: %w", err)
	}
	invalidateACLPushCache()
	time.Sleep(1 * time.Second)
	syncPeersToDaemon()
	pushACLsToDaemon()
	return nil
}

func restartManagedDaemonIfEnabled() {
	if !*manageDaemon {
		return
	}
	if err := restartManagedDaemon(); err != nil {
		log.Printf("Auto-restart after transport change failed: %v", err)
	}
}

func handleRestartDaemon(w http.ResponseWriter, r *http.Request) {
	if err := restartManagedDaemon(); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if err := restartManagedTURNDaemon(); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "restarted"})
}
