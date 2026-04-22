package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

var turnDaemonState = struct {
	sync.Mutex
	cmd  *exec.Cmd
	done chan error
}{}

type turnDaemonListenerSnapshot struct {
	Type string `json:"type"`
	Addr string `json:"addr"`
}

type turnDaemonSessionSnapshot struct {
	Username      string `json:"username"`
	AuthUsername  string `json:"auth_username,omitempty"`
	ClientAddr    string `json:"client_addr"`
	RelayAddr     string `json:"relay_addr"`
	RequestedPort int    `json:"requested_port,omitempty"`
	AllocatedPort int    `json:"allocated_port,omitempty"`
	OutboundOnly  bool   `json:"outbound_only,omitempty"`
	InternalOnly  bool   `json:"internal_only,omitempty"`
}

type turnDaemonStatusSnapshot struct {
	Realm           string                       `json:"realm"`
	MaxSessions     int                          `json:"max_sessions"`
	Users           int                          `json:"users"`
	PortRanges      int                          `json:"port_ranges"`
	GlobalSessions  int64                        `json:"global_sessions"`
	InternalPackets int64                        `json:"internal_packets"`
	ExternalPackets int64                        `json:"external_packets"`
	Listeners       []turnDaemonListenerSnapshot `json:"listeners"`
	Sessions        []turnDaemonSessionSnapshot  `json:"sessions"`
}

func findTurnDaemon() string {
	if *turnDaemonPath != "" {
		return *turnDaemonPath
	}
	candidates := []string{
		"./turn",
		"../turn",
		"../userspace-wireguard-socks/turn/turn",
	}
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	if p, err := exec.LookPath("turn"); err == nil {
		return p
	}
	return "./turn"
}

func normalizeManagedTURNAPIURL() {
	if *turnAPIURL == "unix://turn.sock" && !unixSocketSupported() {
		port := findFreePort()
		*turnAPIURL = fmt.Sprintf("http://127.0.0.1:%d", port)
		if *turnAPIToken == "" {
			tokenBytes := make([]byte, 32)
			rand.Read(tokenBytes)
			*turnAPIToken = hex.EncodeToString(tokenBytes)
		}
		log.Printf("Unix sockets unavailable; TURN API on %s (token set)", *turnAPIURL)
	}
}

func buildTurnDaemonCommand() *exec.Cmd {
	cmd := exec.Command(*turnDaemonPath, "--config", resolvePath("turn_canonical.yaml"))
	configureManagedChild(cmd)
	return cmd
}

func turnHostingEnabled() bool {
	return getConfig("turn_hosting_enabled") == "true"
}

func managedTURNAPIListenAddress() string {
	apiListen := daemonAPIListenAddress(*turnAPIURL)
	if strings.HasPrefix(apiListen, "unix://") {
		socketPath := strings.TrimPrefix(apiListen, "unix://")
		if !filepath.IsAbs(socketPath) {
			apiListen = "unix://" + resolvePath(socketPath)
		}
	}
	return apiListen
}

func startManagedTURNDaemon() error {
	if !turnHostingEnabled() {
		return nil
	}
	if len(listEnabledTURNListeners()) == 0 {
		log.Printf("TURN hosting enabled but no TURN listeners are configured; skipping TURN daemon start")
		return nil
	}

	cmd := buildTurnDaemonCommand()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	log.Printf("Starting managed TURN daemon: %s %s", cmd.Path, strings.Join(cmd.Args[1:], " "))
	if err := cmd.Start(); err != nil {
		return err
	}

	done := make(chan error, 1)
	turnDaemonState.Lock()
	turnDaemonState.cmd = cmd
	turnDaemonState.done = done
	turnDaemonState.Unlock()

	go func(started *exec.Cmd) {
		err := started.Wait()
		done <- err
		turnDaemonState.Lock()
		if turnDaemonState.cmd == started {
			turnDaemonState.cmd = nil
			turnDaemonState.done = nil
		}
		turnDaemonState.Unlock()
		if err != nil {
			log.Printf("Managed TURN daemon exited: %v", err)
		}
	}(cmd)
	return nil
}

func stopManagedTURNDaemon(timeout time.Duration) error {
	turnDaemonState.Lock()
	cmd := turnDaemonState.cmd
	done := turnDaemonState.done
	turnDaemonState.Unlock()
	if cmd == nil || cmd.Process == nil {
		return nil
	}

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil && !strings.Contains(err.Error(), "process already finished") {
		return err
	}
	select {
	case <-done:
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		<-done
	}

	turnDaemonState.Lock()
	if turnDaemonState.cmd == cmd {
		turnDaemonState.cmd = nil
		turnDaemonState.done = nil
	}
	turnDaemonState.Unlock()
	return nil
}

func restartManagedTURNDaemon() error {
	if !*manageDaemon {
		return fmt.Errorf("daemon management is disabled")
	}
	generateTurnCanonicalYAML()
	if err := stopManagedTURNDaemon(5 * time.Second); err != nil {
		return fmt.Errorf("stop turn daemon: %w", err)
	}
	if !turnHostingEnabled() {
		return nil
	}
	if err := startManagedTURNDaemon(); err != nil {
		return fmt.Errorf("start turn daemon: %w", err)
	}
	time.Sleep(300 * time.Millisecond)
	return syncTURNCredentialsToDaemon()
}

func restartManagedTURNDaemonIfEnabled() {
	if !*manageDaemon {
		return
	}
	if err := restartManagedTURNDaemon(); err != nil {
		log.Printf("Auto-restart after TURN change failed: %v", err)
	}
}

func generateTurnCanonicalYAML() {
	_ = os.WriteFile(resolvePath("turn_canonical.yaml"), buildTurnCanonicalYAMLBytes(), 0o644)
}

func buildTurnCanonicalYAMLBytes() []byte {
	config := map[string]interface{}{
		"realm": turnHostingRealm(),
		"listen": map[string]interface{}{
			"relay_ip": turnHostingRelayIP(),
		},
		"api": map[string]interface{}{
			"listen": managedTURNAPIListenAddress(),
			"token":  *turnAPIToken,
		},
	}

	if listeners := buildTURNListenerConfigMaps(); len(listeners) > 0 {
		config["listeners"] = listeners
	}
	if users := buildTURNDaemonUsers(); len(users) > 0 {
		config["users"] = users
	}
	data, _ := yaml.Marshal(config)
	return data
}

func turnRequest(method, path string, body io.Reader, out interface{}) (int, error) {
	addr := *turnAPIURL
	var (
		client  *http.Client
		baseURL string
	)
	if strings.HasPrefix(addr, "unix://") {
		socketPath := strings.TrimPrefix(addr, "unix://")
		if !filepath.IsAbs(socketPath) {
			socketPath = resolvePath(socketPath)
		}
		client = &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
				},
			},
		}
		baseURL = "http://turn.sock"
	} else {
		client = &http.Client{Timeout: 5 * time.Second}
		baseURL = strings.TrimRight(addr, "/")
	}

	req, err := http.NewRequest(method, baseURL+path, body)
	if err != nil {
		return 0, err
	}
	if *turnAPIToken != "" {
		req.Header.Set("Authorization", "Bearer "+*turnAPIToken)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if out != nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return resp.StatusCode, err
		}
	}
	return resp.StatusCode, nil
}

func syncTURNCredentialsToDaemon() error {
	if !turnHostingEnabled() {
		return nil
	}
	payload, err := json.Marshal(buildTURNDaemonUsers())
	if err != nil {
		return err
	}
	code, err := turnRequest(http.MethodPut, "/v1/users", bytes.NewReader(payload), nil)
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("turn daemon returned %d for user sync", code)
	}
	return nil
}

func fetchTURNStatus() turnDaemonStatusSnapshot {
	var status turnDaemonStatusSnapshot
	_, err := turnRequest(http.MethodGet, "/v1/status", nil, &status)
	if err != nil {
		return turnDaemonStatusSnapshot{}
	}
	return status
}

func activeTURNUsernames() map[string]bool {
	status := fetchTURNStatus()
	active := make(map[string]bool, len(status.Sessions))
	for _, sess := range status.Sessions {
		if sess.Username != "" {
			active[sess.Username] = true
		}
	}
	return active
}

func turnHostingRealm() string {
	if realm := strings.TrimSpace(getConfig("turn_hosting_realm")); realm != "" {
		return realm
	}
	return "open-relay.local"
}

func turnHostingRelayIP() string {
	if ip := strings.TrimSpace(getConfig("turn_hosting_relay_ip")); ip != "" {
		return ip
	}
	host := hostWithoutPort(strings.TrimSpace(getConfig("server_endpoint")))
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.String()
	}
	if detected := detectDefaultBootstrapIP(); detected != "" {
		return detected
	}
	return "127.0.0.1"
}

func turnUserCredentialsAllowed() bool {
	return getConfig("turn_allow_user_credentials") == "true"
}

func turnUserCredentialLimit() int {
	n, _ := strconv.Atoi(strings.TrimSpace(getConfig("turn_max_user_credentials")))
	if n <= 0 {
		return 3
	}
	return n
}

func turnUserPortRange() (int, int) {
	start, _ := strconv.Atoi(strings.TrimSpace(getConfig("turn_user_port_start")))
	end, _ := strconv.Atoi(strings.TrimSpace(getConfig("turn_user_port_end")))
	if start <= 0 {
		start = 40000
	}
	if end < start {
		end = 49999
	}
	return start, end
}
