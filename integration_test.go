package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"gopkg.in/yaml.v3"
)

func TestIntegrationManagedDaemonRuntimeAndProxy(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireUDPPort(t, 51820)

	daemonBin := buildIntegrationUwgsocks(t)
	apiPort := freeIntegrationTCPPort(t)
	httpProxyPort := freeIntegrationTCPPort(t)
	dataDir := t.TempDir()
	setupIntegrationGlobals(t, dataDir, daemonBin, fmt.Sprintf("http://127.0.0.1:%d", apiPort), "integration-token")
	setupTestDB(t)
	ensureDefaultTransport()
	setTestConfig(t, "enable_client_ipv6", "false")
	setTestConfig(t, "yaml_http_port", fmt.Sprint(httpProxyPort))
	setTestConfig(t, "yaml_socks5_port", fmt.Sprint(freeIntegrationTCPPort(t)))
	setTestConfig(t, "http_proxy_access_enabled", "true")
	setTestConfig(t, "acl_outbound_default", "deny")
	setTestConfig(t, "acl_relay_default", "deny")
	setTestConfig(t, "yaml_l3_forwarding", "true")

	if err := gdb.Create(&Group{Name: "engineering", Subnet: "100.100.8.0/24", SubnetIPv6: "fd00:100:8::/64"}).Error; err != nil {
		t.Fatal(err)
	}
	user, _ := createTestUser(t, "integration-user", false)
	user.PrimaryGroup = "engineering"
	user.Tags = "staff"
	if err := gdb.Save(&user).Error; err != nil {
		t.Fatal(err)
	}
	hash, _ := hashPassword("proxy-secret")
	if err := gdb.Create(&AccessProxyCredential{UserID: user.ID, Username: "proxy-user", PasswordHash: hash, Name: "integration", Enabled: true}).Error; err != nil {
		t.Fatal(err)
	}

	generateCanonicalYAML()
	if err := startManagedDaemon(); err != nil {
		t.Fatalf("start managed daemon: %v", err)
	}
	t.Cleanup(func() { _ = stopManagedDaemon(5 * time.Second) })
	waitForDaemonStatus(t)

	clientKey := mustIntegrationKey(t)
	peer := createIntegrationPeer(t, user, clientKey.PublicKey().String())
	assignedIPv4 := firstAssignedIPv4(t, peer.AssignedIPs)
	if !strings.HasPrefix(assignedIPv4.String(), "100.100.8.") {
		t.Fatalf("peer was not allocated from primary group subnet: %s", peer.AssignedIPs)
	}
	assertDaemonPeer(t, clientKey.PublicKey().String())

	clientEchoPort := freeIntegrationTCPPort(t)
	clientEchoTargetPort := freeIntegrationTCPPort(t)
	stopClientEcho := startHostEcho(t, fmt.Sprintf("127.0.0.1:%d", clientEchoTargetPort), "client")
	defer stopClientEcho()
	clientLocalForwardPort := freeIntegrationTCPPort(t)
	reversePort := 18091
	stopClient := startIntegrationClientDaemon(t, daemonBin, dataDir, clientKey, peer, assignedIPv4, clientEchoPort, clientEchoTargetPort, clientLocalForwardPort, reversePort)
	defer stopClient()

	allowStaffToClientEcho(t, assignedIPv4.String(), clientEchoPort)
	assertDaemonACLContains(t, "outbound", assignedIPv4.String()+"/32", fmt.Sprint(clientEchoPort))
	assertDaemonACLContains(t, "relay", assignedIPv4.String()+"/32", fmt.Sprint(clientEchoPort))

	createRuntimeTransport(t, freeIntegrationTCPPort(t))
	assertDaemonTransport(t, "tcp-runtime")

	hostEchoPort := freeIntegrationTCPPort(t)
	stopHostEcho := startHostEcho(t, fmt.Sprintf("127.0.0.1:%d", hostEchoPort), "host")
	defer stopHostEcho()
	createRuntimeForward(t, TunnelForward{
		Name:    "client-to-host",
		Reverse: true,
		Proto:   "tcp",
		Listen:  fmt.Sprintf("100.100.0.1:%d", reversePort),
		Target:  fmt.Sprintf("127.0.0.1:%d", hostEchoPort),
	})
	assertDaemonForward(t, true, fmt.Sprintf("100.100.0.1:%d", reversePort), fmt.Sprintf("127.0.0.1:%d", hostEchoPort))
	assertEchoOverTCP(t, fmt.Sprintf("127.0.0.1:%d", clientLocalForwardPort), "reverse", "host:reverse\n")

	forwardPort := freeIntegrationTCPPort(t)
	createRuntimeForward(t, TunnelForward{
		Name:   "host-to-client",
		Proto:  "tcp",
		Listen: fmt.Sprintf("127.0.0.1:%d", forwardPort),
		Target: fmt.Sprintf("%s:%d", assignedIPv4, clientEchoPort),
	})
	assertDaemonForward(t, false, fmt.Sprintf("127.0.0.1:%d", forwardPort), fmt.Sprintf("%s:%d", assignedIPv4, clientEchoPort))
	assertEchoOverTCP(t, fmt.Sprintf("127.0.0.1:%d", forwardPort), "forward", "client:forward\n")

	ui := httptest.NewServer(wrapRootHandler(http.NewServeMux()))
	defer ui.Close()
	assertProxyCONNECT(t, ui.URL, fmt.Sprintf("%s:%d", assignedIPv4, clientEchoPort), "proxied", "client:proxied\n", http.StatusOK)

	gdb.Model(&ACLRule{}).Where("list_name = ?", "outbound").Update("action", "deny")
	invalidateACLPushCache()
	pushACLsToDaemon()
	assertProxyCONNECT(t, ui.URL, fmt.Sprintf("%s:%d", assignedIPv4, clientEchoPort), "blocked", "", http.StatusForbidden)
}

func setupIntegrationGlobals(t *testing.T, dir, daemon, apiURL, token string) {
	t.Helper()
	oldDataDir, oldDaemon, oldURL, oldToken := *dataDir, *daemonPath, *uwgsocksURL, *uwgsocksToken
	oldManage, oldSystem := *manageDaemon, *systemMode
	*dataDir = dir
	*daemonPath = daemon
	*uwgsocksURL = apiURL
	*uwgsocksToken = token
	*manageDaemon = true
	*systemMode = false
	t.Cleanup(func() {
		*dataDir = oldDataDir
		*daemonPath = oldDaemon
		*uwgsocksURL = oldURL
		*uwgsocksToken = oldToken
		*manageDaemon = oldManage
		*systemMode = oldSystem
	})
}

func buildIntegrationUwgsocks(t *testing.T) string {
	t.Helper()

	repo := "./userspace-wireguard-socks"
	if st, err := os.Stat(filepath.Join(repo, "uwgsocks.go")); err != nil || st.IsDir() {
		repo = "../userspace-wireguard-socks"
		if st, err := os.Stat(filepath.Join(repo, "uwgsocks.go")); err != nil || st.IsDir() {
			repo = "../"
			if st, err := os.Stat(filepath.Join(repo, "uwgsocks.go")); err != nil || st.IsDir() {
				t.Skipf("sibling userspace-wireguard-socks repo not found at %s", repo)
			}
		}
	}
	binDir, err := os.MkdirTemp("", "uwgsocks-test-*")
	if err != nil {
		t.Fatal(err)
	}
	// On Windows the OS holds an .exe lock briefly after the process exits.
	// t.TempDir cleanup is immediate and fails; retry with backoff instead.
	t.Cleanup(func() {
		for i := 0; i < 15; i++ {
			if err := os.RemoveAll(binDir); err == nil {
				return
			}
			time.Sleep(200 * time.Millisecond)
		}
		_ = os.RemoveAll(binDir)
	})
	bin := filepath.Join(binDir, "uwgsocks")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	goBin := "go"
	if p := filepath.Join(os.Getenv("HOME"), "sdk", "go", "bin", "go"); fileExists(p) {
		goBin = p
	}
	cmd := exec.Command(goBin, "build", "-o", bin, "./cmd/uwgsocks")
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=auto")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build sibling uwgsocks: %v\n%s", err, out)
	}
	return bin
}

func createIntegrationPeer(t *testing.T, user User, publicKey string) Peer {
	t.Helper()
	body, _ := json.Marshal(map[string]interface{}{
		"name":          "integration-client",
		"public_key":    publicKey,
		"is_manual_key": true,
		"keepalive":     1,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/peers", bytes.NewReader(body))
	req.Header.Set("X-User-Id", fmt.Sprint(user.ID))
	req.Header.Set("X-Is-Admin", "true")
	w := httptest.NewRecorder()
	handleCreatePeer(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("create peer status = %d: %s", w.Code, w.Body.String())
	}
	var peer Peer
	if err := gdb.First(&peer, "public_key = ?", publicKey).Error; err != nil {
		t.Fatal(err)
	}
	return peer
}

func startIntegrationClientDaemon(t *testing.T, daemonBin, dir string, key wgtypes.Key, peer Peer, assignedIPv4 netip.Addr, clientEchoPort, clientEchoTargetPort, localForwardPort, reversePort int) func() {
	t.Helper()
	cfg := map[string]interface{}{
		"wireguard": map[string]interface{}{
			"private_key": key.String(),
			"addresses":   splitCSVList(peer.AssignedIPs),
			"peers": []map[string]interface{}{{
				"public_key":           getConfig("server_pubkey"),
				"preshared_key":        decryptAtRest(peer.PresharedKey),
				"endpoint":             "127.0.0.1:51820",
				"allowed_ips":          []string{"100.100.0.0/16"},
				"persistent_keepalive": 1,
			}},
		},
		"api": map[string]interface{}{
			"listen": fmt.Sprintf("127.0.0.1:%d", freeIntegrationTCPPort(t)),
		},
		"proxy": map[string]interface{}{
			"socks5": fmt.Sprintf("127.0.0.1:%d", freeIntegrationTCPPort(t)),
			"http":   fmt.Sprintf("127.0.0.1:%d", freeIntegrationTCPPort(t)),
		},
		"forwards": []map[string]interface{}{{
			"proto":  "tcp",
			"listen": fmt.Sprintf("127.0.0.1:%d", localForwardPort),
			"target": fmt.Sprintf("100.100.0.1:%d", reversePort),
		}},
		"reverse_forwards": []map[string]interface{}{{
			"proto":  "tcp",
			"listen": fmt.Sprintf("%s:%d", assignedIPv4, clientEchoPort),
			"target": fmt.Sprintf("127.0.0.1:%d", clientEchoTargetPort),
		}},
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "client.yaml")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(daemonBin, "--config", path)
	cmd.Stdout = pipeWriter{os.Stdout}
	cmd.Stderr = pipeWriter{os.Stderr}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start client daemon: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	return func() {
		if cmd.Process != nil {
			_ = cmd.Process.Signal(os.Interrupt)
		}
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	}
}

func allowStaffToClientEcho(t *testing.T, ip string, port int) {
	t.Helper()
	rules := []ACLRule{
		{ListName: "outbound", Action: "allow", Dst: ip + "/32", Proto: "tcp", DPort: fmt.Sprint(port), SortOrder: 0},
		{ListName: "outbound", Action: "allow", SrcTags: "staff", Dst: ip + "/32", Proto: "tcp", DPort: fmt.Sprint(port), SortOrder: 1},
		{ListName: "relay", Action: "allow", SrcTags: "staff", Dst: ip + "/32", Proto: "tcp", DPort: fmt.Sprint(port), SortOrder: 0},
	}
	for _, rule := range rules {
		if err := gdb.Create(&rule).Error; err != nil {
			t.Fatal(err)
		}
	}
	invalidateACLPushCache()
	pushACLsToDaemon()
}

func createRuntimeTransport(t *testing.T, port int) {
	t.Helper()
	body, _ := json.Marshal(map[string]interface{}{
		"name":        "tcp-runtime",
		"base":        "tcp",
		"listen":      true,
		"listen_port": port,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/admin/transports", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handleCreateTransport(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create transport status = %d: %s", w.Code, w.Body.String())
	}
}

func createRuntimeForward(t *testing.T, f TunnelForward) {
	t.Helper()
	body, _ := json.Marshal(f)
	req := httptest.NewRequest(http.MethodPost, "/api/admin/forwards", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handleCreateForward(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create forward status = %d: %s", w.Code, w.Body.String())
	}
}

func startHostEcho(t *testing.T, addr, prefix string) func() {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go serveEcho(ln, prefix, done)
	return func() {
		_ = ln.Close()
		<-done
	}
}

func serveEcho(ln net.Listener, prefix string, done chan<- struct{}) {
	defer close(done)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			line, _ := bufio.NewReader(c).ReadString('\n')
			_, _ = io.WriteString(c, prefix+":"+line)
		}(conn)
	}
}

func assertEchoOverTCP(t *testing.T, addr, msg, want string) {
	t.Helper()
	var lastErr error
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			lastErr = err
			continue
		}
		got, err := writeReadLine(conn, msg)
		_ = conn.Close()
		if err == nil && got == want {
			return
		}
		lastErr = fmt.Errorf("got %q err=%v", got, err)
	}
	t.Fatalf("echo over tcp %s failed: %v", addr, lastErr)
}

func assertProxyCONNECT(t *testing.T, uiURL, target, msg, want string, wantStatus int) {
	t.Helper()
	addr := strings.TrimPrefix(uiURL, "http://")
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	auth := base64.StdEncoding.EncodeToString([]byte("proxy-user:proxy-secret"))
	_, _ = fmt.Fprintf(conn, "CONNECT /proxy/%s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n", target, addr, auth)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != wantStatus {
		t.Fatalf("CONNECT status = %d, want %d", resp.StatusCode, wantStatus)
	}
	if wantStatus != http.StatusOK {
		return
	}
	_, _ = io.WriteString(conn, msg+"\n")
	got, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("proxy echo = %q, want %q", got, want)
	}
}

func writeReadLine(conn net.Conn, msg string) (string, error) {
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(conn, msg+"\n"); err != nil {
		return "", err
	}
	return bufio.NewReader(conn).ReadString('\n')
}

func daemonJSON(t *testing.T, method, path string, body io.Reader, out interface{}) int {
	t.Helper()
	req, err := http.NewRequest(method, strings.TrimSuffix(*uwgsocksURL, "/")+path, body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+*uwgsocksToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatalf("decode daemon %s %s: %v", method, path, err)
		}
	}
	return resp.StatusCode
}

func waitForDaemonStatus(t *testing.T) {
	t.Helper()
	var lastErr error
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		req, _ := http.NewRequest(http.MethodGet, strings.TrimSuffix(*uwgsocksURL, "/")+"/v1/status", nil)
		req.Header.Set("Authorization", "Bearer "+*uwgsocksToken)
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
		} else {
			lastErr = err
		}
	}
	t.Fatalf("daemon API did not become ready: %v", lastErr)
}

func assertDaemonPeer(t *testing.T, publicKey string) {
	t.Helper()
	var peers []map[string]interface{}
	if code := daemonJSON(t, http.MethodGet, "/v1/peers", nil, &peers); code != http.StatusOK {
		t.Fatalf("GET /v1/peers = %d", code)
	}
	for _, peer := range peers {
		if peer["public_key"] == publicKey {
			return
		}
	}
	t.Fatalf("daemon peer %s not found in %+v", publicKey, peers)
}

func assertDaemonACLContains(t *testing.T, listName, dst, dport string) {
	t.Helper()
	var acl map[string]interface{}
	if code := daemonJSON(t, http.MethodGet, "/v1/acls", nil, &acl); code != http.StatusOK {
		t.Fatalf("GET /v1/acls = %d", code)
	}
	rules, _ := acl[listName].([]interface{})
	for _, raw := range rules {
		rule, _ := raw.(map[string]interface{})
		if rule["destination"] == dst && rule["destination_port"] == dport {
			return
		}
	}
	t.Fatalf("daemon %s ACL missing dst=%s dport=%s in %+v", listName, dst, dport, rules)
}

func assertDaemonTransport(t *testing.T, name string) {
	t.Helper()
	var transports []map[string]interface{}
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		transports = nil
		if code := daemonJSON(t, http.MethodGet, "/v1/transports", nil, &transports); code != http.StatusOK {
			t.Fatalf("GET /v1/transports = %d", code)
		}
		for _, tr := range transports {
			if tr["name"] == name {
				return
			}
		}
	}
	t.Fatalf("daemon transport %q not found in %+v", name, transports)
}

func assertDaemonForward(t *testing.T, reverse bool, listen, target string) {
	t.Helper()
	var forwards []daemonForwardSnapshot
	if code := daemonJSON(t, http.MethodGet, "/v1/forwards", nil, &forwards); code != http.StatusOK {
		t.Fatalf("GET /v1/forwards = %d", code)
	}
	for _, f := range forwards {
		if f.Reverse == reverse && f.Listen == listen && f.Target == target {
			return
		}
	}
	t.Fatalf("daemon forward reverse=%v listen=%s target=%s not found in %+v", reverse, listen, target, forwards)
}

func firstAssignedIPv4(t *testing.T, assigned string) netip.Addr {
	t.Helper()
	for _, part := range splitCSVList(assigned) {
		prefix, err := netip.ParsePrefix(part)
		if err == nil && prefix.Addr().Is4() {
			return prefix.Addr()
		}
	}
	t.Fatalf("assigned IPs do not contain IPv4: %s", assigned)
	return netip.Addr{}
}

func mustIntegrationKey(t *testing.T) wgtypes.Key {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func freeIntegrationTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func requireUDPPort(t *testing.T, port int) {
	t.Helper()
	conn, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Skipf("UDP port %d unavailable for managed uwgsocks integration test: %v", port, err)
	}
	_ = conn.Close()
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}
