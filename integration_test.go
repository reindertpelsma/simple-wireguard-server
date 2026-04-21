//go:build integration

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
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
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
	setTestConfig(t, "e2e_encryption_enabled", "false")
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
	waitForDaemonPeerHandshake(t, clientKey.PublicKey().String())

	allowStaffToTarget(t, assignedIPv4.String(), clientEchoPort)
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
	waitForProxyCONNECTReady(t, ui.URL, fmt.Sprintf("%s:%d", assignedIPv4, clientEchoPort))
	assertProxyCONNECT(t, ui.URL, fmt.Sprintf("%s:%d", assignedIPv4, clientEchoPort), "proxied", "client:proxied\n", http.StatusOK)

	gdb.Model(&ACLRule{}).Where("list_name = ?", "outbound").Update("action", "deny")
	invalidateACLPushCache()
	pushACLsToDaemon()
	assertProxyCONNECT(t, ui.URL, fmt.Sprintf("%s:%d", assignedIPv4, clientEchoPort), "blocked", "", http.StatusForbidden)
}

func TestIntegrationUISmokeLoginConfigAndProxy(t *testing.T) {
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
	user, _ := createTestUser(t, "integration-admin", true)
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

	ui := httptest.NewServer(buildIntegrationUIHandler())
	defer ui.Close()

	loginPageResp, err := http.Get(ui.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	loginPage, _ := io.ReadAll(loginPageResp.Body)
	_ = loginPageResp.Body.Close()
	if loginPageResp.StatusCode != http.StatusOK || !bytes.Contains(loginPage, []byte("<form id=\"login-form\">")) {
		t.Fatalf("login page status=%d body=%q", loginPageResp.StatusCode, loginPage)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar}
	loginBody, _ := json.Marshal(map[string]string{
		"username": "integration-admin",
		"password": "password",
	})
	loginResp, err := client.Post(ui.URL+"/api/login", "application/json", bytes.NewReader(loginBody))
	if err != nil {
		t.Fatal(err)
	}
	if loginResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(loginResp.Body)
		_ = loginResp.Body.Close()
		t.Fatalf("login status=%d body=%q", loginResp.StatusCode, body)
	}
	_ = loginResp.Body.Close()
	if len(jar.Cookies(mustURL(t, ui.URL))) == 0 {
		t.Fatal("login did not set a session cookie")
	}

	createBody, _ := json.Marshal(map[string]interface{}{
		"name":      "smoke-client",
		"keepalive": 1,
	})
	createResp, err := client.Post(ui.URL+"/api/peers", "application/json", bytes.NewReader(createBody))
	if err != nil {
		t.Fatal(err)
	}
	if createResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(createResp.Body)
		_ = createResp.Body.Close()
		t.Fatalf("create peer status=%d body=%q", createResp.StatusCode, body)
	}
	_ = createResp.Body.Close()

	var peers []Peer
	getJSONAs(t, client, ui.URL+"/api/peers", &peers)
	if len(peers) != 1 || peers[0].Name != "smoke-client" {
		t.Fatalf("unexpected peers after create: %+v", peers)
	}
	peerID := peers[0].ID
	if peers[0].PublicKey == "" {
		t.Fatalf("created peer missing public key: %+v", peers[0])
	}
	var dbPeer Peer
	if err := gdb.First(&dbPeer, peerID).Error; err != nil {
		t.Fatal(err)
	}

	var publicCfg map[string]string
	getJSONAs(t, client, ui.URL+"/api/config/public", &publicCfg)
	if publicCfg["server_pubkey"] == "" || publicCfg["server_endpoint"] == "" {
		t.Fatalf("public config missing endpoint material: %+v", publicCfg)
	}

	var privateCfg struct {
		EncryptedPrivateKey string `json:"encrypted_private_key"`
		PresharedKey        string `json:"preshared_key"`
		AssignedIPs         string `json:"assigned_ips"`
	}
	getJSONAs(t, client, fmt.Sprintf("%s/api/peers/%d/private", ui.URL, peerID), &privateCfg)
	if privateCfg.EncryptedPrivateKey == "" || privateCfg.AssignedIPs == "" {
		t.Fatalf("peer private config incomplete: %+v", privateCfg)
	}
	assignedIPv4 := firstAssignedIPv4(t, privateCfg.AssignedIPs)
	assertDaemonPeer(t, peers[0].PublicKey)

	clientEchoPort := freeIntegrationTCPPort(t)
	clientEchoTargetPort := freeIntegrationTCPPort(t)
	stopClientEcho := startHostEcho(t, fmt.Sprintf("127.0.0.1:%d", clientEchoTargetPort), "client")
	defer stopClientEcho()
	clientLocalForwardPort := freeIntegrationTCPPort(t)
	reversePort := 18092
	stopClient := startIntegrationClientDaemon(t, daemonBin, dataDir, mustIntegrationKeyFromPrivate(t, privateCfg.EncryptedPrivateKey), dbPeer, assignedIPv4, clientEchoPort, clientEchoTargetPort, clientLocalForwardPort, reversePort)
	defer stopClient()
	waitForDaemonPeerHandshake(t, peers[0].PublicKey)

	smokeForwardPort := freeIntegrationTCPPort(t)
	createRuntimeForward(t, TunnelForward{
		Name:   "smoke-proxy-forward",
		Proto:  "tcp",
		Listen: fmt.Sprintf("127.0.0.1:%d", smokeForwardPort),
		Target: fmt.Sprintf("%s:%d", assignedIPv4, clientEchoPort),
	})
	allowStaffToTarget(t, assignedIPv4.String(), clientEchoPort)
	allowStaffToTarget(t, "127.0.0.1", smokeForwardPort)
	waitForProxyCONNECTReady(t, ui.URL, fmt.Sprintf("127.0.0.1:%d", smokeForwardPort))
	assertProxyCONNECTStatus(t, ui.URL, fmt.Sprintf("127.0.0.1:%d", smokeForwardPort), http.StatusOK)
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
	repo := filepath.Join(os.Getenv("HOME"), "userspace-wireguard-socks")
	if st, err := os.Stat(filepath.Join(repo, "go.mod")); err != nil || st.IsDir() {
		t.Skipf("sibling userspace-wireguard-socks repo not found at %s", repo)
	}
	bin := filepath.Join(t.TempDir(), "uwgsocks")
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

func buildIntegrationUIHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/login", handleLogin)
	mux.HandleFunc("GET /api/peers", authMiddleware(handleGetPeers))
	mux.HandleFunc("POST /api/peers", authMiddleware(handleCreatePeer))
	mux.HandleFunc("GET /api/peers/{id}/private", authMiddleware(handleGetPeerPrivate))
	mux.HandleFunc("GET /api/distribute-peers", authMiddleware(handleGetDistributePeers))
	mux.HandleFunc("GET /api/config/public", authMiddleware(handleGetPublicConfig))
	registerAccessProxyRoutes(mux)
	registerFrontendRoutes(mux)
	return wrapRootHandler(mux)
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
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
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
	allowStaffToTarget(t, ip, port)
}

func allowStaffToTarget(t *testing.T, ip string, port int) {
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
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	auth := base64.StdEncoding.EncodeToString([]byte("proxy-user:proxy-secret"))
	_, _ = fmt.Fprintf(conn, "CONNECT /proxy/%s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n", target, addr, auth)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != wantStatus {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("CONNECT status = %d, want %d, body=%q", resp.StatusCode, wantStatus, body)
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

func assertProxyCONNECTStatus(t *testing.T, uiURL, target string, wantStatus int) {
	t.Helper()
	addr := strings.TrimPrefix(uiURL, "http://")
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	auth := base64.StdEncoding.EncodeToString([]byte("proxy-user:proxy-secret"))
	_, _ = fmt.Fprintf(conn, "CONNECT /proxy/%s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n", target, addr, auth)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != wantStatus {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("CONNECT status = %d, want %d, body=%q", resp.StatusCode, wantStatus, body)
	}
}

func waitForProxyCONNECTReady(t *testing.T, uiURL, target string) {
	t.Helper()
	var lastErr error
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(250 * time.Millisecond) {
		addr := strings.TrimPrefix(uiURL, "http://")
		conn, err := net.DialTimeout("tcp", addr, 1500*time.Millisecond)
		if err != nil {
			lastErr = err
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(1500 * time.Millisecond))
		auth := base64.StdEncoding.EncodeToString([]byte("proxy-user:proxy-secret"))
		_, _ = fmt.Fprintf(conn, "CONNECT /proxy/%s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n", target, addr, auth)
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		_ = conn.Close()
		if err != nil {
			lastErr = err
			continue
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return
		}
		lastErr = fmt.Errorf("status %d", resp.StatusCode)
	}
	t.Fatalf("proxy CONNECT to %s did not become ready: %v", target, lastErr)
}

func getJSONAs(t *testing.T, client *http.Client, rawURL string, out interface{}) {
	t.Helper()
	resp, err := client.Get(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET %s status=%d body=%q", rawURL, resp.StatusCode, body)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatalf("decode %s: %v", rawURL, err)
	}
}

func mustIntegrationKeyFromPrivate(t *testing.T, raw string) wgtypes.Key {
	t.Helper()
	key, err := wgtypes.ParseKey(strings.TrimSpace(raw))
	if err != nil {
		t.Fatalf("parse private key: %v", err)
	}
	return key
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse url %q: %v", raw, err)
	}
	return u
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

func waitForDaemonPeerHandshake(t *testing.T, publicKey string) {
	t.Helper()
	var lastErr error
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		var status struct {
			Peers []struct {
				PublicKey    string `json:"public_key"`
				HasHandshake bool   `json:"has_handshake"`
			} `json:"peers"`
		}
		if code := daemonJSON(t, http.MethodGet, "/v1/status", nil, &status); code != http.StatusOK {
			lastErr = fmt.Errorf("status %d", code)
			continue
		}
		for _, peer := range status.Peers {
			if peer.PublicKey == publicKey && peer.HasHandshake {
				return
			}
		}
		lastErr = fmt.Errorf("peer %s has no handshake yet", publicKey)
	}
	t.Fatalf("daemon peer handshake not ready: %v", lastErr)
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
