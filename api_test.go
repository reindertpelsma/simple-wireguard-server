// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func setupTestDB(t *testing.T) {
	var err error
	bootstrapState = bootstrapInfo{}
	lastPushedACLHash = ""
	gdb, err = gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	gdb.AutoMigrate(&User{}, &Peer{}, &GlobalConfig{}, &ACLRule{}, &SharedConfigLink{}, &TransportConfig{}, &AccessProxyCredential{}, &ExposedService{}, &PolicyTag{}, &TunnelForward{}, &TURNHostedListener{}, &TURNCredential{})
	initGlobalSettings()
}

func createTestUser(t *testing.T, username string, isAdmin bool) (User, string) {
	hp, _ := hashPassword("password")
	user := User{
		Username:     username,
		PasswordHash: hp,
		IsAdmin:      isAdmin,
		MaxConfigs:   5,
		Token:        "token-" + username,
	}
	gdb.Create(&user)
	return user, user.Token
}

func setTestSessionTimes(t *testing.T, userID uint, tokenIssuedAt, sudoAuthAt time.Time) {
	t.Helper()
	if err := gdb.Model(&User{}).Where("id = ?", userID).Updates(map[string]interface{}{
		"token_issued_at": tokenIssuedAt,
		"sudo_auth_at":    sudoAuthAt,
	}).Error; err != nil {
		t.Fatalf("update session times: %v", err)
	}
}

func TestAdminGroupControlsAdminStatus(t *testing.T) {
	setupTestDB(t)
	actor, _ := createTestUser(t, "owner", true)
	body := bytes.NewBufferString(`{"username":"group-admin","password":"password","primary_group":"default","groups":"admin"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/admin/users", body)
	req.Header.Set("X-User-Id", fmt.Sprint(actor.ID))
	w := httptest.NewRecorder()
	handleCreateUser(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create user status = %d: %s", w.Code, w.Body.String())
	}

	var user User
	if err := gdb.First(&user, "username = ?", "group-admin").Error; err != nil {
		t.Fatal(err)
	}
	if !user.IsAdmin || !userIsAdmin(user) {
		t.Fatalf("admin group did not grant admin status: %+v", user)
	}

	req = httptest.NewRequest(http.MethodPatch, "/api/admin/users/1", bytes.NewBufferString(`{"groups":""}`))
	req.SetPathValue("id", fmt.Sprint(user.ID))
	req.Header.Set("X-User-Id", fmt.Sprint(actor.ID))
	w = httptest.NewRecorder()
	handleUpdateUser(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("update user status = %d: %s", w.Code, w.Body.String())
	}
	if err := gdb.First(&user, user.ID).Error; err != nil {
		t.Fatal(err)
	}
	if user.IsAdmin || hasAdminGroup(user.Tags) {
		t.Fatalf("removing admin group did not revoke admin status: is_admin=%v groups=%q", user.IsAdmin, user.Tags)
	}
}

func TestPrimaryGroupSubnetAllocationAndPeerGroupInheritance(t *testing.T) {
	setupTestDB(t)
	group := Group{Name: "engineering", Subnet: "100.100.4.0/22", SubnetIPv6: "fd00:0:0:1::/64"}
	if err := gdb.Create(&group).Error; err != nil {
		t.Fatal(err)
	}
	user, token := createTestUser(t, "alice", false)
	user.PrimaryGroup = "engineering"
	user.Tags = "staff"
	if err := gdb.Save(&user).Error; err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/peers", bytes.NewBufferString(`{"name":"phone","public_key":"pub","groups":"laptop"}`))
	req.Header.Set("X-User-Id", fmt.Sprint(user.ID))
	req.Header.Set("X-Is-Admin", "false")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handleCreatePeer(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("create peer status = %d: %s", w.Code, w.Body.String())
	}

	var peer Peer
	if err := gdb.First(&peer, "name = ?", "phone").Error; err != nil {
		t.Fatal(err)
	}
	if peer.PrimaryGroup != "engineering" {
		t.Fatalf("peer primary group = %q, want engineering", peer.PrimaryGroup)
	}
	if !strings.Contains(peer.Tags, "staff") || !strings.Contains(peer.Tags, "laptop") {
		t.Fatalf("peer groups = %q, want inherited staff plus laptop", peer.Tags)
	}
	if !strings.HasPrefix(peer.AssignedIPs, "100.100.4.") {
		t.Fatalf("peer assigned IPs = %q, want engineering subnet", peer.AssignedIPs)
	}
}

func TestBuildClientConfigTextAddsControlDirectiveForPeerSyncPeer(t *testing.T) {
	setupTestDB(t)
	setTestConfig(t, "peer_sync_mode", "opt_in")
	setTestConfig(t, "peer_sync_port", "28765")
	setTestConfig(t, "client_dns", "100.64.0.1")
	peer := Peer{Name: "laptop", AssignedIPs: "100.64.0.2/32", PeerSyncEnabled: true}

	cfg := buildClientConfigText(peer, "priv", "psk", true)
	if !strings.Contains(cfg, "#!Control=http://100.64.0.1:28765") {
		t.Fatalf("client config missing control directive:\n%s", cfg)
	}

	peer.PeerSyncEnabled = false
	cfg = buildClientConfigText(peer, "priv", "psk", true)
	if strings.Contains(cfg, "#!Control=") {
		t.Fatalf("client config unexpectedly contained control directive for non-opt-in peer:\n%s", cfg)
	}
}

func TestBuildClientTransportProfilesIncludesPreferredAndSocket(t *testing.T) {
	setupTestDB(t)
	setTestConfig(t, "socket_proxy_enabled", "true")
	setTestConfig(t, "server_endpoint", "vpn.example.com:51820")
	setTestConfig(t, "default_transport", "web")
	if err := gdb.Create(&TransportConfig{
		Name:             "udp",
		Base:             "udp",
		Listen:           true,
		ListenPort:       51820,
		ExternalEndpoint: "vpn.example.com:51820",
	}).Error; err != nil {
		t.Fatal(err)
	}
	if err := gdb.Create(&TransportConfig{
		Name:             "web",
		Base:             "https",
		Listen:           true,
		ExternalEndpoint: "https://ui.example.com/socket",
	}).Error; err != nil {
		t.Fatal(err)
	}

	profiles := buildClientTransportProfiles("https://ui.example.com")
	if len(profiles) < 3 {
		t.Fatalf("profiles len=%d want at least 3: %+v", len(profiles), profiles)
	}
	if profiles[1].Name != "web" || !profiles[1].Preferred || profiles[1].DirectiveURL != "https://ui.example.com/socket" {
		t.Fatalf("unexpected preferred web profile: %+v", profiles[1])
	}
	last := profiles[len(profiles)-1]
	if last.Name != "ui-socket-http" || last.DirectiveURL != "https://ui.example.com/socket" {
		t.Fatalf("unexpected socket profile: %+v", last)
	}
}

func TestBuildClientTransportProfilesIncludesTURNHTTPSPath(t *testing.T) {
	setupTestDB(t)
	setTestConfig(t, "server_endpoint", "vpn.example.com:51820")
	if err := gdb.Create(&TransportConfig{
		Name:             "turn-web",
		Base:             "turn",
		TurnServer:       "turn.example.com:443",
		TurnUsername:     "alice",
		TurnPassword:     "secret",
		TurnProtocol:     "https",
		Listen:           false,
		ListenPort:       0,
		ExternalEndpoint: "",
	}).Error; err != nil {
		t.Fatal(err)
	}

	profiles := buildClientTransportProfiles("")
	if len(profiles) != 1 {
		t.Fatalf("profiles len=%d want 1: %+v", len(profiles), profiles)
	}
	if got := profiles[0].DirectiveTURN; got != "https://alice:secret@turn.example.com:443/turn" {
		t.Fatalf("unexpected TURN directive %q", got)
	}
}

func TestGetTransportsConfigIncludesWebSocketAdvertiseHTTP3(t *testing.T) {
	setupTestDB(t)
	if err := gdb.Create(&TransportConfig{
		Name:             "edge-web",
		Base:             "https",
		Listen:           true,
		ListenPort:       443,
		WSPath:           "/wg",
		ConnectHost:      "origin.internal:443",
		HostHeader:       "vpn.example.com",
		WSAdvertiseHTTP3: true,
	}).Error; err != nil {
		t.Fatal(err)
	}

	cfg := getTransportsConfig()
	if len(cfg) != 1 {
		t.Fatalf("expected created transport only, got %d", len(cfg))
	}

	var found map[string]interface{}
	for _, entry := range cfg {
		if entry["name"] == "edge-web" {
			found = entry
			break
		}
	}
	if found == nil {
		t.Fatal("edge-web transport not found in config")
	}
	ws, ok := found["websocket"].(map[string]interface{})
	if !ok {
		t.Fatalf("websocket block missing or wrong type: %#v", found["websocket"])
	}
	if got := ws["path"]; got != "/wg" {
		t.Fatalf("unexpected websocket path %#v", got)
	}
	if got := ws["connect_host"]; got != "origin.internal:443" {
		t.Fatalf("unexpected websocket connect_host %#v", got)
	}
	if got := ws["host_header"]; got != "vpn.example.com" {
		t.Fatalf("unexpected websocket host_header %#v", got)
	}
	if got := ws["advertise_http3"]; got != true {
		t.Fatalf("unexpected websocket advertise_http3 %#v", got)
	}
}

func TestTransportConfigToAPIPayloadIncludesWebSocketAdvertiseHTTP3(t *testing.T) {
	payload := transportConfigToAPIPayload(TransportConfig{
		Name:             "edge-web",
		Base:             "https",
		Listen:           true,
		WSPath:           "/wg",
		ConnectHost:      "origin.internal:443",
		HostHeader:       "vpn.example.com",
		WSAdvertiseHTTP3: true,
	})
	ws, ok := payload["websocket"].(map[string]interface{})
	if !ok {
		t.Fatalf("websocket block missing or wrong type: %#v", payload["websocket"])
	}
	if got := ws["path"]; got != "/wg" {
		t.Fatalf("unexpected websocket path %#v", got)
	}
	if got := ws["connect_host"]; got != "origin.internal:443" {
		t.Fatalf("unexpected websocket connect_host %#v", got)
	}
	if got := ws["host_header"]; got != "vpn.example.com" {
		t.Fatalf("unexpected websocket host_header %#v", got)
	}
	if got := ws["advertise_http3"]; got != true {
		t.Fatalf("unexpected websocket advertise_http3 %#v", got)
	}
}

func TestAdvanceBySubnetIPv4UsesPrefixBlockSize(t *testing.T) {
	start := netip.MustParseAddr("100.100.0.0")
	if got := advanceBySubnet(start, 22); got.String() != "100.100.4.0" {
		t.Fatalf("advance /22 = %s, want 100.100.4.0", got)
	}
}

func TestAPIPeerVisibility(t *testing.T) {
	setupTestDB(t)
	admin, adminToken := createTestUser(t, "admin", true)
	user1, user1Token := createTestUser(t, "user1", false)
	user2, _ := createTestUser(t, "user2", false)

	_ = admin
	_ = adminToken

	// Create a peer for user2
	p2 := Peer{
		UserID:      user2.ID,
		Name:        "User2 Phone",
		PublicKey:   "pubkey2",
		AssignedIPs: "10.0.0.2/32",
		Enabled:     true,
	}
	gdb.Create(&p2)

	// Test 1: Admin sees everything
	req := httptest.NewRequest("GET", "/api/peers", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("X-User-Id", fmt.Sprint(admin.ID))
	req.Header.Set("X-Is-Admin", "true")

	w := httptest.NewRecorder()
	handleGetPeers(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var peers []Peer
	json.Unmarshal(w.Body.Bytes(), &peers)
	found := false
	for _, p := range peers {
		if p.PublicKey == "pubkey2" {
			found = true
			break
		}
	}
	if !found {
		t.Error("admin should see pubkey2")
	}

	// Test 2: user1 sees user2's peer but filtered
	req = httptest.NewRequest("GET", "/api/peers", nil)
	req.Header.Set("Authorization", "Bearer "+user1Token)
	req.Header.Set("X-User-Id", fmt.Sprint(user1.ID))
	req.Header.Set("X-Is-Admin", "false")

	w = httptest.NewRecorder()
	handleGetPeers(w, req)

	json.Unmarshal(w.Body.Bytes(), &peers)
	for _, p := range peers {
		if p.Name == "User2 Phone" && p.PublicKey != "" {
			t.Error("user1 should NOT see user2's public key by default")
		}
	}
}

func TestAPIPeerIDOR(t *testing.T) {
	setupTestDB(t)
	user1, user1Token := createTestUser(t, "user1", false)
	user2, _ := createTestUser(t, "user2", false)

	// Create a peer for user2
	p2 := Peer{
		UserID: user2.ID,
		Name:   "User2 Phone",
	}
	gdb.Create(&p2)

	// User1 tries to update User2's peer
	update := map[string]interface{}{"name": "Hacked"}
	b, _ := json.Marshal(update)
	req := httptest.NewRequest("PATCH", "/api/peers/"+fmt.Sprint(p2.ID), bytes.NewBuffer(b))
	req.SetPathValue("id", fmt.Sprint(p2.ID))
	req.Header.Set("Authorization", "Bearer "+user1Token)
	req.Header.Set("X-User-Id", fmt.Sprint(user1.ID))
	req.Header.Set("X-Is-Admin", "false")

	w := httptest.NewRecorder()
	handleUpdatePeer(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("IDOR: expected 403, got %d", w.Code)
	}
}

func TestAPIPeerExpiration(t *testing.T) {
	setupTestDB(t)
	admin, _ := createTestUser(t, "admin", true)

	past := time.Now().Add(-1 * time.Hour)
	p := Peer{
		UserID:    admin.ID,
		Name:      "Expired",
		PublicKey: "expired-pub",
		Enabled:   true,
		ExpiresAt: &past,
	}
	gdb.Create(&p)

	// Manually run expiration logic
	var expired []Peer
	gdb.Where("enabled = ? AND expires_at IS NOT NULL AND expires_at < ?", true, time.Now()).Find(&expired)
	for _, ep := range expired {
		gdb.Model(&ep).Update("enabled", false)
	}

	gdb.First(&p, p.ID)
	if p.Enabled {
		t.Error("peer should be disabled after expiration")
	}
}

func TestOIDCLogin(t *testing.T) {
	setupTestDB(t)

	oldIssuer, oldClientID, oldClientSecret, oldRedirect := *oidcIssuer, *oidcClientID, *oidcClientSecret, *oidcRedirectURL
	defer func() {
		*oidcIssuer = oldIssuer
		*oidcClientID = oldClientID
		*oidcClientSecret = oldClientSecret
		*oidcRedirectURL = oldRedirect
	}()

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"issuer": %q, "authorization_endpoint": %q, "token_endpoint": %q, "userinfo_endpoint": %q}`,
				server.URL, server.URL+"/auth", server.URL+"/token", server.URL+"/userinfo")
			return
		}
		if strings.HasSuffix(r.URL.Path, "/token") {
			if err := r.ParseForm(); err != nil {
				t.Fatalf("parse token form: %v", err)
			}
			if r.Form.Get("client_id") != "ui-client" || r.Form.Get("client_secret") != "ui-secret" || r.Form.Get("code") != "code-123" {
				t.Fatalf("unexpected token form: %v", r.Form)
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"access-123","token_type":"Bearer"}`)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/userinfo") {
			if got := r.Header.Get("Authorization"); got != "Bearer access-123" {
				t.Fatalf("unexpected userinfo authorization header: %q", got)
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"sub": "oidc-sub-123", "preferred_username": "oidc-user"}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	*oidcIssuer = server.URL
	*oidcClientID = "ui-client"
	*oidcClientSecret = "ui-secret"
	*oidcRedirectURL = ""

	req := httptest.NewRequest("GET", "http://ui.example/api/oidc/login", nil)
	w := httptest.NewRecorder()
	handleOIDCLogin(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("expected OIDC login redirect, got %d: %s", w.Code, w.Body.String())
	}
	location, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect location: %v", err)
	}
	state := location.Query().Get("state")
	if location.Path != "/auth" || state == "" {
		t.Fatalf("unexpected OIDC redirect: %s", location.String())
	}

	req = httptest.NewRequest("GET", "http://ui.example/api/oidc/callback?code=code-123&state="+url.QueryEscape(state), nil)
	for _, cookie := range w.Result().Cookies() {
		req.AddCookie(cookie)
	}
	w = httptest.NewRecorder()
	handleOIDCCallback(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected callback success, got %d: %s", w.Code, w.Body.String())
	}

	var user User
	if err := gdb.First(&user, "username = ?", "oidc-user").Error; err != nil {
		t.Fatalf("expected OIDC user to be created: %v", err)
	}
	if user.Token == "" {
		t.Fatalf("expected OIDC callback to issue a session token")
	}
}

func TestACLManagement(t *testing.T) {
	setupTestDB(t)
	_, adminToken := createTestUser(t, "admin", true)

	rule := ACLRule{
		ListName: "inbound",
		Action:   "deny",
		Src:      "1.2.3.4/32",
	}
	b, _ := json.Marshal(rule)
	req := httptest.NewRequest("POST", "/api/admin/acls", bytes.NewBuffer(b))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("X-Is-Admin", "true")

	w := httptest.NewRecorder()
	handleCreateACL(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", w.Code)
	}
}

func TestHandleGetPeersIncludesTransportStatus(t *testing.T) {
	setupTestDB(t)
	user, token := createTestUser(t, "user1", false)
	peer := Peer{
		UserID:      user.ID,
		Name:        "Phone",
		PublicKey:   "peer-pub",
		AssignedIPs: "100.64.0.2/32",
		Enabled:     true,
	}
	if err := gdb.Create(&peer).Error; err != nil {
		t.Fatalf("create peer: %v", err)
	}

	oldURL, oldToken := *uwgsocksURL, *uwgsocksToken
	defer func() {
		*uwgsocksURL = oldURL
		*uwgsocksToken = oldToken
	}()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/status" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
			"peers": [{
				"public_key": "peer-pub",
				"endpoint_ip": "198.51.100.10",
				"has_handshake": true,
				"transport_name": "turn-edge",
				"transport_state": "ConnEstablished",
				"transport_endpoint": "turn-edge@198.51.100.10:51820",
				"transport_source_addr": "10.0.0.2:49152",
				"transport_carrier_remote_addr": "161.35.159.61:3478"
			}]
		}`)
	}))
	defer server.Close()
	*uwgsocksURL = server.URL

	req := httptest.NewRequest("GET", "/api/peers", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-User-Id", fmt.Sprint(user.ID))
	req.Header.Set("X-Is-Admin", "false")
	w := httptest.NewRecorder()
	handleGetPeers(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var peers []Peer
	if err := json.Unmarshal(w.Body.Bytes(), &peers); err != nil {
		t.Fatalf("decode peers: %v", err)
	}
	if len(peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(peers))
	}
	if peers[0].TransportName != "turn-edge" {
		t.Fatalf("expected transport name turn-edge, got %q", peers[0].TransportName)
	}
	if peers[0].TransportState != "ConnEstablished" {
		t.Fatalf("expected transport state ConnEstablished, got %q", peers[0].TransportState)
	}
	if peers[0].TransportEndpoint != "turn-edge@198.51.100.10:51820" {
		t.Fatalf("unexpected transport endpoint: %q", peers[0].TransportEndpoint)
	}
	if peers[0].TransportSourceAddr != "10.0.0.2:49152" {
		t.Fatalf("unexpected transport source addr: %q", peers[0].TransportSourceAddr)
	}
	if peers[0].TransportCarrierAddr != "161.35.159.61:3478" {
		t.Fatalf("unexpected transport carrier addr: %q", peers[0].TransportCarrierAddr)
	}
}

func TestHandleGetTransportsIncludesRuntimeStatus(t *testing.T) {
	setupTestDB(t)
	if err := gdb.Create(&TransportConfig{
		Name:       "turn-edge",
		Base:       "turn",
		TurnServer: "turn.example.com:3478",
	}).Error; err != nil {
		t.Fatalf("create transport: %v", err)
	}

	oldURL, oldToken := *uwgsocksURL, *uwgsocksToken
	defer func() {
		*uwgsocksURL = oldURL
		*uwgsocksToken = oldToken
	}()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/status" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
			"transports": [{
				"name": "turn-edge",
				"connected": true,
				"carrier_protocol": "tls",
				"carrier_local_addr": "10.0.0.2:50000",
				"carrier_remote_addr": "161.35.159.61:443",
				"relay_addr": "161.35.159.61:55000",
				"active_sessions": 3
			}]
		}`)
	}))
	defer server.Close()
	*uwgsocksURL = server.URL

	req := httptest.NewRequest("GET", "/api/admin/transports", nil)
	w := httptest.NewRecorder()
	handleGetTransports(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var transports []TransportConfig
	if err := json.Unmarshal(w.Body.Bytes(), &transports); err != nil {
		t.Fatalf("decode transports: %v", err)
	}
	if len(transports) != 1 {
		t.Fatalf("expected 1 transport, got %d", len(transports))
	}
	if !transports[0].Connected {
		t.Fatalf("expected transport to be marked connected")
	}
	if transports[0].CarrierProtocol != "tls" {
		t.Fatalf("unexpected carrier protocol: %q", transports[0].CarrierProtocol)
	}
	if transports[0].RelayAddr != "161.35.159.61:55000" {
		t.Fatalf("unexpected relay addr: %q", transports[0].RelayAddr)
	}
	if transports[0].ActiveSessions != 3 {
		t.Fatalf("unexpected active sessions: %d", transports[0].ActiveSessions)
	}
}

func TestResolvedServerEndpointUsesTurnRelayAddr(t *testing.T) {
	setupTestDB(t)
	if err := gdb.Create(&TransportConfig{
		Name:       "turn-edge",
		Base:       "turn",
		TurnServer: "turn.example.com:3478",
	}).Error; err != nil {
		t.Fatalf("create transport: %v", err)
	}
	gdb.Model(&GlobalConfig{}).Where("key = ?", "server_endpoint").Update("value", "")
	gdb.Model(&GlobalConfig{}).Where("key = ?", "default_transport").Update("value", "turn-edge")

	oldURL, oldToken := *uwgsocksURL, *uwgsocksToken
	defer func() {
		*uwgsocksURL = oldURL
		*uwgsocksToken = oldToken
	}()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/status" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
			"transports": [{
				"name": "turn-edge",
				"relay_addr": "161.35.159.61:55000"
			}]
		}`)
	}))
	defer server.Close()
	*uwgsocksURL = server.URL

	if got := resolvedServerEndpoint(); got != "161.35.159.61:55000" {
		t.Fatalf("expected relay addr, got %q", got)
	}
}

func TestLoginWithTOTP(t *testing.T) {
	setupTestDB(t)
	hash, _ := hashPassword("password")
	secret := "JBSWY3DPEHPK3PXP"
	user := User{
		Username:     "totp-user",
		PasswordHash: hash,
		TOTPSecret:   encryptAtRest(secret),
		TOTPEnabled:  true,
		MaxConfigs:   5,
	}
	if err := gdb.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	body, _ := json.Marshal(map[string]string{"username": "totp-user", "password": "password"})
	req := httptest.NewRequest("POST", "/api/login", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handleLogin(w, req)
	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for missing 2FA, got %d: %s", w.Code, w.Body.String())
	}

	code, err := totpCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	body, _ = json.Marshal(map[string]string{"username": "totp-user", "password": "password", "totp_code": code})
	req = httptest.NewRequest("POST", "/api/login", bytes.NewReader(body))
	w = httptest.NewRecorder()
	handleLogin(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 after valid 2FA, got %d: %s", w.Code, w.Body.String())
	}
	if len(w.Result().Cookies()) == 0 {
		t.Fatalf("expected login to set a session cookie")
	}
}

func TestYAMLOverrideIsStoredAndWritten(t *testing.T) {
	setupTestDB(t)
	oldDataDir := *dataDir
	*dataDir = t.TempDir()
	defer func() { *dataDir = oldDataDir }()

	custom := "api:\n  listen: unix:///tmp/custom.sock\nwireguard:\n  addresses:\n    - 100.64.77.1/24\n"
	body, _ := json.Marshal(map[string]interface{}{
		"enabled": true,
		"custom":  custom,
	})
	req := httptest.NewRequest("POST", "/api/admin/yaml", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handleSaveYAMLConfig(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204 saving YAML, got %d: %s", w.Code, w.Body.String())
	}
	if getConfig("custom_yaml_enabled") != "true" || getConfig("custom_yaml") != custom {
		t.Fatalf("custom YAML settings were not persisted")
	}
	data, err := os.ReadFile(resolvePath("uwg_canonical.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != custom {
		t.Fatalf("expected custom YAML file, got:\n%s", string(data))
	}

	req = httptest.NewRequest("GET", "/api/admin/yaml", nil)
	w = httptest.NewRecorder()
	handleGetYAMLConfig(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 fetching YAML, got %d", w.Code)
	}
	var response yamlConfigResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !response.Enabled || response.Custom != custom || response.Effective != custom {
		t.Fatalf("unexpected YAML response: %+v", response)
	}
}

func TestPeerTrafficShaperUpdatePushesDaemonAPI(t *testing.T) {
	setupTestDB(t)
	admin, _ := createTestUser(t, "shaper-admin", true)

	var pushed map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/peers" {
			t.Fatalf("unexpected daemon request: %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&pushed); err != nil {
			t.Fatalf("decode daemon payload: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	oldURL := *uwgsocksURL
	*uwgsocksURL = server.URL
	defer func() { *uwgsocksURL = oldURL }()

	peer := Peer{
		UserID:       admin.ID,
		Name:         "limited",
		PublicKey:    "limited-pub",
		AssignedIPs:  "100.64.0.44/32",
		PresharedKey: encryptAtRest("psk"),
		Enabled:      true,
	}
	if err := gdb.Create(&peer).Error; err != nil {
		t.Fatalf("create peer: %v", err)
	}

	body, _ := json.Marshal(map[string]interface{}{
		"traffic_shaper": map[string]interface{}{
			"upload_bps":   1200000,
			"download_bps": 3400000,
			"latency_ms":   25,
		},
	})
	req := httptest.NewRequest("PATCH", "/api/peers/"+fmt.Sprint(peer.ID), bytes.NewReader(body))
	req.SetPathValue("id", fmt.Sprint(peer.ID))
	req.Header.Set("X-User-Id", fmt.Sprint(admin.ID))
	req.Header.Set("X-Is-Admin", "true")
	w := httptest.NewRecorder()
	handleUpdatePeer(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 updating shaper, got %d: %s", w.Code, w.Body.String())
	}

	var saved Peer
	gdb.First(&saved, peer.ID)
	if saved.TrafficUploadBps != 1200000 || saved.TrafficDownloadBps != 3400000 || saved.TrafficLatencyMs != 25 {
		t.Fatalf("shaper was not saved: %+v", saved)
	}
	shaper, ok := pushed["traffic_shaper"].(map[string]interface{})
	if !ok {
		t.Fatalf("daemon payload missing traffic_shaper: %+v", pushed)
	}
	if shaper["upload_bps"].(float64) != 1200000 || shaper["download_bps"].(float64) != 3400000 || shaper["latency_ms"].(float64) != 25 {
		t.Fatalf("unexpected daemon shaper payload: %+v", shaper)
	}
}

func TestForwardCRUDUsesDaemonRuntimeAPI(t *testing.T) {
	setupTestDB(t)

	type daemonCall struct {
		Method string
		Path   string
		Query  string
		Body   map[string]interface{}
	}
	var calls []daemonCall
	postCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := daemonCall{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery}
		if r.Body != nil {
			body, _ := io.ReadAll(r.Body)
			if len(bytes.TrimSpace(body)) > 0 {
				if err := json.Unmarshal(body, &call.Body); err != nil {
					t.Fatalf("decode daemon request body: %v", err)
				}
			}
		}
		calls = append(calls, call)
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/forwards":
			postCount++
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintf(w, `{"name":"forward.dynamic.%d","reverse":%v,"proto":%q,"listen":%q,"target":%q}`,
				postCount, call.Body["reverse"], call.Body["proto"], call.Body["listen"], call.Body["target"])
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/forwards":
			if r.URL.Query().Get("name") == "" {
				t.Fatalf("delete forward missing name")
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected daemon request: %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
		}
	}))
	defer server.Close()

	oldURL, oldToken := *uwgsocksURL, *uwgsocksToken
	defer func() {
		*uwgsocksURL = oldURL
		*uwgsocksToken = oldToken
	}()
	*uwgsocksURL = server.URL
	*uwgsocksToken = ""

	createBody := bytes.NewBufferString(`{"name":"web","reverse":false,"proto":"tcp","listen":"127.0.0.1:18080","target":"100.64.0.2:80","proxy_protocol":"v1"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/admin/forwards", createBody)
	w := httptest.NewRecorder()
	handleCreateForward(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create forward status = %d: %s", w.Code, w.Body.String())
	}
	var saved TunnelForward
	if err := gdb.First(&saved, "name = ?", "web").Error; err != nil {
		t.Fatal(err)
	}
	if saved.RuntimeName != "forward.dynamic.1" {
		t.Fatalf("runtime name after create = %q", saved.RuntimeName)
	}
	if len(calls) != 1 || calls[0].Method != http.MethodPost || calls[0].Body["listen"] != "127.0.0.1:18080" || calls[0].Body["proxy_protocol"] != "v1" {
		t.Fatalf("unexpected create calls: %+v", calls)
	}

	updateBody := bytes.NewBufferString(`{"name":"web","reverse":true,"proto":"tcp","listen":"100.64.0.1:18081","target":"127.0.0.1:8081"}`)
	req = httptest.NewRequest(http.MethodPatch, "/api/admin/forwards/"+fmt.Sprint(saved.ID), updateBody)
	req.SetPathValue("id", fmt.Sprint(saved.ID))
	w = httptest.NewRecorder()
	handleUpdateForward(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("update forward status = %d: %s", w.Code, w.Body.String())
	}
	if err := gdb.First(&saved, saved.ID).Error; err != nil {
		t.Fatal(err)
	}
	if saved.RuntimeName != "forward.dynamic.2" {
		t.Fatalf("runtime name after update = %q", saved.RuntimeName)
	}
	if len(calls) != 3 || calls[1].Method != http.MethodDelete || calls[1].Query != "name=forward.dynamic.1" || calls[2].Method != http.MethodPost {
		t.Fatalf("unexpected update calls: %+v", calls)
	}
	if calls[2].Body["reverse"] != true || calls[2].Body["listen"] != "100.64.0.1:18081" || calls[2].Body["target"] != "127.0.0.1:8081" {
		t.Fatalf("unexpected update payload: %+v", calls[2].Body)
	}

	req = httptest.NewRequest(http.MethodDelete, "/api/admin/forwards/"+fmt.Sprint(saved.ID), nil)
	req.SetPathValue("id", fmt.Sprint(saved.ID))
	w = httptest.NewRecorder()
	handleDeleteForward(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("delete forward status = %d: %s", w.Code, w.Body.String())
	}
	if len(calls) != 4 || calls[3].Method != http.MethodDelete || calls[3].Query != "name=forward.dynamic.2" {
		t.Fatalf("unexpected delete calls: %+v", calls)
	}
}

func TestFrontendDistIsCookieGated(t *testing.T) {
	setupTestDB(t)
	_, token := createTestUser(t, "frontend-user", false)

	mux := http.NewServeMux()
	registerFrontendRoutes(mux)

	req := httptest.NewRequest("GET", "/app", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/login" {
		t.Fatalf("expected anonymous /app redirect to /login, got %d location=%q", w.Code, w.Header().Get("Location"))
	}

	req = httptest.NewRequest("GET", "/login", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Only the lock is public") {
		t.Fatalf("expected lightweight login page, got %d", w.Code)
	}

	req = httptest.NewRequest("GET", "/app", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected authenticated /app to serve frontend, got %d: %s", w.Code, w.Body.String())
	}

	asset := firstDistJSAsset(t)
	req = httptest.NewRequest("GET", "http://ui.example/"+asset, nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/login" {
		t.Fatalf("expected anonymous dashboard asset redirect, got %d location=%q", w.Code, w.Header().Get("Location"))
	}

	req = httptest.NewRequest("GET", "http://ui.example/"+asset, nil)
	req.Header.Set("Referer", "http://ui.example/config/share-token")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected shared config asset to load with config referer, got %d", w.Code)
	}
}

func firstDistJSAsset(t *testing.T) string {
	t.Helper()
	dist, err := frontendDist()
	if err != nil {
		t.Fatal(err)
	}
	var found string
	err = fs.WalkDir(dist, "assets", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.IsDir() && strings.HasSuffix(name, ".js") {
			found = name
			return fs.SkipAll
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found == "" {
		t.Fatal("no frontend JS asset found in dist")
	}
	return found
}

func TestGetPeerPrivateAllowsServerManagedKeysWithoutNonce(t *testing.T) {
	setupTestDB(t)
	admin, adminToken := createTestUser(t, "admin", true)

	peer := Peer{
		UserID:       admin.ID,
		Name:         "Server Managed",
		PublicKey:    "server-managed-pub",
		AssignedIPs:  "100.64.0.2/32",
		PrivateKey:   encryptAtRest("plain-private-key"),
		PresharedKey: encryptAtRest("plain-psk"),
		IsE2E:        false,
	}
	if err := gdb.Create(&peer).Error; err != nil {
		t.Fatalf("failed to create peer: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/peers/"+fmt.Sprint(peer.ID)+"/private", nil)
	req.SetPathValue("id", fmt.Sprint(peer.ID))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("X-User-Id", fmt.Sprint(admin.ID))
	req.Header.Set("X-Is-Admin", "true")

	w := httptest.NewRecorder()
	handleGetPeerPrivate(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var response Peer
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if response.EncryptedPrivateKey != "plain-private-key" {
		t.Fatalf("expected plain private key, got %q", response.EncryptedPrivateKey)
	}
	if response.PresharedKey != "plain-psk" {
		t.Fatalf("expected plain PSK, got %q", response.PresharedKey)
	}
}

func TestPublicConfigFiltering(t *testing.T) {
	setupTestDB(t)

	req := httptest.NewRequest("GET", "/api/config/public", nil)
	w := httptest.NewRecorder()
	handleGetPublicConfig(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var response map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if _, ok := response["server_privkey"]; ok {
		t.Fatalf("server private key must not be exposed in the public config")
	}
	if response["server_pubkey"] == "" {
		t.Fatalf("expected server_pubkey in public config")
	}
}

func TestSharedConfigLinkOneUseFlow(t *testing.T) {
	setupTestDB(t)
	admin, _ := createTestUser(t, "admin", true)

	peer := Peer{
		UserID:              admin.ID,
		Name:                "Shared Laptop",
		PublicKey:           "shared-pub",
		AssignedIPs:         "100.64.0.5/32",
		EncryptedPrivateKey: encryptAtRest("v2:encrypted-client-key"),
		PresharedKey:        encryptAtRest("shared-psk"),
		NonceHash:           "nonce-hash",
		IsE2E:               true,
	}
	if err := gdb.Create(&peer).Error; err != nil {
		t.Fatalf("failed to create peer: %v", err)
	}

	token := "share-token-123"
	link := SharedConfigLink{
		PeerID:          peer.ID,
		CreatedByUserID: admin.ID,
		TokenHash:       shareTokenHash(token),
		EncryptedToken:  encryptAtRest(token),
		OneUse:          true,
	}
	if err := gdb.Create(&link).Error; err != nil {
		t.Fatalf("failed to create share link: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/share/"+token, nil)
	req.SetPathValue("token", token)
	req.Header.Set("X-Nonce-Hash", "nonce-hash")
	w := httptest.NewRecorder()
	handleGetSharedConfig(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if response["encrypted_private_key"] != "v2:encrypted-client-key" {
		t.Fatalf("expected shared encrypted key, got %v", response["encrypted_private_key"])
	}

	req = httptest.NewRequest("GET", "/api/share/"+token, nil)
	req.SetPathValue("token", token)
	req.Header.Set("X-Nonce-Hash", "nonce-hash")
	w = httptest.NewRecorder()
	handleGetSharedConfig(w, req)

	if w.Code != http.StatusGone {
		t.Fatalf("expected 410 after one-use link is consumed, got %d", w.Code)
	}
}

func TestTrafficTrackerHistory(t *testing.T) {
	tracker := newTrafficTracker(10 * time.Minute)
	now := time.Now()

	tracker.Record([]Peer{{
		PublicKey:     "pub-1",
		ReceiveBytes:  100,
		TransmitBytes: 50,
	}}, now)
	tracker.Record([]Peer{{
		PublicKey:     "pub-1",
		ReceiveBytes:  260,
		TransmitBytes: 90,
	}}, now.Add(30*time.Second))

	history := tracker.History("pub-1")
	if len(history) != 2 {
		t.Fatalf("expected 2 traffic samples, got %d", len(history))
	}
	if history[1].ReceiveDelta != 160 {
		t.Fatalf("expected receive delta 160, got %d", history[1].ReceiveDelta)
	}
	if history[1].TransmitDelta != 40 {
		t.Fatalf("expected transmit delta 40, got %d", history[1].TransmitDelta)
	}
}

func TestReadOnlyModeStillAllowsServicesAndPing(t *testing.T) {
	setupTestDB(t)
	admin, token := createTestUser(t, "admin", true)
	now := time.Now()
	setTestSessionTimes(t, admin.ID, now, now.Add(-2*defaultSudoTimeout))

	if err := gdb.Create(&ExposedService{
		Name:      "Wiki",
		Host:      "wiki.example.com",
		TargetURL: "http://100.64.0.50:80",
		AuthMode:  "login",
	}).Error; err != nil {
		t.Fatal(err)
	}
	peer := Peer{
		UserID:       admin.ID,
		Name:         "Phone",
		PublicKey:    "phone-pub",
		AssignedIPs:  "100.64.0.10/32",
		PrivateKey:   encryptAtRest("server-managed-private"),
		PresharedKey: encryptAtRest("server-managed-psk"),
	}
	if err := gdb.Create(&peer).Error; err != nil {
		t.Fatal(err)
	}

	oldURL := *uwgsocksURL
	defer func() { *uwgsocksURL = oldURL }()
	pingServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/ping" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"transmitted":3,"received":3,"round_trip_ms":[12.5]}`)
	}))
	defer pingServer.Close()
	*uwgsocksURL = pingServer.URL

	mux := http.NewServeMux()
	registerAccessProxyRoutes(mux)
	mux.HandleFunc("POST /api/peers/{id}/ping", authMiddleware(handlePingPeer))
	mux.HandleFunc("GET /api/peers/{id}/private", authMiddleware(sudoMiddleware(handleGetPeerPrivate)))

	req := httptest.NewRequest(http.MethodGet, "/api/services", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("services should stay available in read-only mode, got %d: %s", w.Code, w.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/peers/"+fmt.Sprint(peer.ID)+"/ping", nil)
	req.SetPathValue("id", fmt.Sprint(peer.ID))
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("ping should stay available in read-only mode, got %d: %s", w.Code, w.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/peers/"+fmt.Sprint(peer.ID)+"/private", nil)
	req.SetPathValue("id", fmt.Sprint(peer.ID))
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusPreconditionRequired {
		t.Fatalf("sensitive config access should still require sudo, got %d: %s", w.Code, w.Body.String())
	}
}
