package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestACLTagExpansionForDaemonPayload(t *testing.T) {
	setupTestDB(t)
	user, _ := createTestUser(t, "alice", false)
	user.Tags = "staff"
	if err := gdb.Save(&user).Error; err != nil {
		t.Fatal(err)
	}
	if err := gdb.Create(&Peer{UserID: user.ID, Name: "phone", PublicKey: "pub", AssignedIPs: "100.64.0.2/32, fd00:64::2/128", Tags: "laptop"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := gdb.Create(&PolicyTag{Name: "staff", ExtraCIDRs: "100.64.99.0/24"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := gdb.Create(&ACLRule{ListName: "outbound", Action: "allow", SrcTags: "staff", Dst: "100.64.10.10/32", Proto: "tcp", DPort: "443", Priority: 50}).Error; err != nil {
		t.Fatal(err)
	}

	acl := getACLConfig()
	outbound := acl["outbound"].([]map[string]interface{})
	foundPeer := false
	foundExtra := false
	for _, rule := range outbound {
		if rule["destination"] != "100.64.10.10/32" {
			continue
		}
		switch rule["source"] {
		case "100.64.0.2/32":
			foundPeer = true
		case "100.64.99.0/24":
			foundExtra = true
		}
	}
	if !foundPeer || !foundExtra {
		raw, _ := json.Marshal(outbound)
		t.Fatalf("expanded ACL did not include peer and extra CIDR: %s", raw)
	}
}

func TestAccessProxyACLUsesAuthenticatedUserTags(t *testing.T) {
	setupTestDB(t)
	setTestConfig(t, "http_proxy_access_enabled", "true")
	setTestConfig(t, "acl_outbound_default", "deny")
	user, _ := createTestUser(t, "alice", false)
	user.Tags = "staff"
	gdb.Save(&user)
	hash, _ := hashPassword("secret")
	gdb.Create(&AccessProxyCredential{UserID: user.ID, Username: "proxy-user", PasswordHash: hash, Name: "test", Enabled: true})
	gdb.Create(&ACLRule{ListName: "outbound", Action: "allow", SrcTags: "staff", Dst: "service.internal", Proto: "tcp", DPort: "443", Priority: 100})

	req := httptest.NewRequest(http.MethodConnect, "http://ui.example", nil)
	req.URL.Path = "/proxy/service.internal:443"
	req.Header.Set("Proxy-Authorization", "Basic cHJveHktdXNlcjpzZWNyZXQ=")
	w := httptest.NewRecorder()
	wrapRootHandler(http.NewServeMux()).ServeHTTP(w, req)
	if w.Code == http.StatusForbidden {
		t.Fatalf("expected tag ACL to allow CONNECT before upstream dial, got forbidden")
	}

	req = httptest.NewRequest(http.MethodConnect, "http://ui.example", nil)
	req.URL.Path = "/proxy/blocked.internal:443"
	req.Header.Set("Proxy-Authorization", "Basic cHJveHktdXNlcjpzZWNyZXQ=")
	w = httptest.NewRecorder()
	wrapRootHandler(http.NewServeMux()).ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected missing tag ACL to deny CONNECT, got %d", w.Code)
	}
}
