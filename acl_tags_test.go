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
	if err := gdb.Create(&ACLRule{ListName: "outbound", Action: "allow", SrcTags: "staff", Dst: "100.64.10.10/32", Proto: "tcp", DPort: "443"}).Error; err != nil {
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

func TestACLTagInheritanceExpandsDaemonPayload(t *testing.T) {
	setupTestDB(t)
	user, _ := createTestUser(t, "alice", false)
	user.Tags = "admins"
	if err := gdb.Save(&user).Error; err != nil {
		t.Fatal(err)
	}
	if err := gdb.Create(&Peer{UserID: user.ID, Name: "phone", PublicKey: "pub", AssignedIPs: "100.64.0.2/32"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := gdb.Create(&PolicyTag{Name: "staff"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := gdb.Create(&PolicyTag{Name: "admins", ParentGroups: "staff", ExtraCIDRs: "100.64.88.0/24"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := gdb.Create(&ACLRule{ListName: "outbound", Action: "allow", SrcTags: "staff", Dst: "100.64.10.10/32", Proto: "tcp", DPort: "443"}).Error; err != nil {
		t.Fatal(err)
	}

	acl := getACLConfig()
	outbound := acl["outbound"].([]map[string]interface{})
	foundPeer := false
	foundChildExtra := false
	for _, rule := range outbound {
		if rule["destination"] != "100.64.10.10/32" {
			continue
		}
		switch rule["source"] {
		case "100.64.0.2/32":
			foundPeer = true
		case "100.64.88.0/24":
			foundChildExtra = true
		}
	}
	if !foundPeer || !foundChildExtra {
		raw, _ := json.Marshal(outbound)
		t.Fatalf("inherited tag ACL did not include peer and child extra CIDR: %s", raw)
	}
}

func TestPolicyTagInheritanceRejectsCycles(t *testing.T) {
	setupTestDB(t)
	if err := gdb.Create(&PolicyTag{Name: "staff"}).Error; err != nil {
		t.Fatal(err)
	}
	admins := PolicyTag{Name: "admins", ParentGroups: "staff"}
	if err := validatePolicyTagGraph(&admins); err != nil {
		t.Fatalf("expected acyclic graph to validate: %v", err)
	}
	if err := gdb.Create(&admins).Error; err != nil {
		t.Fatal(err)
	}

	var staff PolicyTag
	if err := gdb.First(&staff, "name = ?", "staff").Error; err != nil {
		t.Fatal(err)
	}
	staff.ParentGroups = "admins"
	if err := validatePolicyTagGraph(&staff); err == nil {
		t.Fatal("expected inherited tag cycle to be rejected")
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
	gdb.Create(&ACLRule{ListName: "outbound", Action: "allow", SrcTags: "staff", Dst: "service.internal", Proto: "tcp", DPort: "443"})

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

func TestAccessProxyACLUsesInheritedAuthenticatedUserTags(t *testing.T) {
	setupTestDB(t)
	setTestConfig(t, "http_proxy_access_enabled", "true")
	setTestConfig(t, "acl_outbound_default", "deny")
	if err := gdb.Create(&PolicyTag{Name: "staff"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := gdb.Create(&PolicyTag{Name: "admins", ParentGroups: "staff"}).Error; err != nil {
		t.Fatal(err)
	}
	user, _ := createTestUser(t, "alice", false)
	user.Tags = "admins"
	gdb.Save(&user)
	hash, _ := hashPassword("secret")
	gdb.Create(&AccessProxyCredential{UserID: user.ID, Username: "proxy-user", PasswordHash: hash, Name: "test", Enabled: true})
	gdb.Create(&ACLRule{ListName: "outbound", Action: "allow", SrcTags: "staff", Dst: "service.internal", Proto: "tcp", DPort: "443"})

	req := httptest.NewRequest(http.MethodConnect, "http://ui.example", nil)
	req.URL.Path = "/proxy/service.internal:443"
	req.Header.Set("Proxy-Authorization", "Basic cHJveHktdXNlcjpzZWNyZXQ=")
	w := httptest.NewRecorder()
	wrapRootHandler(http.NewServeMux()).ServeHTTP(w, req)
	if w.Code == http.StatusForbidden {
		t.Fatalf("expected inherited tag ACL to allow CONNECT before upstream dial, got forbidden")
	}
}

func TestAccessACLFirstMatchWildcardAndDefault(t *testing.T) {
	setupTestDB(t)
	setTestConfig(t, "acl_outbound_default", "deny")
	user, _ := createTestUser(t, "alice", false)
	identity := identityForUser(user)
	req := httptest.NewRequest(http.MethodGet, "http://ui.example", nil)

	if accessAllowedByACL(req, identity, "service.internal", 443, "tcp") {
		t.Fatal("expected default deny without matching rule")
	}

	gdb.Create(&ACLRule{ListName: "outbound", Action: "allow", Proto: "tcp", DPort: "443", SortOrder: 1})
	if !accessAllowedByACL(req, identity, "service.internal", 443, "tcp") {
		t.Fatal("expected wildcard source and destination allow rule to match")
	}

	// Deny rule with lower sort_order appears before the allow rule → should match first.
	gdb.Create(&ACLRule{ListName: "outbound", Action: "deny", Proto: "tcp", Dst: "service.internal", DPort: "443", SortOrder: 0})
	if accessAllowedByACL(req, identity, "service.internal", 443, "tcp") {
		t.Fatal("expected earlier deny rule to win before later allow")
	}
}
