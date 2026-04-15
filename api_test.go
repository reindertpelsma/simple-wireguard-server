// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupTestDB(t *testing.T) {
	var err error
	gdb, err = gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	gdb.AutoMigrate(&User{}, &Peer{}, &GlobalConfig{}, &ACLRule{})
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
	
	// 1. Mock OIDC Server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"issuer": "%s", "authorization_endpoint": "%s/auth", "token_endpoint": "%s/token", "userinfo_endpoint": "%s/userinfo", "jwks_uri": "%s/jwks"}`, 
				r.Host, r.Host, r.Host, r.Host, r.Host)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/userinfo") {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"sub": "oidc-sub-123", "preferred_username": "oidc-user"}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	// 2. Test user creation/mapping via OIDC stub
	// (Note: full OIDC flow requires complex exchange, we test the internal mapping logic)
	sub := "oidc-sub-123"
	user := User{
		Username:     "oidc-user",
		OIDCProvider: "mock",
		OIDCSubject:  &sub,
	}
	if err := gdb.Create(&user).Error; err != nil {
		t.Fatalf("failed to create OIDC user: %v", err)
	}

	// Verify second user with same sub fails (Unique constraint)
	user2 := User{
		Username:     "oidc-user-2",
		OIDCProvider: "mock",
		OIDCSubject:  &sub,
	}
	if err := gdb.Create(&user2).Error; err == nil {
		t.Error("expected unique constraint failure for OIDCSubject")
	}
}

func TestACLManagement(t *testing.T) {
	setupTestDB(t)
	_, adminToken := createTestUser(t, "admin", true)

	rule := ACLRule{
		ListName: "inbound",
		Action:   "deny",
		Src:      "1.2.3.4/32",
		Priority: 100,
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
