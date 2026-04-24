package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestEncryptAtRestUsesExternalKeyAndMigratesLegacyCiphertexts(t *testing.T) {
	setupTestDB(t)

	legacyKey, ok := legacyAtRestEncryptionKey()
	if !ok {
		t.Fatal("legacy encryption key unavailable")
	}
	legacyCipher := encryptAtRestWithKey("legacy-secret", legacyKey[:])
	if strings.HasPrefix(legacyCipher, atRestCipherPrefix) {
		t.Fatal("legacy ciphertext unexpectedly used the new prefix")
	}
	if got := decryptAtRest(legacyCipher); got != "legacy-secret" {
		t.Fatalf("legacy ciphertext did not decrypt, got %q", got)
	}

	hash, _ := hashPassword("password")
	user := User{
		Username:     "legacy-user",
		PasswordHash: hash,
		TOTPSecret:   legacyCipher,
		TOTPEnabled:  true,
		MaxConfigs:   5,
	}
	if err := gdb.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	migrateAtRestCiphertexts()

	var stored User
	if err := gdb.First(&stored, user.ID).Error; err != nil {
		t.Fatalf("reload user: %v", err)
	}
	if !strings.HasPrefix(stored.TOTPSecret, atRestCipherPrefix) {
		t.Fatalf("expected migrated ciphertext prefix, got %q", stored.TOTPSecret)
	}
	if got := decryptAtRest(stored.TOTPSecret); got != "legacy-secret" {
		t.Fatalf("migrated ciphertext did not decrypt, got %q", got)
	}
	if current := encryptAtRest("fresh-secret"); !strings.HasPrefix(current, atRestCipherPrefix) {
		t.Fatalf("new ciphertext missing prefix: %q", current)
	}
}

func TestLoginRateLimitAfterRepeatedFailures(t *testing.T) {
	setupTestDB(t)

	hash, _ := hashPassword("password")
	user := User{Username: "rate-limit-user", PasswordHash: hash, MaxConfigs: 5}
	if err := gdb.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	body, _ := json.Marshal(map[string]string{"username": user.Username, "password": "wrong"})
	for i := 0; i < authRateLimitFreeFailures; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(body))
		req.RemoteAddr = "203.0.113.40:4321"
		w := httptest.NewRecorder()
		handleLogin(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d expected 401, got %d: %s", i+1, w.Code, w.Body.String())
		}
	}

	req := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(body))
	req.RemoteAddr = "203.0.113.40:4321"
	w := httptest.NewRecorder()
	handleLogin(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after repeated failures, got %d: %s", w.Code, w.Body.String())
	}
}

func TestTOTPEnableRateLimitAfterRepeatedFailures(t *testing.T) {
	setupTestDB(t)

	hash, _ := hashPassword("password")
	user := User{
		Username:     "totp-user",
		PasswordHash: hash,
		TOTPSecret:   encryptAtRest("JBSWY3DPEHPK3PXP"),
		MaxConfigs:   5,
	}
	if err := gdb.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	body, _ := json.Marshal(map[string]string{"code": "000000"})
	for i := 0; i < authRateLimitFreeFailures; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/me/2fa/enable", bytes.NewReader(body))
		req.RemoteAddr = "203.0.113.41:4321"
		req.Header.Set("X-User-Id", strings.TrimSpace(strconv.FormatUint(uint64(user.ID), 10)))
		w := httptest.NewRecorder()
		handleTOTPEnable(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d expected 401, got %d: %s", i+1, w.Code, w.Body.String())
		}
	}

	req := httptest.NewRequest(http.MethodPost, "/api/me/2fa/enable", bytes.NewReader(body))
	req.RemoteAddr = "203.0.113.41:4321"
	req.Header.Set("X-User-Id", strings.TrimSpace(strconv.FormatUint(uint64(user.ID), 10)))
	w := httptest.NewRecorder()
	handleTOTPEnable(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after repeated invalid TOTP enable attempts, got %d: %s", w.Code, w.Body.String())
	}
}

func TestOIDCDiscoveryBodyLimit(t *testing.T) {
	setupTestDB(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"authorization_endpoint":"`)
		io.WriteString(w, strings.Repeat("a", int(oidcResponseBodyLimit)+1024))
		io.WriteString(w, `","token_endpoint":"https://issuer/token","userinfo_endpoint":"https://issuer/userinfo"}`)
	}))
	defer server.Close()

	oldIssuer := *oidcIssuer
	*oidcIssuer = server.URL
	defer func() { *oidcIssuer = oldIssuer }()

	req := httptest.NewRequest(http.MethodGet, "/api/oidc/login", nil)
	if _, err := fetchOIDCDiscovery(req); err == nil {
		t.Fatal("expected oversized OIDC discovery response to fail")
	}
}

func TestOIDCUserinfoBodyLimit(t *testing.T) {
	setupTestDB(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"sub":"`)
		io.WriteString(w, strings.Repeat("a", int(oidcResponseBodyLimit)+1024))
		io.WriteString(w, `"}`)
	}))
	defer server.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/oidc/callback", nil)
	if _, err := fetchOIDCUserinfo(req, oidcDiscovery{UserinfoEndpoint: server.URL}, "token"); err == nil {
		t.Fatal("expected oversized OIDC userinfo response to fail")
	}
}
