package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBuildTURNCredentialProfilesUsesListenerEndpoints(t *testing.T) {
	setupTestDB(t)
	if err := gdb.Create(&TURNHostedListener{
		Name:             "turn-web",
		Type:             "https",
		Listen:           "0.0.0.0:443",
		ExternalEndpoint: "https://turn.example.com/turn",
		Enabled:          true,
	}).Error; err != nil {
		t.Fatal(err)
	}
	if err := gdb.Create(&TURNHostedListener{
		Name:             "turn-udp",
		Type:             "udp",
		Listen:           "0.0.0.0:3478",
		ExternalEndpoint: "turn.example.com:3478",
		Enabled:          true,
	}).Error; err != nil {
		t.Fatal(err)
	}

	profiles := buildTURNCredentialProfiles(TURNCredential{Username: "alice"}, "secret")
	if len(profiles) != 2 {
		t.Fatalf("profiles len=%d want 2: %+v", len(profiles), profiles)
	}
	if profiles[0].URL != "https://alice:secret@turn.example.com/turn" {
		t.Fatalf("unexpected https profile %q", profiles[0].URL)
	}
	if profiles[1].URL != "udp://alice:secret@turn.example.com:3478" {
		t.Fatalf("unexpected udp profile %q", profiles[1].URL)
	}
}

func TestCreateMyTURNCredentialSyncsTurnDaemonUsers(t *testing.T) {
	setupTestDB(t)
	setTestConfig(t, "turn_hosting_enabled", "true")
	setTestConfig(t, "turn_allow_user_credentials", "true")
	user, _ := createTestUser(t, "alice", false)

	var pushed []map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/v1/users" {
			t.Fatalf("unexpected turn daemon request: %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&pushed); err != nil {
			t.Fatalf("decode pushed users: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(pushed)
	}))
	defer server.Close()

	oldURL, oldToken := *turnAPIURL, *turnAPIToken
	*turnAPIURL, *turnAPIToken = server.URL, ""
	defer func() {
		*turnAPIURL, *turnAPIToken = oldURL, oldToken
	}()

	body := bytes.NewBufferString(`{"name":"TURN relay"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/me/turn-credentials", body)
	req.Header.Set("X-User-Id", fmt.Sprint(user.ID))
	w := httptest.NewRecorder()
	handleCreateMyTURNCredential(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	if len(pushed) != 1 {
		t.Fatalf("expected 1 pushed user, got %+v", pushed)
	}
	if got := pushed[0]["wireguard_mode"]; got != "required-in-username" {
		t.Fatalf("unexpected wireguard_mode %#v", got)
	}
	if got := pushed[0]["username"]; got == "" {
		t.Fatalf("expected pushed username, got %#v", got)
	}
	if got := pushed[0]["password"]; got == "" {
		t.Fatalf("expected pushed password, got %#v", got)
	}

	var cred TURNCredential
	if err := gdb.First(&cred, "user_id = ?", user.ID).Error; err != nil {
		t.Fatalf("credential not persisted: %v", err)
	}
	if cred.Port == 0 {
		t.Fatalf("expected allocated port, got %+v", cred)
	}
}

func TestHandleGetMyTURNCredentialsMarksConnected(t *testing.T) {
	setupTestDB(t)
	user, _ := createTestUser(t, "alice", false)
	if err := gdb.Create(&TURNHostedListener{
		Name:             "turn-web",
		Type:             "https",
		Listen:           "0.0.0.0:443",
		ExternalEndpoint: "https://turn.example.com/turn",
		Enabled:          true,
	}).Error; err != nil {
		t.Fatal(err)
	}
	cred := TURNCredential{
		UserID:            user.ID,
		Name:              "TURN relay",
		Username:          "turn-u1-demo",
		PasswordEncrypted: encryptAtRest("secret"),
		Port:              40100,
		Enabled:           true,
	}
	if err := gdb.Create(&cred).Error; err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/status" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(turnDaemonStatusSnapshot{
			Sessions: []turnDaemonSessionSnapshot{{Username: cred.Username}},
		})
	}))
	defer server.Close()

	oldURL, oldToken := *turnAPIURL, *turnAPIToken
	*turnAPIURL, *turnAPIToken = server.URL, ""
	defer func() {
		*turnAPIURL, *turnAPIToken = oldURL, oldToken
	}()

	req := httptest.NewRequest(http.MethodGet, "/api/me/turn-credentials", nil)
	req.Header.Set("X-User-Id", fmt.Sprint(user.ID))
	w := httptest.NewRecorder()
	handleGetMyTURNCredentials(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var creds []TURNCredential
	if err := json.Unmarshal(w.Body.Bytes(), &creds); err != nil {
		t.Fatalf("decode credentials: %v", err)
	}
	if len(creds) != 1 || !creds[0].Connected {
		t.Fatalf("expected connected credential, got %+v", creds)
	}
	if len(creds[0].Profiles) != 1 || creds[0].Profiles[0].URL != "https://turn-u1-demo:secret@turn.example.com/turn" {
		t.Fatalf("unexpected profiles %+v", creds[0].Profiles)
	}
}
