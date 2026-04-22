package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type TURNHostedListener struct {
	ID               uint      `gorm:"primaryKey" json:"id"`
	Name             string    `gorm:"uniqueIndex;not null" json:"name"`
	Type             string    `gorm:"not null" json:"type"`
	Listen           string    `gorm:"not null" json:"listen"`
	ExternalEndpoint string    `json:"external_endpoint,omitempty"`
	Path             string    `json:"path,omitempty"`
	AdvertiseHTTP3   bool      `json:"advertise_http3,omitempty"`
	CertFile         string    `json:"cert_file,omitempty"`
	KeyFile          string    `json:"key_file,omitempty"`
	CAFile           string    `json:"ca_file,omitempty"`
	VerifyPeer       bool      `json:"verify_peer,omitempty"`
	Enabled          bool      `gorm:"default:true" json:"enabled"`
	SortOrder        int       `gorm:"default:0" json:"sort_order"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
	BoundAddr        string    `gorm:"-" json:"bound_addr,omitempty"`
}

type TURNCredential struct {
	ID                 uint                `gorm:"primaryKey" json:"id"`
	UserID             uint                `gorm:"index;not null" json:"user_id"`
	User               User                `gorm:"foreignKey:UserID" json:"-"`
	OwnerUsername      string              `gorm:"-" json:"owner_username,omitempty"`
	Name               string              `json:"name"`
	Username           string              `gorm:"uniqueIndex;not null" json:"username"`
	PasswordEncrypted  string              `json:"-"`
	Port               int                 `gorm:"uniqueIndex;not null" json:"port"`
	WireGuardPublicKey string              `json:"wireguard_public_key,omitempty"`
	Enabled            bool                `gorm:"default:true" json:"enabled"`
	CreatedAt          time.Time           `json:"created_at"`
	UpdatedAt          time.Time           `json:"updated_at"`
	Connected          bool                `gorm:"-" json:"connected,omitempty"`
	Profiles           []TURNClientProfile `gorm:"-" json:"profiles,omitempty"`
}

type TURNClientProfile struct {
	Label string `json:"label"`
	Type  string `json:"type"`
	URL   string `json:"url"`
}

func registerTURNRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/turn/listeners", authMiddleware(handleListTURNListeners))
	mux.HandleFunc("GET /api/admin/turn/listeners", authMiddleware(adminMiddleware(handleListTURNListeners)))
	mux.HandleFunc("POST /api/admin/turn/listeners", authMiddleware(sudoMiddleware(adminMiddleware(handleCreateTURNListener))))
	mux.HandleFunc("PATCH /api/admin/turn/listeners/{id}", authMiddleware(sudoMiddleware(adminMiddleware(handleUpdateTURNListener))))
	mux.HandleFunc("DELETE /api/admin/turn/listeners/{id}", authMiddleware(sudoMiddleware(adminMiddleware(handleDeleteTURNListener))))
	mux.HandleFunc("GET /api/admin/turn/credentials", authMiddleware(adminMiddleware(handleListAllTURNCredentials)))
	mux.HandleFunc("GET /api/admin/turn/status", authMiddleware(adminMiddleware(handleGetTURNStatus)))

	mux.HandleFunc("GET /api/me/turn-credentials", authMiddleware(handleGetMyTURNCredentials))
	mux.HandleFunc("POST /api/me/turn-credentials", authMiddleware(sudoMiddleware(handleCreateMyTURNCredential)))
	mux.HandleFunc("DELETE /api/me/turn-credentials/{id}", authMiddleware(sudoMiddleware(handleDeleteMyTURNCredential)))
}

func listEnabledTURNListeners() []TURNHostedListener {
	var listeners []TURNHostedListener
	gdb.Where("enabled = ?", true).Order("sort_order asc, id asc").Find(&listeners)
	return listeners
}

func normalizeTURNHostedListener(listener *TURNHostedListener) {
	listener.Name = strings.TrimSpace(listener.Name)
	listener.Type = strings.ToLower(strings.TrimSpace(listener.Type))
	listener.Listen = strings.TrimSpace(listener.Listen)
	listener.ExternalEndpoint = strings.TrimSpace(listener.ExternalEndpoint)
	listener.Path = strings.TrimSpace(listener.Path)
	listener.CertFile = strings.TrimSpace(listener.CertFile)
	listener.KeyFile = strings.TrimSpace(listener.KeyFile)
	listener.CAFile = strings.TrimSpace(listener.CAFile)
	if listener.Path == "" && slices.Contains([]string{"http", "https", "quic"}, listener.Type) {
		listener.Path = "/turn"
	}
}

func validateTURNHostedListener(listener TURNHostedListener) error {
	if listener.Name == "" {
		return fmt.Errorf("name is required")
	}
	if listener.Listen == "" {
		return fmt.Errorf("listen is required")
	}
	if !slices.Contains([]string{"udp", "tcp", "tls", "dtls", "http", "https", "quic"}, listener.Type) {
		return fmt.Errorf("unsupported listener type %q", listener.Type)
	}
	if listener.ExternalEndpoint != "" && strings.Contains(listener.ExternalEndpoint, "://") {
		if _, err := url.Parse(listener.ExternalEndpoint); err != nil {
			return fmt.Errorf("external_endpoint: %w", err)
		}
	}
	return nil
}

func handleListTURNListeners(w http.ResponseWriter, r *http.Request) {
	var listeners []TURNHostedListener
	gdb.Order("sort_order asc, id asc").Find(&listeners)
	status := fetchTURNStatus()
	boundByType := map[string]string{}
	for _, listener := range status.Listeners {
		if _, ok := boundByType[listener.Type]; !ok {
			boundByType[listener.Type] = listener.Addr
		}
	}
	for i := range listeners {
		listeners[i].BoundAddr = boundByType[listeners[i].Type]
	}
	w.Header().Set("Content-Type", "application/json")
	if listeners == nil {
		listeners = []TURNHostedListener{}
	}
	json.NewEncoder(w).Encode(listeners)
}

func handleCreateTURNListener(w http.ResponseWriter, r *http.Request) {
	var listener TURNHostedListener
	if err := json.NewDecoder(r.Body).Decode(&listener); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	normalizeTURNHostedListener(&listener)
	if err := validateTURNHostedListener(listener); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := gdb.Create(&listener).Error; err != nil {
		http.Error(w, "failed to create listener", http.StatusConflict)
		return
	}
	generateTurnCanonicalYAML()
	go restartManagedTURNDaemonIfEnabled()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(listener)
}

func handleUpdateTURNListener(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	var listener TURNHostedListener
	if err := gdb.First(&listener, id).Error; err != nil {
		http.Error(w, "listener not found", http.StatusNotFound)
		return
	}
	var req TURNHostedListener
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	req.ID = listener.ID
	normalizeTURNHostedListener(&req)
	if err := validateTURNHostedListener(req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := gdb.Model(&listener).Updates(req).Error; err != nil {
		http.Error(w, "failed to update listener", http.StatusConflict)
		return
	}
	generateTurnCanonicalYAML()
	go restartManagedTURNDaemonIfEnabled()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(req)
}

func handleDeleteTURNListener(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	gdb.Delete(&TURNHostedListener{}, id)
	generateTurnCanonicalYAML()
	go restartManagedTURNDaemonIfEnabled()
	w.WriteHeader(http.StatusNoContent)
}

func handleGetTURNStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(fetchTURNStatus())
}

func handleGetMyTURNCredentials(w http.ResponseWriter, r *http.Request) {
	user, ok := currentUserFromRequest(w, r)
	if !ok {
		return
	}
	var creds []TURNCredential
	gdb.Where("user_id = ?", user.ID).Order("created_at desc").Find(&creds)
	active := activeTURNUsernames()
	for i := range creds {
		password := decryptAtRest(creds[i].PasswordEncrypted)
		creds[i].Connected = active[creds[i].Username]
		creds[i].Profiles = buildTURNCredentialProfiles(creds[i], password)
	}
	w.Header().Set("Content-Type", "application/json")
	if creds == nil {
		creds = []TURNCredential{}
	}
	json.NewEncoder(w).Encode(creds)
}

func handleListAllTURNCredentials(w http.ResponseWriter, r *http.Request) {
	var creds []TURNCredential
	gdb.Preload("User").Order("created_at desc").Find(&creds)
	active := activeTURNUsernames()
	for i := range creds {
		password := decryptAtRest(creds[i].PasswordEncrypted)
		creds[i].Connected = active[creds[i].Username]
		creds[i].Profiles = buildTURNCredentialProfiles(creds[i], password)
		creds[i].OwnerUsername = creds[i].User.Username
	}
	w.Header().Set("Content-Type", "application/json")
	if creds == nil {
		creds = []TURNCredential{}
	}
	json.NewEncoder(w).Encode(creds)
}

func handleCreateMyTURNCredential(w http.ResponseWriter, r *http.Request) {
	user, ok := currentUserFromRequest(w, r)
	if !ok {
		return
	}
	if !turnHostingEnabled() || !turnUserCredentialsAllowed() {
		http.Error(w, "TURN self-service is disabled", http.StatusForbidden)
		return
	}

	var req struct {
		Name               string `json:"name"`
		WireGuardPublicKey string `json:"wireguard_public_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.WireGuardPublicKey = strings.TrimSpace(req.WireGuardPublicKey)
	if req.WireGuardPublicKey != "" {
		if _, err := wgtypes.ParseKey(req.WireGuardPublicKey); err != nil {
			http.Error(w, "invalid wireguard_public_key", http.StatusBadRequest)
			return
		}
	}

	var count int64
	gdb.Model(&TURNCredential{}).Where("user_id = ?", user.ID).Count(&count)
	if count >= int64(turnUserCredentialLimit()) {
		http.Error(w, "credential limit reached", http.StatusConflict)
		return
	}

	port, err := allocateTURNCredentialPort()
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	password := randomSecret(18)
	cred := TURNCredential{
		UserID:             user.ID,
		Name:               req.Name,
		Username:           fmt.Sprintf("turn-u%d-%s", user.ID, randomSecret(5)),
		PasswordEncrypted:  encryptAtRest(password),
		Port:               port,
		WireGuardPublicKey: req.WireGuardPublicKey,
		Enabled:            true,
	}
	if cred.Name == "" {
		cred.Name = "TURN relay"
	}
	if err := gdb.Create(&cred).Error; err != nil {
		http.Error(w, "failed to create credential", http.StatusConflict)
		return
	}
	generateTurnCanonicalYAML()
	if err := syncTURNCredentialsToDaemon(); err != nil {
		log.Printf("TURN daemon sync failed after create, restarting: %v", err)
		go restartManagedTURNDaemonIfEnabled()
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":                   cred.ID,
		"name":                 cred.Name,
		"username":             cred.Username,
		"password":             password,
		"port":                 cred.Port,
		"wireguard_public_key": cred.WireGuardPublicKey,
		"profiles":             buildTURNCredentialProfiles(cred, password),
	})
}

func handleDeleteMyTURNCredential(w http.ResponseWriter, r *http.Request) {
	user, ok := currentUserFromRequest(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	result := gdb.Where("id = ? AND user_id = ?", id, user.ID).Delete(&TURNCredential{})
	if result.RowsAffected == 0 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	generateTurnCanonicalYAML()
	if err := syncTURNCredentialsToDaemon(); err != nil {
		log.Printf("TURN daemon sync failed after delete, restarting: %v", err)
		go restartManagedTURNDaemonIfEnabled()
	}
	w.WriteHeader(http.StatusNoContent)
}

func allocateTURNCredentialPort() (int, error) {
	start, end := turnUserPortRange()
	var creds []TURNCredential
	gdb.Find(&creds)
	used := map[int]struct{}{}
	for _, cred := range creds {
		used[cred.Port] = struct{}{}
	}
	for port := start; port <= end; port++ {
		if _, ok := used[port]; !ok {
			return port, nil
		}
	}
	return 0, fmt.Errorf("no TURN user ports available in %d-%d", start, end)
}

func buildTURNListenerConfigMaps() []map[string]interface{} {
	listeners := listEnabledTURNListeners()
	out := make([]map[string]interface{}, 0, len(listeners))
	for _, listener := range listeners {
		m := map[string]interface{}{
			"type":   listener.Type,
			"listen": listener.Listen,
		}
		if listener.Path != "" {
			m["path"] = listener.Path
		}
		if listener.AdvertiseHTTP3 {
			m["advertise_http3"] = true
		}
		if listener.CertFile != "" {
			m["cert_file"] = listener.CertFile
		}
		if listener.KeyFile != "" {
			m["key_file"] = listener.KeyFile
		}
		if listener.CAFile != "" {
			m["ca_file"] = listener.CAFile
		}
		if listener.VerifyPeer {
			m["verify_peer"] = true
		}
		out = append(out, m)
	}
	return out
}

func buildTURNDaemonUsers() []map[string]interface{} {
	var creds []TURNCredential
	gdb.Where("enabled = ?", true).Order("id asc").Find(&creds)
	out := make([]map[string]interface{}, 0, len(creds))
	for _, cred := range creds {
		user := map[string]interface{}{
			"username": cred.Username,
			"password": decryptAtRest(cred.PasswordEncrypted),
			"port":     cred.Port,
		}
		if cred.WireGuardPublicKey != "" {
			user["wireguard_public_key"] = cred.WireGuardPublicKey
			user["wireguard_mode"] = "server-only"
		} else {
			user["wireguard_mode"] = "required-in-username"
		}
		out = append(out, user)
	}
	return out
}

func buildTURNCredentialProfiles(cred TURNCredential, password string) []TURNClientProfile {
	listeners := listEnabledTURNListeners()
	out := make([]TURNClientProfile, 0, len(listeners))
	for _, listener := range listeners {
		if profileURL := buildTURNListenerURL(listener, cred.Username, password); profileURL != "" {
			out = append(out, TURNClientProfile{
				Label: strings.ToUpper(listener.Type),
				Type:  listener.Type,
				URL:   profileURL,
			})
		}
	}
	return out
}

func buildTURNListenerURL(listener TURNHostedListener, username, password string) string {
	raw := strings.TrimSpace(listener.ExternalEndpoint)
	if raw == "" {
		raw = defaultTURNExternalEndpoint(listener)
	}
	if raw == "" {
		return ""
	}

	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return ""
		}
		u.User = url.UserPassword(username, password)
		if u.Path == "" && slices.Contains([]string{"http", "https", "quic"}, listener.Type) {
			u.Path = listener.Path
			if u.Path == "" {
				u.Path = "/turn"
			}
		}
		return u.String()
	}

	u := &url.URL{
		Scheme: listener.Type,
		Host:   raw,
		User:   url.UserPassword(username, password),
	}
	if slices.Contains([]string{"http", "https", "quic"}, listener.Type) {
		u.Path = listener.Path
		if u.Path == "" {
			u.Path = "/turn"
		}
	}
	return u.String()
}

func defaultTURNExternalEndpoint(listener TURNHostedListener) string {
	host := hostWithoutPort(strings.TrimSpace(getConfig("server_endpoint")))
	if host == "" {
		host = detectDefaultBootstrapIP()
	}
	if host == "" {
		return ""
	}
	_, port, err := net.SplitHostPort(listener.Listen)
	if err != nil || port == "" {
		return ""
	}
	return net.JoinHostPort(host, port)
}
