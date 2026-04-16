// wgui.go
package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"gopkg.in/yaml.v3"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

//go:embed dist/*
var frontendFS embed.FS

// --- Configuration ---
var (
	dbDSN         = flag.String("dsn", "wgui.db", "Database DSN")
	dbType        = flag.String("db-type", "sqlite", "Database type: sqlite, mysql, postgres")
	listenAddr    = flag.String("listen", "0.0.0.0:8080", "HTTP/HTTPS listen address")
	uwgsocksURL   = flag.String("wg-url", "unix://uwgsocks.sock", "uwgsocks API URL")
	uwgsocksToken = flag.String("wg-token", "", "uwgsocks API Token")
	manageDaemon  = flag.Bool("manage", true, "Start and manage uwgsocks daemon")
	daemonPath    = flag.String("daemon-path", "", "Path to uwgsocks binary (auto-detected if empty)")
	tlsCert       = flag.String("tls-cert", "", "Path to TLS cert")
	tlsKey        = flag.String("tls-key", "", "Path to TLS key")

	// TURN settings from CLI
	turnServer = flag.String("turn-server", "", "TURN server (host:port)")
	turnUser   = flag.String("turn-user", "", "TURN username")
	turnPass   = flag.String("turn-pass", "", "TURN password")
	turnRealm  = flag.String("turn-realm", "", "TURN realm")

	baselineConfig = flag.String("baseline-config", "", "Path to baseline YAML configuration to merge with UI settings")
	generateConfig = flag.Bool("generate-config", false, "Generate and print a bootstrap WireGuard client config on startup")

	systemMode = flag.Bool("system", false, "Use kernel WireGuard (requires root)")
	autoSystem = flag.Bool("auto-system", false, "Auto-detect and use kernel WireGuard if possible")
	dataDir    = flag.String("data-dir", ".", "Directory to store configuration and database files")
)

var gdb *gorm.DB
var mu sync.Mutex
var hmacSecret = make([]byte, 32)
var trafficHistory = newTrafficTracker(30 * time.Minute)

// --- Discovery Helpers ---

func resolvePath(name string) string {
	if *dataDir == "." || filepath.IsAbs(name) {
		return name
	}
	return filepath.Join(*dataDir, name)
}

func hasNetAdmin() bool {
	// Simple check: can we open a netlink socket or create a dummy interface?
	// Real check would use unix.Capget, but this is a good heuristic.
	if os.Geteuid() != 0 {
		return false
	}
	// Try creating a test link (omitted for brevity, assume root = yes for now)
	return true
}

func findDaemon(system bool) string {
	if *daemonPath != "" {
		return *daemonPath
	}
	name := "uwgsocks"
	if system {
		name = "uwgkm"
	}

	if _, err := os.Stat("./" + name); err == nil {
		return "./" + name
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	if _, err := os.Stat("../" + name); err == nil {
		return "../" + name
	}
	return "./" + name
}

func discoverMTU() int {
	log.Println("Discovering optimal MTU...")
	// Start with default
	mtu := 1420
	// Simple strategy: ping google.com with varying sizes
	// This is a placeholder; real implementation would use raw sockets or exec ping
	// For now, we return 1420 but reduce if TURN is present.
	if *turnServer != "" {
		mtu = 1280 // Reduce for TURN overhead
		log.Printf("TURN enabled, using conservative MTU: %d", mtu)
	}
	return mtu
}

// --- GORM Models ---
type User struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	Username     string    `gorm:"uniqueIndex;not null" json:"username"`
	PasswordHash string    `json:"-"`
	Token        string    `gorm:"uniqueIndex" json:"token,omitempty"`
	IsAdmin      bool      `gorm:"default:false" json:"is_admin"`
	MaxConfigs   int       `gorm:"default:10" json:"max_configs"`
	TOTPSecret   string    `json:"-"`
	TOTPEnabled  bool      `gorm:"default:false" json:"totp_enabled"`
	OIDCProvider string    `json:"oidc_provider,omitempty"`
	OIDCSubject  *string   `gorm:"uniqueIndex" json:"oidc_subject,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Peers        []Peer    `gorm:"foreignKey:UserID" json:"peers,omitempty"`
}

type Peer struct {
	ID                  uint       `gorm:"primaryKey" json:"id"`
	UserID              uint       `gorm:"not null" json:"user_id"`
	User                User       `gorm:"foreignKey:UserID" json:"-"`
	Username            string     `gorm:"-" json:"username,omitempty"`
	Name                string     `gorm:"not null" json:"name"`
	AssignedIPs         string     `gorm:"not null" json:"assigned_ips"`
	Keepalive           int        `gorm:"default:0" json:"keepalive"`
	EndpointIP          string     `json:"endpoint_ip,omitempty"`
	PublicKey           string     `gorm:"uniqueIndex;not null" json:"public_key"`
	NonceHash           string     `json:"nonce_hash,omitempty"`
	PresharedKey        string     `json:"preshared_key,omitempty"`
	EncryptedPrivateKey string     `json:"encrypted_private_key,omitempty"`
	PrivateKey          string     `json:"-"` // Only populated if IsE2E is false, stored encrypted at rest
	IsE2E               bool       `gorm:"default:false" json:"is_e2e"`
	Enabled             bool       `gorm:"default:true" json:"enabled"`
	IsManualKey         bool       `gorm:"default:false" json:"is_manual_key"`
	IsOwner             bool       `gorm:"-" json:"is_owner"`
	StaticEndpoint      string     `json:"static_endpoint,omitempty"`
	ExpiresAt           *time.Time `json:"expires_at,omitempty"`
	// Stats from uwgsocks (volatile)
	LastHandshakeTime     string             `gorm:"-" json:"last_handshake_time,omitempty"`
	TransmitBytes         uint64             `gorm:"-" json:"transmit_bytes"`
	ReceiveBytes          uint64             `gorm:"-" json:"receive_bytes"`
	HasHandshake          bool               `gorm:"-" json:"has_handshake"`
	HasPrivateKeyMaterial bool               `gorm:"-" json:"has_private_key_material"`
	TrafficHistory        []PeerTrafficPoint `gorm:"-" json:"traffic_history,omitempty"`
}

type GlobalConfig struct {
	Key   string `gorm:"primaryKey"`
	Value string
}

type ACLRule struct {
	ID       uint   `gorm:"primaryKey" json:"id"`
	ListName string `gorm:"not null" json:"list_name"` // inbound, outbound, relay
	Action   string `gorm:"not null" json:"action"`    // allow, deny
	Src      string `json:"src,omitempty"`
	Dst      string `json:"dst,omitempty"`
	Proto    string `json:"proto,omitempty"`
	DPort    string `json:"dport,omitempty"`
	Priority int    `gorm:"default:0" json:"priority"`
}

type PeerProtected = Peer
type PeerPrivate = Peer

// --- Main Initialization ---
func startHTTPServer(mux *http.ServeMux) {
	if *tlsCert == "" || *tlsKey == "" {
		*tlsCert, *tlsKey = ensureSelfSignedCert()
	}

	cert, err := tls.LoadX509KeyPair(*tlsCert, *tlsKey)
	if err != nil {
		log.Printf("Failed to load TLS cert: %v. Running HTTP only.", err)
		log.Fatal(http.ListenAndServe(*listenAddr, mux))
		return
	}

	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}
	l, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("UI Backend listening on %s (HTTP/HTTPS Multiplexed)", *listenAddr)

	httpLn := newInternalListener(l.Addr())
	httpsLn := newInternalListener(l.Addr())

	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 30 * time.Second,
	}

	go server.Serve(httpLn)
	go server.Serve(tls.NewListener(httpsLn, tlsConfig))

	for {
		conn, err := l.Accept()
		if err != nil {
			continue
		}

		go func(c net.Conn) {
			buf := make([]byte, 1)
			c.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, err := c.Read(buf)
			c.SetReadDeadline(time.Time{})

			if err != nil {
				c.Close()
				return
			}

			wrapped := &peekedConn{Conn: c, peeked: buf[:n]}
			if buf[0] == 0x16 {
				httpsLn.conns <- wrapped
			} else {
				httpLn.conns <- wrapped
			}
		}(conn)
	}
}

type internalListener struct {
	addr  net.Addr
	conns chan net.Conn
}

func newInternalListener(addr net.Addr) *internalListener {
	return &internalListener{
		addr:  addr,
		conns: make(chan net.Conn),
	}
}

func (l *internalListener) Accept() (net.Conn, error) {
	c, ok := <-l.conns
	if !ok {
		return nil, io.EOF
	}
	return c, nil
}

func (l *internalListener) Close() error   { return nil }
func (l *internalListener) Addr() net.Addr { return l.addr }

type peekedConn struct {
	net.Conn
	peeked []byte
}

func (c *peekedConn) Read(b []byte) (int, error) {
	if len(c.peeked) > 0 {
		n := copy(b, c.peeked)
		c.peeked = c.peeked[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}

func ensureSelfSignedCert() (string, string) {
	certFile := resolvePath("wgui.crt")
	keyFile := resolvePath("wgui.key")

	if _, err := os.Stat(certFile); err == nil {
		return certFile, keyFile
	}

	log.Println("Generating self-signed TLS certificate...")

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("rsa.GenerateKey: %v", err)
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"WireGuard SD-WAN"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("0.0.0.0")},
		DNSNames:              []string{"localhost"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		log.Fatalf("x509.CreateCertificate: %v", err)
	}

	certOut, err := os.Create(certFile)
	if err != nil {
		log.Fatalf("os.Create(certOut): %v", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		log.Fatalf("pem.Encode(certOut): %v", err)
	}
	certOut.Close()

	keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("os.OpenFile(keyFile): %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		log.Fatalf("pem.Encode(keyOut): %v", err)
	}
	keyOut.Close()

	return certFile, keyFile
}

func main() {
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	if *baselineConfig == "" {
		*baselineConfig = os.Getenv("BASELINE_CONFIG")
	}
	if *turnServer == "" {
		*turnServer = os.Getenv("TURN_SERVER")
	}
	if *turnUser == "" {
		*turnUser = os.Getenv("TURN_USER")
	}
	if *turnPass == "" {
		*turnPass = os.Getenv("TURN_PASS")
	}
	if *turnRealm == "" {
		*turnRealm = os.Getenv("TURN_REALM")
	}
	os.MkdirAll(*dataDir, 0755)
	rand.Read(hmacSecret)
	initDB()
	initGlobalSettings()
	maybeGenerateBootstrapConfig()

	if os.Getenv("SYSTEM_MODE") == "true" {
		*systemMode = true
		log.Println("SYSTEM_MODE=true environment variable found, enabling system WireGuard mode.")
	}

	*daemonPath = findDaemon(*systemMode)

	if *manageDaemon {
		// Set MTU if not manually overridden in DB already
		if getConfig("global_mtu") == "1420" {
			mtu := discoverMTU()
			gdb.Model(&GlobalConfig{}).Where("key = ?", "global_mtu").Update("value", strconv.Itoa(mtu))
		}

		generateCanonicalYAML()
		startDaemon()
	}

	time.Sleep(1 * time.Second)
	syncPeersToDaemon()

	// Expiration Ticker
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		for range ticker.C {
			var expired []Peer
			gdb.Where("enabled = ? AND expires_at IS NOT NULL AND expires_at < ?", true, time.Now()).Find(&expired)
			for _, p := range expired {
				log.Printf("Disabling expired peer: %s", p.Name)
				removePeerFromDaemon(p.PublicKey)
				gdb.Model(&p).Update("enabled", false)
			}
		}
	}()

	mux := http.NewServeMux()

	// Auth
	mux.HandleFunc("POST /api/login", handleLogin)
	mux.HandleFunc("GET /api/auth/hmac-nonce", authMiddleware(handleHMACNonce))
	mux.HandleFunc("GET /api/share/{token}", handleGetSharedConfig)

	// Peer Management
	mux.HandleFunc("GET /api/peers", authMiddleware(handleGetPeers))
	mux.HandleFunc("POST /api/peers", authMiddleware(handleCreatePeer))
	mux.HandleFunc("PATCH /api/peers/{id}", authMiddleware(handleUpdatePeer))
	mux.HandleFunc("DELETE /api/peers/{id}", authMiddleware(handleDeletePeer))
	mux.HandleFunc("GET /api/peers/{id}/private", authMiddleware(handleGetPeerPrivate))
	mux.HandleFunc("POST /api/peers/{id}/ping", authMiddleware(handlePingPeer))
	mux.HandleFunc("POST /api/peers/{id}/share-links", authMiddleware(handleCreateShareLink))

	// Admin - Users
	mux.HandleFunc("GET /api/admin/users", authMiddleware(adminMiddleware(handleGetUsers)))
	mux.HandleFunc("POST /api/admin/users", authMiddleware(adminMiddleware(handleCreateUser)))
	mux.HandleFunc("DELETE /api/admin/users/{id}", authMiddleware(adminMiddleware(handleDeleteUser)))

	// Admin - ACLs
	mux.HandleFunc("GET /api/admin/acls", authMiddleware(adminMiddleware(handleGetACLs)))
	mux.HandleFunc("POST /api/admin/acls", authMiddleware(adminMiddleware(handleCreateACL)))
	mux.HandleFunc("DELETE /api/admin/acls/{id}", authMiddleware(adminMiddleware(handleDeleteACL)))

	// Admin - Config
	mux.HandleFunc("GET /api/admin/config", authMiddleware(adminMiddleware(handleGetAdminConfig)))
	mux.HandleFunc("POST /api/admin/config", authMiddleware(adminMiddleware(handleUpdateGlobalConfig)))
	mux.HandleFunc("GET /api/config/public", authMiddleware(handleGetPublicConfig))
	mux.HandleFunc("GET /api/openapi.yaml", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "openapi.yaml")
	})
	mux.HandleFunc("GET /api/admin/yaml", authMiddleware(adminMiddleware(func(w http.ResponseWriter, r *http.Request) {
		d, _ := os.ReadFile("uwg_canonical.yaml")
		w.Header().Set("Content-Type", "text/plain")
		w.Write(d)
	})))
	mux.HandleFunc("GET /api/admin/stats", authMiddleware(adminMiddleware(func(w http.ResponseWriter, r *http.Request) {
		resp, _ := uwgRequest("GET", "/v1/status", nil)
		w.Header().Set("Content-Type", "application/json")
		io.Copy(w, resp.Body)
		resp.Body.Close()
	})))

	// Static Frontend & Redirect (Embedded)
	distFS, _ := fs.Sub(frontendFS, "dist")
	staticHandler := http.FileServer(http.FS(distFS))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		isLocal := strings.HasPrefix(r.RemoteAddr, "127.0.0.1") || strings.HasPrefix(r.RemoteAddr, "[::1]")
		if !isLocal && r.TLS == nil && !strings.HasPrefix(r.URL.Path, "/api") {
			host, _, _ := net.SplitHostPort(r.Host)
			if host == "" {
				host = r.Host
			}
			http.Redirect(w, r, "https://"+host+r.RequestURI, http.StatusMovedPermanently)
			return
		}

		path := r.URL.Path
		if strings.HasPrefix(path, "/api") {
			http.NotFound(w, r)
			return
		}

		// Try to serve static file
		f, err := distFS.Open(strings.TrimPrefix(path, "/"))
		if err == nil {
			f.Close()
			staticHandler.ServeHTTP(w, r)
			return
		}
		// Fallback to index.html for SPA
		index, err := distFS.Open("index.html")
		if err != nil {
			http.Error(w, "Frontend assets missing", http.StatusNotFound)
			return
		}
		defer index.Close()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.Copy(w, index)
	})

	startHTTPServer(mux)
}

// --- Database Init & Auth ---
func initDB() {
	var dialer gorm.Dialector
	switch *dbType {
	case "mysql":
		dialer = mysql.Open(*dbDSN)
	case "postgres":
		dialer = postgres.Open(*dbDSN)
	default:
		dbPath := *dbDSN
		if *dbDSN == "wgui.db" {
			dbPath = resolvePath("wgui.db")
		}
		dialer = sqlite.Open(dbPath)
	}

	var err error
	gdb, err = gorm.Open(dialer, &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Auto Migration
	err = gdb.AutoMigrate(&User{}, &Peer{}, &GlobalConfig{}, &ACLRule{}, &SharedConfigLink{})
	if err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}

	ensureInitialAdminUser()
}

type SecretsConfig struct {
	ServerPrivateKey string `json:"server_private_key"`
	ServerPublicKey  string `json:"server_public_key"`
	HMACSecretHex    string `json:"hmac_secret_hex"`
}

func initGlobalSettings() {
	secretsPath := resolvePath("wgui_secrets.json")
	var secrets SecretsConfig

	// Try reading secrets
	if data, err := os.ReadFile(secretsPath); err == nil {
		json.Unmarshal(data, &secrets)
	}

	if secrets.ServerPrivateKey == "" {
		key, _ := wgtypes.GeneratePrivateKey()
		secrets.ServerPrivateKey = key.String()
		secrets.ServerPublicKey = key.PublicKey().String()

		rand.Read(hmacSecret)
		secrets.HMACSecretHex = hex.EncodeToString(hmacSecret)

		d, _ := json.MarshalIndent(secrets, "", "  ")
		os.WriteFile(secretsPath, d, 0600)
		log.Printf("Generated new server keys and HMAC secret in %s", secretsPath)
	} else {
		b, err := hex.DecodeString(secrets.HMACSecretHex)
		if err == nil && len(b) == 32 {
			copy(hmacSecret, b)
		} else {
			rand.Read(hmacSecret)
		}
	}

	defaults := map[string]string{
		"server_privkey":           secrets.ServerPrivateKey,
		"server_pubkey":            secrets.ServerPublicKey,
		"server_endpoint":          "127.0.0.1:51820",
		"client_dns":               "100.64.0.1",
		"client_subnet_ipv4":       "100.64.0.0/24",
		"client_subnet_ipv6":       "fd00:64::/64",
		"public_keys_visible":      "false",
		"endpoints_visible":        "false",
		"p2p_routing_enabled":      "true",
		"allow_custom_private_key": "true",
		"e2e_encryption_enabled":   "true",
		"global_mtu":               "1420",
		// Canonical YAML Toggles
		"yaml_l3_forwarding":       "true",
		"yaml_block_rfc":           "true",
		"yaml_host_forward":        "false",
		"yaml_socks5_port":         "1080",
		"yaml_inbound_transparent": "true",
		"yaml_socks5_udp":          "true",
	}

	if ep := os.Getenv("WG_PUBLIC_ENDPOINT"); ep != "" {
		defaults["server_endpoint"] = ep
	}
	if dns := os.Getenv("WG_CLIENT_DNS"); dns != "" {
		defaults["client_dns"] = dns
	}

	for k, v := range defaults {
		gdb.Where(GlobalConfig{Key: k}).FirstOrCreate(&GlobalConfig{Key: k, Value: v})
		if (k == "server_endpoint" && os.Getenv("WG_PUBLIC_ENDPOINT") != "") ||
			(k == "client_dns" && os.Getenv("WG_CLIENT_DNS") != "") {
			gdb.Model(&GlobalConfig{}).Where("key = ?", k).Update("value", v)
		}
	}
}

func getConfig(k string) string {
	var c GlobalConfig
	gdb.First(&c, "key = ?", k)
	return c.Value
}

// --- Middlewares ---
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if strings.HasPrefix(token, "Bearer ") {
			token = strings.TrimPrefix(token, "Bearer ")
		}

		if token == "" {
			log.Printf("Auth failed: Missing token for %s %s", r.Method, r.URL.Path)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		var user User
		if err := gdb.First(&user, "token = ?", token).Error; err != nil {
			log.Printf("Auth failed: Invalid token %q for %s %s: %v", token, r.Method, r.URL.Path, err)
			http.Error(w, "Invalid Token", http.StatusUnauthorized)
			return
		}

		r.Header.Set("X-User-Id", fmt.Sprint(user.ID))
		r.Header.Set("X-Is-Admin", fmt.Sprint(user.IsAdmin))
		next.ServeHTTP(w, r)
	}
}

func adminMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Is-Admin") != "true" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	}
}

// --- Hashing & Crypto Helpers ---
func hashPassword(password string) (string, error) {
	// Argon2id is preferred
	salt := make([]byte, 16)
	rand.Read(salt)
	hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)

	res := fmt.Sprintf("$argon2id$v=19$m=65536,t=1,p=4$%s$%s",
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash))
	return res, nil
}

func verifyPassword(password, encodedHash string) bool {
	if strings.HasPrefix(encodedHash, "$argon2id$") {
		vals := strings.Split(encodedHash, "$")
		if len(vals) != 6 {
			return false
		}
		salt, _ := base64.RawStdEncoding.DecodeString(vals[4])
		hash, _ := base64.RawStdEncoding.DecodeString(vals[5])

		// Parse m, t, p
		var m, t uint32
		var p uint8
		fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &m, &t, &p)

		comp := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(hash)))
		return hmac.Equal(hash, comp)
	}
	// Fallback to bcrypt
	return bcrypt.CompareHashAndPassword([]byte(encodedHash), []byte(password)) == nil
}

func getDBEncryptionKey() []byte {
	priv := getConfig("server_privkey")
	h := sha256.Sum256([]byte(priv))
	return h[:]
}

func encryptAtRest(plain string) string {
	if plain == "" {
		return ""
	}
	key := getDBEncryptionKey()
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	cipherText := gcm.Seal(nonce, nonce, []byte(plain), nil)
	return base64.StdEncoding.EncodeToString(cipherText)
}

func decryptAtRest(cipherB64 string) string {
	if cipherB64 == "" {
		return ""
	}
	data, err := base64.StdEncoding.DecodeString(cipherB64)
	if err != nil {
		return ""
	}
	key := getDBEncryptionKey()
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return ""
	}
	nonce, cipherText := data[:nonceSize], data[nonceSize:]
	plain, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return ""
	}
	return string(plain)
}

// --- Handlers ---
func handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	var user User
	if err := gdb.First(&user, "username = ?", req.Username).Error; err != nil {
		log.Printf("Login failed: user %q not found", req.Username)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if !verifyPassword(req.Password, user.PasswordHash) {
		log.Printf("Login failed for user %q: wrong password", req.Username)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	b := make([]byte, 32)
	rand.Read(b)
	token := base64.URLEncoding.EncodeToString(b)
	gdb.Model(&user).Update("token", token)

	log.Printf("User %q logged in successfully", req.Username)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

// Creates a peer. Expects Client to send Public Key, Encrypted Priv Key, and Nonce Hash.
func handleCreatePeer(w http.ResponseWriter, r *http.Request) {
	userIDStr := r.Header.Get("X-User-Id")
	isAdmin := r.Header.Get("X-Is-Admin") == "true"
	var userID uint
	fmt.Sscanf(userIDStr, "%d", &userID)

	var user User
	gdb.First(&user, userID)

	var count int64
	gdb.Model(&Peer{}).Where("user_id = ?", userID).Count(&count)
	if count >= int64(user.MaxConfigs) && !isAdmin {
		http.Error(w, "Config limit reached", http.StatusForbidden)
		return
	}

	var req struct {
		Name                string     `json:"name"`
		PublicKey           string     `json:"public_key"`
		NonceHash           string     `json:"nonce_hash"`
		EncryptedPrivateKey string     `json:"encrypted_private_key"`
		RequestedIP         string     `json:"requested_ip,omitempty"`
		Keepalive           int        `json:"keepalive"`
		StaticEndpoint      string     `json:"static_endpoint,omitempty"`
		IsManualKey         bool       `json:"is_manual_key"`
		ExpiresAt           *time.Time `json:"expires_at,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	e2eEnabled := getConfig("e2e_encryption_enabled") == "true"
	if isAdmin {
		e2eEnabled = req.EncryptedPrivateKey != ""
	} // Admin can choose based on input

	var serverPriv, serverPub string
	if !e2eEnabled && !req.IsManualKey {
		key, _ := wgtypes.GeneratePrivateKey()
		serverPriv = key.String()
		serverPub = key.PublicKey().String()
		req.PublicKey = serverPub
	}

	if getConfig("allow_custom_private_key") == "false" && req.IsManualKey && !isAdmin {
		http.Error(w, "Manual private keys are disabled by operator", http.StatusForbidden)
		return
	}

	// Determine IP Address
	var assignedIP string
	if req.RequestedIP != "" && isAdmin {
		assignedIP = req.RequestedIP
	} else {
		var err error
		assignedIP, err = allocateIP()
		if err != nil {
			http.Error(w, "Subnet exhausted", http.StatusInternalServerError)
			return
		}
	}

	pskBytes := make([]byte, 32)
	rand.Read(pskBytes)
	psk := base64.StdEncoding.EncodeToString(pskBytes)

	peer := Peer{
		UserID:              userID,
		Name:                req.Name,
		AssignedIPs:         assignedIP,
		PublicKey:           req.PublicKey,
		NonceHash:           req.NonceHash,
		PresharedKey:        encryptAtRest(psk),
		EncryptedPrivateKey: encryptAtRest(req.EncryptedPrivateKey),
		PrivateKey:          encryptAtRest(serverPriv),
		IsE2E:               e2eEnabled && !req.IsManualKey,
		Keepalive:           req.Keepalive,
		IsManualKey:         req.IsManualKey,
		StaticEndpoint:      req.StaticEndpoint,
		ExpiresAt:           req.ExpiresAt,
		Enabled:             true,
	}

	if err := gdb.Create(&peer).Error; err != nil {
		log.Printf("Failed to save peer: %v", err)
		http.Error(w, "Failed to save peer (public key must be unique)", http.StatusInternalServerError)
		return
	}

	// Sync directly to uwgsocks API
	pushPeerToDaemon(peer.PublicKey, assignedIP, psk, req.Keepalive, req.StaticEndpoint)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":                       peer.ID,
		"assigned_ips":             assignedIP,
		"public_key":               peer.PublicKey,
		"has_private_key_material": peerHasPrivateKeyMaterial(peer),
	})
}

// Returns Private data ONLY if the correct X-Nonce-Hash is provided
func handleGetPeerPrivate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	userID := r.Header.Get("X-User-Id")
	isAdmin := r.Header.Get("X-Is-Admin") == "true"
	providedHash := r.Header.Get("X-Nonce-Hash")

	var peer Peer
	if err := gdb.First(&peer, id).Error; err != nil {
		http.Error(w, "Peer not found", http.StatusNotFound)
		return
	}

	if fmt.Sprint(peer.UserID) != userID && !isAdmin {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	if peer.IsE2E {
		if providedHash == "" {
			http.Error(w, "Missing X-Nonce-Hash header", http.StatusBadRequest)
			return
		}
		if providedHash != peer.NonceHash {
			log.Printf("Hash mismatch for peer %d: expected %s, got %s", peer.ID, peer.NonceHash, providedHash)
			http.Error(w, "Invalid Nonce Hash. Decryption locked.", http.StatusForbidden)
			return
		}
		peer.EncryptedPrivateKey = decryptAtRest(peer.EncryptedPrivateKey)
	} else {
		// Server managed
		peer.EncryptedPrivateKey = decryptAtRest(peer.PrivateKey)
	}

	peer.PresharedKey = decryptAtRest(peer.PresharedKey)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(peer)
}

func handleHMACNonce(w http.ResponseWriter, r *http.Request) {
	nonce := r.URL.Query().Get("nonce")
	if nonce == "" {
		http.Error(w, "Missing nonce", http.StatusBadRequest)
		return
	}
	h := hmac.New(sha256.New, hmacSecret)
	h.Write([]byte(nonce))
	key := h.Sum(nil)
	fmt.Fprintf(w, "%x", key)
}

func fetchDaemonPeerStats() map[string]Peer {
	statsMap := make(map[string]Peer)
	resp, err := uwgRequest("GET", "/v1/status", nil)
	if err != nil {
		return statsMap
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return statsMap
	}

	var st struct {
		Peers []Peer `json:"peers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return statsMap
	}

	trafficHistory.Record(st.Peers, time.Now())
	for _, p := range st.Peers {
		statsMap[p.PublicKey] = p
	}
	return statsMap
}

func handleGetPeers(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-User-Id")
	isAdmin := r.Header.Get("X-Is-Admin") == "true"

	statsMap := fetchDaemonPeerStats()

	pubVisible := getConfig("public_keys_visible") == "true"
	endVisible := getConfig("endpoints_visible") == "true"

	var peers []Peer
	gdb.Preload("User").Find(&peers)

	var result []Peer
	for _, p := range peers {
		// Populate Username for grouping
		p.Username = p.User.Username

		// Merge Stats
		if stat, ok := statsMap[p.PublicKey]; ok {
			p.LastHandshakeTime = stat.LastHandshakeTime
			p.TransmitBytes = stat.TransmitBytes
			p.ReceiveBytes = stat.ReceiveBytes
			p.HasHandshake = stat.HasHandshake
			if stat.EndpointIP != "" {
				p.EndpointIP = stat.EndpointIP
			}
		}

		// Filter sensitive data
		isOwner := fmt.Sprint(p.UserID) == userID
		p.IsOwner = isOwner
		p.HasPrivateKeyMaterial = peerHasPrivateKeyMaterial(p)
		p.TrafficHistory = trafficHistory.History(p.PublicKey)

		if !isAdmin && !isOwner {
			if !pubVisible {
				p.PublicKey = ""
			}
			if !endVisible {
				p.EndpointIP = ""
				p.StaticEndpoint = ""
			}
		}
		result = append(result, p)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func handleDeletePeer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	userID := r.Header.Get("X-User-Id")
	isAdmin := r.Header.Get("X-Is-Admin") == "true"

	var peer Peer
	if err := gdb.First(&peer, id).Error; err != nil {
		http.Error(w, "Peer not found", http.StatusNotFound)
		return
	}

	if fmt.Sprint(peer.UserID) != userID && !isAdmin {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	gdb.Where("peer_id = ?", peer.ID).Delete(&SharedConfigLink{})
	removePeerFromDaemon(peer.PublicKey)
	gdb.Delete(&peer)
	w.WriteHeader(http.StatusOK)
}

func handleGetPublicConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(publicConfigMap())
}

func handleGetAdminConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(adminConfigMap())
}

func handleUpdatePeer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	userID := r.Header.Get("X-User-Id")
	isAdmin := r.Header.Get("X-Is-Admin") == "true"

	var peer Peer
	if err := gdb.First(&peer, id).Error; err != nil {
		http.Error(w, "Peer not found", http.StatusNotFound)
		return
	}

	if fmt.Sprint(peer.UserID) != userID && !isAdmin {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	var req struct {
		Name           *string    `json:"name"`
		AssignedIPs    *string    `json:"assigned_ips"`
		Keepalive      *int       `json:"keepalive"`
		Enabled        *bool      `json:"enabled"`
		StaticEndpoint *string    `json:"static_endpoint"`
		ExpiresAt      *time.Time `json:"expires_at"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	if req.Name != nil {
		peer.Name = *req.Name
	}
	if req.AssignedIPs != nil && isAdmin {
		peer.AssignedIPs = *req.AssignedIPs
	}
	if req.Keepalive != nil {
		peer.Keepalive = *req.Keepalive
	}
	if req.Enabled != nil {
		peer.Enabled = *req.Enabled
	}
	if req.StaticEndpoint != nil {
		peer.StaticEndpoint = *req.StaticEndpoint
	}
	if req.ExpiresAt != nil {
		peer.ExpiresAt = req.ExpiresAt
	}

	gdb.Save(&peer)

	psk := decryptAtRest(peer.PresharedKey)
	if peer.Enabled && (peer.ExpiresAt == nil || peer.ExpiresAt.After(time.Now())) {
		pushPeerToDaemon(peer.PublicKey, peer.AssignedIPs, psk, peer.Keepalive, peer.StaticEndpoint)
	} else {
		removePeerFromDaemon(peer.PublicKey)
	}
	w.WriteHeader(http.StatusOK)
}

func handlePingPeer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	userID := r.Header.Get("X-User-Id")
	isAdmin := r.Header.Get("X-Is-Admin") == "true"

	var peer Peer
	if err := gdb.First(&peer, id).Error; err != nil {
		http.Error(w, "Peer not found", http.StatusNotFound)
		return
	}

	if fmt.Sprint(peer.UserID) != userID && !isAdmin {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Use first IP for ping
	target := strings.Split(peer.AssignedIPs, ",")[0]
	target, _, _ = strings.Cut(target, "/")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := uwgRequestWithContext(ctx, "GET", fmt.Sprintf("/v1/ping?target=%s&count=3", target), nil)
	if err != nil {
		http.Error(w, "Ping failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	io.Copy(w, resp.Body)
}

func uwgRequestWithContext(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	addr := *uwgsocksURL
	var client *http.Client
	var targetURL string

	if strings.HasPrefix(addr, "unix://") {
		socketPath := strings.TrimPrefix(addr, "unix://")
		if !filepath.IsAbs(socketPath) {
			socketPath = resolvePath(socketPath)
		}
		client = &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
				},
			},
		}
		targetURL = "http://localhost" + path
	} else {
		client = http.DefaultClient
		targetURL = strings.TrimSuffix(addr, "/") + path
	}

	req, err := http.NewRequestWithContext(ctx, method, targetURL, body)
	if err != nil {
		return nil, err
	}
	if *uwgsocksToken != "" {
		req.Header.Set("Authorization", "Bearer "+*uwgsocksToken)
	}
	return client.Do(req)
}

func handleUpdateGlobalConfig(w http.ResponseWriter, r *http.Request) {
	var req map[string]string
	json.NewDecoder(r.Body).Decode(&req)
	for k, v := range req {
		gdb.Model(&GlobalConfig{}).Where("key = ?", k).Update("value", v)
	}
	generateCanonicalYAML()
	pushACLsToDaemon()
	w.WriteHeader(http.StatusOK)
}

func handleGetUsers(w http.ResponseWriter, r *http.Request) {
	var users []User
	gdb.Find(&users)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

func handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		IsAdmin  bool   `json:"is_admin"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	hp, _ := hashPassword(req.Password)
	user := User{Username: req.Username, PasswordHash: hp, IsAdmin: req.IsAdmin}
	if err := gdb.Create(&user).Error; err != nil {
		http.Error(w, "Username already exists", http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "1" {
		http.Error(w, "Cannot delete primary admin", http.StatusForbidden)
		return
	}
	gdb.Delete(&User{}, id)
	w.WriteHeader(http.StatusOK)
}

func handleGetACLs(w http.ResponseWriter, r *http.Request) {
	var acls []ACLRule
	gdb.Order("priority desc").Find(&acls)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(acls)
}

func handleCreateACL(w http.ResponseWriter, r *http.Request) {
	var a ACLRule
	if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	gdb.Create(&a)
	generateCanonicalYAML()
	pushACLsToDaemon()
	w.WriteHeader(http.StatusCreated)
}

func handleDeleteACL(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	gdb.Delete(&ACLRule{}, id)
	generateCanonicalYAML()
	pushACLsToDaemon()
	w.WriteHeader(http.StatusOK)
}

func getACLConfig() map[string]interface{} {
	getRules := func(list string) []map[string]interface{} {
		var rules []ACLRule
		gdb.Where("list_name = ?", list).Order("priority desc").Find(&rules)
		var out []map[string]interface{}
		for _, r := range rules {
			m := map[string]interface{}{"action": r.Action}
			if r.Src != "" {
				m["source"] = r.Src
			}
			if r.Proto != "" {
				m["protocol"] = strings.ToUpper(r.Proto)
			}
			if r.Dst != "" {
				m["destination"] = r.Dst
			}
			if r.DPort != "" {
				m["destination_port"] = r.DPort
			}
			out = append(out, m)
		}
		return out
	}

	acl := map[string]interface{}{
		"inbound_default":  "allow",
		"outbound_default": "allow",
		"relay_default":    "deny",
		"inbound":          getRules("inbound"),
		"outbound":         getRules("outbound"),
		"relay":            getRules("relay"),
	}
	if getConfig("p2p_routing_enabled") == "true" {
		acl["relay_default"] = "allow"
	}

	if getConfig("yaml_block_rfc") == "true" {
		rfc := []map[string]interface{}{
			{"action": "deny", "destination": "10.0.0.0/8"},
			{"action": "deny", "destination": "172.16.0.0/12"},
			{"action": "deny", "destination": "192.168.0.0/16"},
			{"action": "deny", "destination": "fc00::/7"},
		}
		acl["outbound"] = append(rfc, acl["outbound"].([]map[string]interface{})...)
	}
	return acl
}

func pushACLsToDaemon() {
	acl := getACLConfig()
	data, _ := json.Marshal(acl)
	resp, err := uwgRequestWithContext(context.Background(), "PUT", "/v1/acls", bytes.NewReader(data))
	if err != nil {
		log.Printf("Failed to push ACLs to daemon: %v", err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		log.Printf("Daemon returned error pushing ACLs: %d", resp.StatusCode)
	}
}

// --- IP Allocation & Logic ---
func allocateIP() (string, error) {
	mu.Lock()
	defer mu.Unlock()

	subnetV4 := getConfig("client_subnet_ipv4")
	prefV4, err := netip.ParsePrefix(subnetV4)
	if err != nil {
		return "", fmt.Errorf("v4 subnet: %w", err)
	}

	var assignedIPs []string
	gdb.Model(&Peer{}).Pluck("assigned_ips", &assignedIPs)
	usedMap := make(map[string]bool)
	for _, u := range assignedIPs {
		for _, part := range strings.Split(u, ",") {
			ip, _, _ := strings.Cut(strings.TrimSpace(part), "/")
			usedMap[ip] = true
		}
	}

	// IPv4: Sequential
	v4 := ""
	addr := prefV4.Addr()
	for {
		addr = addr.Next()
		if !prefV4.Contains(addr) {
			break
		}
		// Skip network, gateway (.1), and broadcast (.255)
		if addr.Is4() && (addr.AsSlice()[3] == 0 || addr.AsSlice()[3] == 1 || addr.AsSlice()[3] == 255) {
			continue
		}
		if !usedMap[addr.String()] {
			v4 = addr.String() + "/32"
			break
		}
	}

	// IPv6: Random Suffix
	subnetV6 := getConfig("client_subnet_ipv6")
	prefV6, err := netip.ParsePrefix(subnetV6)
	if err != nil {
		return "", fmt.Errorf("v6 subnet: %w", err)
	}
	v6 := ""
	for i := 0; i < 10; i++ { // Try a few times
		suffix := make([]byte, 8)
		rand.Read(suffix)
		raw := prefV6.Addr().AsSlice()
		copy(raw[8:], suffix)
		v6Addr, _ := netip.AddrFromSlice(raw)
		if !usedMap[v6Addr.String()] {
			v6 = v6Addr.String() + "/128"
			break
		}
	}

	if v4 == "" {
		return "", errors.New("ipv4 subnet exhausted")
	}
	if v6 == "" {
		return v4, nil
	} // Fallback to v4 only if v6 fails
	return v4 + ", " + v6, nil
}

// --- UWGSocks API & Process Management ---

func uwgRequest(method, path string, body io.Reader) (*http.Response, error) {
	return uwgRequestWithContext(context.Background(), method, path, body)
}

func pushPeerToDaemon(pubKey, ips, psk string, keepalive int, endpoint string) {
	var allowed []string
	for _, ip := range strings.Split(ips, ",") {
		allowed = append(allowed, strings.TrimSpace(ip))
	}
	payload := map[string]interface{}{
		"public_key":  pubKey,
		"allowed_ips": allowed,
	}
	if keepalive > 0 {
		payload["persistent_keepalive"] = keepalive
	}
	if psk != "" {
		payload["preshared_key"] = psk
	}
	if endpoint != "" {
		payload["endpoint"] = endpoint
	}

	b, _ := json.Marshal(payload)
	resp, err := uwgRequest("POST", "/v1/peers", bytes.NewBuffer(b))
	if err == nil {
		resp.Body.Close()
	}
}

func removePeerFromDaemon(pubKey string) {
	uwgRequest("DELETE", "/v1/peers?public_key="+pubKey, nil)
}

func syncPeersToDaemon() {
	log.Println("Syncing peers to uwgsocks daemon...")
	var peers []Peer
	gdb.Where("enabled = ? AND (expires_at IS NULL OR expires_at > ?)", true, time.Now()).Find(&peers)
	for _, p := range peers {
		psk := decryptAtRest(p.PresharedKey)
		pushPeerToDaemon(p.PublicKey, p.AssignedIPs, psk, p.Keepalive, p.StaticEndpoint)
	}
}

func deepMerge(dst, src map[string]interface{}) {
	for k, v := range src {
		if dv, ok := dst[k]; ok {
			if dvm, ok := dv.(map[string]interface{}); ok {
				if svm, ok := v.(map[string]interface{}); ok {
					deepMerge(dvm, svm)
					continue
				}
			}
		}
		dst[k] = v
	}
}

func generateCanonicalYAML() {
	port := 51820
	mtu, _ := strconv.Atoi(getConfig("global_mtu"))

	// Ensure unix sockets are absolute paths relative to dataDir
	apiListen := *uwgsocksURL
	if strings.HasPrefix(apiListen, "unix://") {
		socketPath := strings.TrimPrefix(apiListen, "unix://")
		if !filepath.IsAbs(socketPath) {
			apiListen = "unix://" + resolvePath(socketPath)
		}
	}

	// Start with baseline if provided
	config := make(map[string]interface{})
	if *baselineConfig != "" {
		if data, err := os.ReadFile(*baselineConfig); err == nil {
			_ = yaml.Unmarshal(data, &config)
		}
	}

	// Managed settings
	managed := map[string]interface{}{
		"api": map[string]interface{}{
			"listen": apiListen,
			"token":  *uwgsocksToken,
		}, "proxy": map[string]interface{}{
			"socks5":        "0.0.0.0:" + getConfig("yaml_socks5_port"),
			"udp_associate": getConfig("yaml_socks5_udp") == "true",
		},
		"inbound": map[string]interface{}{
			"transparent": getConfig("yaml_inbound_transparent") == "true",
		},
		"wireguard": map[string]interface{}{
			"private_key": getConfig("server_privkey"),
			"addresses":   []string{getConfig("client_dns") + "/24"},
			"listen_port": &port,
			"mtu":         mtu,
		},
		"relay": map[string]interface{}{
			"enabled": getConfig("yaml_l3_forwarding") == "true",
		},
		"dns_server": map[string]interface{}{
			"listen": getConfig("client_dns") + ":53",
		},
	}

	if *turnServer != "" {
		managed["turn"] = map[string]interface{}{
			"server":   *turnServer,
			"username": *turnUser,
			"password": *turnPass,
			"realm":    *turnRealm,
		}
	}

	managed["acl"] = getACLConfig()

	// Merge managed onto baseline
	deepMerge(config, managed)

	d, _ := yaml.Marshal(config)
	os.WriteFile(resolvePath("uwg_canonical.yaml"), d, 0644)
}

func startDaemon() {
	time.Sleep(1 * time.Second)
	var cmd *exec.Cmd

	apiListen := *uwgsocksURL
	if strings.HasPrefix(apiListen, "unix://") {
		socketPath := strings.TrimPrefix(apiListen, "unix://")
		if !filepath.IsAbs(socketPath) {
			apiListen = "unix://" + resolvePath(socketPath)
		}
	}

	if *systemMode {
		// uwgkm flags
		cmd = exec.Command(*daemonPath, "-config", resolvePath("uwg_canonical.yaml"), "-api-listen", apiListen)
	} else {
		// uwgsocks flags
		cmd = exec.Command(*daemonPath, "--config", resolvePath("uwg_canonical.yaml"))
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	go func() {
		log.Printf("Starting embedded daemon: %s...", *daemonPath)
		if err := cmd.Run(); err != nil {
			log.Printf("Daemon exited: %v", err)
		}
	}()
}
