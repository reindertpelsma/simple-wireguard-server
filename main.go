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
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
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

//go:embed frontend/dist/*
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
	turnServer             = flag.String("turn-server", "", "TURN server (host:port)")
	turnUser               = flag.String("turn-user", "", "TURN username")
	turnPass               = flag.String("turn-pass", "", "TURN password")
	turnRealm              = flag.String("turn-realm", "", "TURN realm")
	turnIncludeWGPublicKey = flag.Bool("turn-include-wg-public-key", false, "Append an encrypted WireGuard public key to the TURN username")

	baselineConfig = flag.String("baseline-config", "", "Path to baseline YAML configuration to merge with UI settings")
	generateConfig = flag.Bool("generate-config", false, "Generate and print a bootstrap WireGuard client config on startup")
	frontendDir    = flag.String("frontend-dir", "", "Serve frontend assets from this dist directory instead of the embedded dist")
	extractDist    = flag.String("extract-dist", "", "Extract the embedded frontend dist directory to this path and exit")

	oidcIssuer       = flag.String("oidc-issuer", "", "OIDC issuer URL; enables OIDC login when set")
	oidcClientID     = flag.String("oidc-client-id", "", "OIDC client ID")
	oidcClientSecret = flag.String("oidc-client-secret", "", "OIDC client secret")
	oidcRedirectURL  = flag.String("oidc-redirect-url", "", "OIDC callback URL; defaults to /api/oidc/callback on this server")

	systemMode = flag.Bool("system", false, "Use kernel WireGuard (requires root)")
	autoSystem = flag.Bool("auto-system", false, "Auto-detect and use kernel WireGuard if possible")
	dataDir    = flag.String("data-dir", ".", "Directory to store configuration and database files")
)

var gdb *gorm.DB
var mu sync.Mutex
var aclPushMu sync.Mutex
var lastPushedACLHash string
var hmacSecret = make([]byte, 32)
var trafficHistory = newTrafficTracker(30 * time.Minute)

func invalidateACLPushCache() {
	aclPushMu.Lock()
	lastPushedACLHash = ""
	aclPushMu.Unlock()
}

// --- Discovery Helpers ---

func resolvePath(name string) string {
	if *dataDir == "." || filepath.IsAbs(name) {
		return name
	}
	return filepath.Join(*dataDir, name)
}

func daemonAPIListenAddress(addr string) string {
	if strings.HasPrefix(addr, "http://") || strings.HasPrefix(addr, "https://") {
		if u, err := url.Parse(addr); err == nil && u.Host != "" {
			return u.Host
		}
	}
	return addr
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
	ID           uint    `gorm:"primaryKey" json:"id"`
	Username     string  `gorm:"uniqueIndex;not null" json:"username"`
	PasswordHash string  `json:"-"`
	Token        string  `gorm:"uniqueIndex" json:"token,omitempty"`
	IsAdmin      bool    `gorm:"default:false" json:"is_admin"`
	MaxConfigs   int     `gorm:"default:10" json:"max_configs"`
	TOTPSecret   string  `json:"-"`
	TOTPEnabled  bool    `gorm:"default:false" json:"totp_enabled"`
	OIDCProvider string  `json:"oidc_provider,omitempty"`
	OIDCSubject  *string `gorm:"uniqueIndex" json:"oidc_subject,omitempty"`
	// PrimaryGroup is the required group that determines this user's
	// IP subnet. All peer configs created for this user inherit it.
	PrimaryGroup string `json:"primary_group,omitempty"`
	// Tags stores additional (non-primary) group memberships as CSV.
	// Renamed to "groups" in the UI but kept as "tags" in the DB column.
	Tags      string    `json:"groups,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Peers     []Peer    `gorm:"foreignKey:UserID" json:"peers,omitempty"`
}

type Peer struct {
	ID       uint   `gorm:"primaryKey" json:"id"`
	UserID   uint   `gorm:"not null" json:"user_id"`
	User     User   `gorm:"foreignKey:UserID" json:"-"`
	Username string `gorm:"-" json:"username,omitempty"`
	Name     string `gorm:"not null" json:"name"`
	// PrimaryGroup is fixed at creation (inherits from the user's primary group)
	// and determines the IPv4/IPv6 subnet the config was allocated from.
	PrimaryGroup string `json:"primary_group,omitempty"`
	// Tags stores additional (non-primary) group memberships as CSV.
	Tags                string     `json:"groups,omitempty"`
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
	TrafficUploadBps    int64      `gorm:"default:0" json:"traffic_upload_bps"`
	TrafficDownloadBps  int64      `gorm:"default:0" json:"traffic_download_bps"`
	TrafficLatencyMs    int        `gorm:"default:0" json:"traffic_latency_ms"`
	// Distribute peer: when true, this peer is included in all other clients' configs
	IsDistribute       bool   `gorm:"default:false" json:"is_distribute"`
	DistributeEndpoint string `json:"distribute_endpoint,omitempty"` // endpoint advertised to other clients; auto-updated from last-seen IP
	// Stats from uwgsocks (volatile)
	LastHandshakeTime     string             `gorm:"-" json:"last_handshake_time,omitempty"`
	TransmitBytes         uint64             `gorm:"-" json:"transmit_bytes"`
	ReceiveBytes          uint64             `gorm:"-" json:"receive_bytes"`
	HasHandshake          bool               `gorm:"-" json:"has_handshake"`
	HasPrivateKeyMaterial bool               `gorm:"-" json:"has_private_key_material"`
	TrafficHistory        []PeerTrafficPoint `gorm:"-" json:"traffic_history,omitempty"`
	TransportName         string             `gorm:"-" json:"transport_name,omitempty"`
	TransportState        string             `gorm:"-" json:"transport_state,omitempty"`
	TransportEndpoint     string             `gorm:"-" json:"transport_endpoint,omitempty"`
	TransportSourceAddr   string             `gorm:"-" json:"transport_source_addr,omitempty"`
	TransportCarrierAddr  string             `gorm:"-" json:"transport_carrier_remote_addr,omitempty"`
}

type GlobalConfig struct {
	Key   string `gorm:"primaryKey"`
	Value string
}

type ACLRule struct {
	ID        uint   `gorm:"primaryKey" json:"id"`
	ListName  string `gorm:"not null" json:"list_name"` // inbound, outbound, relay
	Action    string `gorm:"not null" json:"action"`    // allow, deny
	Src       string `json:"src,omitempty"`
	SrcUsers  string `json:"src_users,omitempty"`
	SrcTags   string `json:"src_tags,omitempty"`
	SrcPeers  string `json:"src_peers,omitempty"`
	Dst       string `json:"dst,omitempty"`
	DstUsers  string `json:"dst_users,omitempty"`
	DstTags   string `json:"dst_tags,omitempty"`
	DstPeers  string `json:"dst_peers,omitempty"`
	Proto     string `json:"proto,omitempty"`
	DPort     string `json:"dport,omitempty"`
	SortOrder int    `gorm:"default:0" json:"sort_order"`
}

// TunnelForward stores a port-forwarding entry managed via the UI.
// Reverse=false is a local forward (host-side listener → WireGuard target).
// Reverse=true is a reverse forward (WireGuard-side listener → host target).
type TunnelForward struct {
	ID            uint   `gorm:"primaryKey" json:"id"`
	Name          string `json:"name,omitempty"`
	Reverse       bool   `gorm:"default:false" json:"reverse"`
	Proto         string `gorm:"not null" json:"proto"` // tcp, udp
	Listen        string `gorm:"not null" json:"listen"`
	Target        string `gorm:"not null" json:"target"`
	ProxyProtocol string `json:"proxy_protocol,omitempty"` // "", "v1", "v2"
	RuntimeName   string `json:"runtime_name,omitempty"`   // daemon-side name returned by /v1/forwards
	SortOrder     int    `gorm:"default:0" json:"sort_order"`
}

// TransportConfig stores a pluggable transport entry managed via the UI.
// The JSON fields mirror transport.Config so the UI can read/write them.
type TransportConfig struct {
	ID          uint   `gorm:"primaryKey" json:"id"`
	Name        string `gorm:"uniqueIndex;not null" json:"name"`
	Base        string `gorm:"not null" json:"base"`                   // udp|tcp|tls|dtls|http|https|quic|quic-ws|url
	Listen      bool   `gorm:"default:false" json:"listen"`            // enable listener
	ListenPort  int    `gorm:"default:0" json:"listen_port,omitempty"` // 0 = use wireguard.listen_port
	ListenAddrs string `json:"listen_addrs,omitempty"`                 // comma-separated IPs, empty = all
	URL         string `json:"url,omitempty"`                          // for base=url
	WSPath      string `json:"ws_path,omitempty"`
	ConnectHost string `json:"connect_host,omitempty"`
	HostHeader  string `json:"host_header,omitempty"`
	// TURN base transport settings
	TurnServer             string `json:"turn_server,omitempty"`
	TurnUsername           string `json:"turn_username,omitempty"`
	TurnPassword           string `json:"turn_password,omitempty"`
	TurnRealm              string `json:"turn_realm,omitempty"`
	TurnProtocol           string `json:"turn_protocol,omitempty"`
	TurnNoCreatePermission bool   `json:"turn_no_create_permission,omitempty"`
	TurnIncludeWGPublicKey bool   `json:"turn_include_wg_public_key,omitempty"`
	TurnPermissions        string `json:"turn_permissions,omitempty"` // comma-separated
	// TLS settings
	TLSCertFile   string `json:"tls_cert_file,omitempty"`
	TLSKeyFile    string `json:"tls_key_file,omitempty"`
	TLSCAFile     string `json:"tls_ca_file,omitempty"`
	TLSVerifyPeer bool   `json:"tls_verify_peer,omitempty"`
	TLSServerSNI  string `json:"tls_server_sni,omitempty"`
	// Proxy settings
	ProxyType     string `json:"proxy_type,omitempty"` // none|socks5|http
	ProxyServer   string `json:"proxy_server,omitempty"`
	ProxyUsername string `json:"proxy_username,omitempty"`
	ProxyPassword string `json:"proxy_password,omitempty"`
	// Runtime fields from /v1/status
	Connected         bool   `gorm:"-" json:"connected,omitempty"`
	CarrierProtocol   string `gorm:"-" json:"carrier_protocol,omitempty"`
	CarrierLocalAddr  string `gorm:"-" json:"carrier_local_addr,omitempty"`
	CarrierRemoteAddr string `gorm:"-" json:"carrier_remote_addr,omitempty"`
	RelayAddr         string `gorm:"-" json:"relay_addr,omitempty"`
	ActiveSessions    int    `gorm:"-" json:"active_sessions,omitempty"`
}

type PeerProtected = Peer
type PeerPrivate = Peer

// --- Main Initialization ---
func startHTTPServer(handler http.Handler) {
	if *tlsCert == "" || *tlsKey == "" {
		*tlsCert, *tlsKey = ensureSelfSignedCert()
	}

	cert, err := tls.LoadX509KeyPair(*tlsCert, *tlsKey)
	if err != nil {
		log.Printf("Failed to load TLS cert: %v. Running HTTP only.", err)
		log.Fatal(http.ListenAndServe(*listenAddr, handler))
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
		Handler:           handler,
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

func findFreePort() int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 47322
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

func unixSocketSupported() bool {
	tmp := resolvePath("_probe.sock")
	l, err := net.Listen("unix", tmp)
	if err != nil {
		return false
	}
	l.Close()
	os.Remove(tmp)
	return true
}

func main() {
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// If unix sockets aren't supported (e.g. older Windows), fall back to loopback TCP.
	// Windows 10 build 17063+ does support AF_UNIX, so we probe rather than hard-coding the OS.
	if *uwgsocksURL == "unix://uwgsocks.sock" && !unixSocketSupported() {
		port := findFreePort()
		*uwgsocksURL = fmt.Sprintf("http://127.0.0.1:%d", port)
		if *uwgsocksToken == "" {
			tokenBytes := make([]byte, 32)
			rand.Read(tokenBytes)
			*uwgsocksToken = hex.EncodeToString(tokenBytes)
		}
		log.Printf("Unix sockets unavailable; daemon API on %s (token set)", *uwgsocksURL)
	}

	if *extractDist != "" {
		if err := extractEmbeddedDist(*extractDist); err != nil {
			log.Fatalf("extract frontend dist: %v", err)
		}
		log.Printf("Extracted embedded frontend dist to %s", *extractDist)
		return
	}
	if *baselineConfig == "" {
		*baselineConfig = os.Getenv("BASELINE_CONFIG")
	}
	if *frontendDir == "" {
		*frontendDir = os.Getenv("UWGS_UI_FRONTEND_DIR")
	}
	if *oidcIssuer == "" {
		*oidcIssuer = os.Getenv("OIDC_ISSUER")
	}
	if *oidcClientID == "" {
		*oidcClientID = os.Getenv("OIDC_CLIENT_ID")
	}
	if *oidcClientSecret == "" {
		*oidcClientSecret = os.Getenv("OIDC_CLIENT_SECRET")
	}
	if *oidcRedirectURL == "" {
		*oidcRedirectURL = os.Getenv("OIDC_REDIRECT_URL")
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
	if !*turnIncludeWGPublicKey {
		if v := os.Getenv("TURN_INCLUDE_WG_PUBLIC_KEY"); v != "" {
			if parsed, err := strconv.ParseBool(v); err == nil {
				*turnIncludeWGPublicKey = parsed
			}
		}
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
	mux.HandleFunc("POST /api/logout", authMiddleware(handleLogout))
	mux.HandleFunc("GET /api/auth/methods", handleAuthMethods)
	mux.HandleFunc("GET /api/auth/hmac-nonce", authMiddleware(handleHMACNonce))
	mux.HandleFunc("GET /api/me", authMiddleware(handleMe))
	mux.HandleFunc("PATCH /api/me", authMiddleware(handleUpdateMe))
	mux.HandleFunc("POST /api/me/2fa/setup", authMiddleware(handleTOTPSetup))
	mux.HandleFunc("POST /api/me/2fa/enable", authMiddleware(handleTOTPEnable))
	mux.HandleFunc("DELETE /api/me/2fa", authMiddleware(handleTOTPDisable))
	mux.HandleFunc("GET /api/me/proxy-credentials", authMiddleware(handleGetMyProxyCredentials))
	mux.HandleFunc("POST /api/me/proxy-credentials", authMiddleware(handleCreateMyProxyCredential))
	mux.HandleFunc("DELETE /api/me/proxy-credentials/{id}", authMiddleware(handleDeleteMyProxyCredential))
	mux.HandleFunc("GET /api/oidc/login", handleOIDCLogin)
	mux.HandleFunc("GET /api/oidc/callback", handleOIDCCallback)
	mux.HandleFunc("GET /api/share/{token}", handleGetSharedConfig)
	registerAccessProxyRoutes(mux)

	// Peer Management
	mux.HandleFunc("GET /api/peers", authMiddleware(handleGetPeers))
	mux.HandleFunc("POST /api/peers", authMiddleware(handleCreatePeer))
	mux.HandleFunc("PATCH /api/peers/{id}", authMiddleware(handleUpdatePeer))
	mux.HandleFunc("DELETE /api/peers/{id}", authMiddleware(handleDeletePeer))
	mux.HandleFunc("GET /api/peers/{id}/private", authMiddleware(handleGetPeerPrivate))
	mux.HandleFunc("POST /api/peers/{id}/ping", authMiddleware(handlePingPeer))
	mux.HandleFunc("POST /api/peers/{id}/share-links", authMiddleware(handleCreateShareLink))
	mux.HandleFunc("GET /api/distribute-peers", authMiddleware(handleGetDistributePeers))

	// Admin - Users
	mux.HandleFunc("GET /api/admin/users", authMiddleware(adminMiddleware(handleGetUsers)))
	mux.HandleFunc("POST /api/admin/users", authMiddleware(adminMiddleware(handleCreateUser)))
	mux.HandleFunc("PATCH /api/admin/users/{id}", authMiddleware(adminMiddleware(handleUpdateUser)))
	mux.HandleFunc("DELETE /api/admin/users/{id}", authMiddleware(adminMiddleware(handleDeleteUser)))
	mux.HandleFunc("DELETE /api/admin/users/{id}/2fa", authMiddleware(adminMiddleware(handleAdminDeleteUserTOTP)))
	mux.HandleFunc("GET /api/admin/tags", authMiddleware(adminMiddleware(handleGetTags)))
	mux.HandleFunc("POST /api/admin/tags", authMiddleware(adminMiddleware(handleCreateTag)))
	mux.HandleFunc("PATCH /api/admin/tags/{id}", authMiddleware(adminMiddleware(handleUpdateTag)))
	mux.HandleFunc("DELETE /api/admin/tags/{id}", authMiddleware(adminMiddleware(handleDeleteTag)))

	// Admin - ACLs
	mux.HandleFunc("GET /api/admin/acls", authMiddleware(adminMiddleware(handleGetACLs)))
	mux.HandleFunc("POST /api/admin/acls", authMiddleware(adminMiddleware(handleCreateACL)))
	mux.HandleFunc("PATCH /api/admin/acls/{id}", authMiddleware(adminMiddleware(handleUpdateACL)))
	mux.HandleFunc("DELETE /api/admin/acls/{id}", authMiddleware(adminMiddleware(handleDeleteACL)))
	mux.HandleFunc("POST /api/admin/acls/reorder", authMiddleware(adminMiddleware(handleReorderACLs)))
	mux.HandleFunc("GET /api/admin/acl-tokens", authMiddleware(adminMiddleware(handleACLTokenSearch)))

	// Admin - Forwards
	mux.HandleFunc("GET /api/admin/forwards", authMiddleware(adminMiddleware(handleGetForwards)))
	mux.HandleFunc("POST /api/admin/forwards", authMiddleware(adminMiddleware(handleCreateForward)))
	mux.HandleFunc("PATCH /api/admin/forwards/{id}", authMiddleware(adminMiddleware(handleUpdateForward)))
	mux.HandleFunc("DELETE /api/admin/forwards/{id}", authMiddleware(adminMiddleware(handleDeleteForward)))

	mux.HandleFunc("GET /api/admin/transports", authMiddleware(adminMiddleware(handleGetTransports)))
	mux.HandleFunc("POST /api/admin/transports", authMiddleware(adminMiddleware(handleCreateTransport)))
	mux.HandleFunc("PATCH /api/admin/transports/{id}", authMiddleware(adminMiddleware(handleUpdateTransport)))
	mux.HandleFunc("DELETE /api/admin/transports/{id}", authMiddleware(adminMiddleware(handleDeleteTransport)))

	// Admin - Config
	mux.HandleFunc("GET /api/admin/config", authMiddleware(adminMiddleware(handleGetAdminConfig)))
	mux.HandleFunc("POST /api/admin/config", authMiddleware(adminMiddleware(handleUpdateGlobalConfig)))
	mux.HandleFunc("GET /api/admin/yaml", authMiddleware(adminMiddleware(handleGetYAMLConfig)))
	mux.HandleFunc("POST /api/admin/yaml", authMiddleware(adminMiddleware(handleSaveYAMLConfig)))
	mux.HandleFunc("POST /api/admin/restart", authMiddleware(adminMiddleware(handleRestartDaemon)))
	mux.HandleFunc("GET /api/config/public", authMiddleware(handleGetPublicConfig))
	mux.HandleFunc("GET /api/openapi.yaml", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "openapi.yaml")
	})
	mux.HandleFunc("GET /api/admin/stats", authMiddleware(adminMiddleware(func(w http.ResponseWriter, r *http.Request) {
		resp, _ := uwgRequest("GET", "/v1/status", nil)
		w.Header().Set("Content-Type", "application/json")
		io.Copy(w, resp.Body)
		resp.Body.Close()
	})))

	registerFrontendRoutes(mux)

	startHTTPServer(wrapRootHandler(mux))
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
	err = gdb.AutoMigrate(&User{}, &Peer{}, &GlobalConfig{}, &ACLRule{}, &SharedConfigLink{}, &TransportConfig{}, &AccessProxyCredential{}, &ExposedService{}, &Group{}, &TunnelForward{})

	if err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}

	migrateLegacyPolicyTags()
	ensureInitialAdminUser()
	ensureDefaultTransport()
}

func migrateLegacyPolicyTags() {
	if !gdb.Migrator().HasTable("policy_tags") {
		return
	}
	var legacy []legacyPolicyTag
	if err := gdb.Find(&legacy).Error; err != nil {
		log.Printf("Failed to read legacy policy_tags table: %v", err)
		return
	}
	for _, old := range legacy {
		name := normalizeGroupName(old.Name)
		if name == "" {
			continue
		}
		var existing Group
		if err := gdb.First(&existing, "name = ?", name).Error; err == nil {
			changed := false
			if existing.ExtraCIDRs == "" && old.ExtraCIDRs != "" {
				existing.ExtraCIDRs = joinCSVList(splitCSVList(old.ExtraCIDRs))
				changed = true
			}
			if existing.ParentGroups == "" && old.ParentTags != "" {
				existing.ParentGroups = normalizeGroupList(splitCSVList(old.ParentTags))
				changed = true
			}
			if changed {
				gdb.Save(&existing)
			}
			continue
		}
		group := Group{
			Name:         name,
			ExtraCIDRs:   joinCSVList(splitCSVList(old.ExtraCIDRs)),
			ParentGroups: normalizeGroupList(splitCSVList(old.ParentTags)),
		}
		if err := gdb.Create(&group).Error; err != nil {
			log.Printf("Failed to migrate legacy policy tag %q: %v", name, err)
		}
	}
}

// ensureDefaultTransport seeds the default UDP transport on first boot so the
// UI always shows at least one entry representing the standard WireGuard path.
func ensureDefaultTransport() {
	var count int64
	gdb.Model(&TransportConfig{}).Count(&count)
	if count > 0 {
		return
	}
	gdb.Create(&TransportConfig{
		Name:       "udp",
		Base:       "udp",
		Listen:     true,
		ListenPort: 51820,
	})
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

	ipv6Default := "false"
	var countUsers int64
	gdb.Model(&User{}).Count(&countUsers)
	if countUsers == 0 {
		// First start: detect IPv6 internet connectivity
		if detectIPv6Internet() {
			ipv6Default = "true"
			log.Println("IPv6 internet detected; enabling IPv6 client addresses by default.")
		} else {
			log.Println("No IPv6 internet detected; disabling IPv6 client addresses by default.")
		}
	}

	defaults := map[string]string{
		"server_privkey":    secrets.ServerPrivateKey,
		"server_pubkey":     secrets.ServerPublicKey,
		"server_endpoint":   resolvedServerEndpoint(),
		"default_transport": "",
		"client_dns":        "100.64.0.1",
		// group_base_subnet is the pool from which group subnets are auto-assigned.
		"group_base_subnet": "100.100.0.0/16",
		// group_subnet_bits is the prefix length for auto-assigned group subnets.
		"group_subnet_bits": "22",
		// group_base_subnet_ipv6 is the IPv6 pool for auto-assigned group subnets.
		"group_base_subnet_ipv6": "fd00::/48",
		// group_subnet_ipv6_bits is the IPv6 prefix length per group.
		"group_subnet_ipv6_bits": "64",
		// Legacy flat subnet settings kept as fallback for peers without a group.
		"client_subnet_ipv4":       "100.100.0.0/22",
		"client_subnet_ipv6":       "fd00::0:0/64",
		"enable_client_ipv6":       ipv6Default,
		"public_keys_visible":      "false",
		"endpoints_visible":        "false",
		"p2p_routing_enabled":      "true",
		"allow_custom_private_key": "true",
		"e2e_encryption_enabled":   "true",
		"global_mtu":               "1420",
		// Canonical YAML Toggles
		"yaml_l3_forwarding":            "true",
		"yaml_block_rfc":                "true",
		"yaml_host_forward_redirect_ip": "127.0.0.1",
		"yaml_socks5_port":              "1080",
		"yaml_http_port":                "8118",
		"yaml_proxy_username":           "",
		"yaml_proxy_password":           "",
		"yaml_inbound_transparent":      "true",
		"yaml_socks5_udp":               "true",
		"custom_yaml_enabled":           "false",
		"custom_yaml":                   "",
		"acl_inbound_default":           "allow",
		"acl_outbound_default":          "allow",
		"acl_relay_default":             "deny",
		// #! directives included in downloaded client configs
		"client_config_tcp":           "",
		"client_config_turn_url":      "",
		"client_config_skipverifytls": "",
		"client_config_url":           "",
		// Routes pushed to clients (AllowedIPs for the server peer entry)
		"client_allowed_ips": "0.0.0.0/0, ::/0",
		// Reverse-proxy and browser access settings
		"trusted_proxy_cidrs":         "",
		"web_base_url":                "",
		"http_proxy_access_enabled":   "false",
		"socket_proxy_enabled":        "false",
		"socket_proxy_http_port":      strconv.Itoa(findFreePort()),
		"exposed_services_enabled":    "true",
		"service_auth_cookie_seconds": strconv.Itoa(int((12 * time.Hour).Seconds())),
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

	bootstrapBuiltInGroups()
}

// bootstrapBuiltInGroups ensures the "default" and "admin" built-in groups
// exist. Called once during init. Existing users/peers with no PrimaryGroup
// are assigned to "default".
func bootstrapBuiltInGroups() {
	// Ensure "default" group exists with the first auto-assigned subnet.
	var defaultGroup Group
	if gdb.First(&defaultGroup, "name = ?", "default").Error != nil {
		subnet, subnetV6 := nextAvailableGroupSubnet()
		defaultGroup = Group{
			Name:       "default",
			Subnet:     subnet,
			SubnetIPv6: subnetV6,
			BuiltIn:    true,
		}
		gdb.Create(&defaultGroup)
	}

	// Ensure "admin" group exists (no subnet — it is a role group).
	var adminGroup Group
	if gdb.First(&adminGroup, "name = ?", "admin").Error != nil {
		adminGroup = Group{Name: "admin", BuiltIn: true}
		gdb.Create(&adminGroup)
	}

	// Migrate existing users: assign primary group and sync admin group membership.
	var users []User
	gdb.Find(&users)
	for _, u := range users {
		changed := false
		if u.PrimaryGroup == "" {
			u.PrimaryGroup = "default"
			changed = true
		}
		// Sync IsAdmin → "admin" group membership in Tags.
		groups := splitCSVList(u.Tags)
		hasAdmin := containsToken(groups, "admin")
		if u.IsAdmin && !hasAdmin {
			groups = append(groups, "admin")
			u.Tags = normalizeGroupList(groups)
			changed = true
		}
		if hasAdmin && !u.IsAdmin {
			u.IsAdmin = true
			changed = true
		}
		if changed {
			gdb.Save(&u)
		}
	}

	// Migrate existing peers: assign primary group from user.
	var peers []Peer
	gdb.Find(&peers)
	for _, p := range peers {
		if p.PrimaryGroup != "" {
			continue
		}
		var owner User
		if gdb.First(&owner, p.UserID).Error == nil && owner.PrimaryGroup != "" {
			p.PrimaryGroup = owner.PrimaryGroup
		} else {
			p.PrimaryGroup = "default"
		}
		gdb.Save(&p)
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
		token := bearerTokenFromRequest(r)
		if token == "" {
			log.Printf("Auth failed: Missing token for %s %s from %s", r.Method, r.URL.Path, clientIPForRequest(r))
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		var user User
		if err := gdb.First(&user, "token = ?", token).Error; err != nil {
			log.Printf("Auth failed: Invalid token %q for %s %s from %s: %v", token, r.Method, r.URL.Path, clientIPForRequest(r), err)
			http.Error(w, "Invalid Token", http.StatusUnauthorized)
			return
		}

		r.Header.Set("X-User-Id", fmt.Sprint(user.ID))
		r.Header.Set("X-Is-Admin", fmt.Sprint(userIsAdmin(user)))
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
		TOTPCode string `json:"totp_code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	var user User
	if err := gdb.First(&user, "username = ?", req.Username).Error; err != nil {
		log.Printf("Login failed: user %q not found from %s", req.Username, clientIPForRequest(r))
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if !verifyPassword(req.Password, user.PasswordHash) {
		log.Printf("Login failed for user %q from %s: wrong password", req.Username, clientIPForRequest(r))
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if user.TOTPEnabled {
		if strings.TrimSpace(req.TOTPCode) == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"requires_2fa": true})
			return
		}
		if !verifyTOTPCode(decryptAtRest(user.TOTPSecret), req.TOTPCode, time.Now()) {
			log.Printf("Login failed for user %q from %s: invalid 2FA code", req.Username, clientIPForRequest(r))
			http.Error(w, "Invalid two-factor code", http.StatusUnauthorized)
			return
		}
	}

	token := issueUserToken(w, &user)

	log.Printf("User %q logged in successfully from %s", req.Username, clientIPForRequest(r))
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
		Tags                string     `json:"tags"`
		Groups              string     `json:"groups"`
		PublicKey           string     `json:"public_key"`
		NonceHash           string     `json:"nonce_hash"`
		EncryptedPrivateKey string     `json:"encrypted_private_key"`
		RequestedIP         string     `json:"requested_ip,omitempty"`
		Keepalive           int        `json:"keepalive"`
		StaticEndpoint      string     `json:"static_endpoint,omitempty"`
		IsManualKey         bool       `json:"is_manual_key"`
		ExpiresAt           *time.Time `json:"expires_at,omitempty"`
		TrafficShaper       struct {
			UploadBps     int64 `json:"upload_bps"`
			DownloadBps   int64 `json:"download_bps"`
			LatencyMillis int   `json:"latency_ms"`
		} `json:"traffic_shaper"`
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

	// Determine the primary group from the owner user (immutable after creation).
	var peerPrimaryGroup string
	if gdb.First(&user, userID).Error == nil {
		peerPrimaryGroup = user.PrimaryGroup
	}
	if peerPrimaryGroup == "" {
		peerPrimaryGroup = "default"
	}

	// Determine IP Address
	var assignedIP string
	if req.RequestedIP != "" && isAdmin {
		assignedIP = req.RequestedIP
	} else {
		var err error
		assignedIP, err = allocateIPInGroup(peerPrimaryGroup)
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
		PrimaryGroup:        peerPrimaryGroup,
		Tags:                normalizeGroupList(append(splitCSVList(user.Tags), append(splitCSVList(req.Tags), splitCSVList(req.Groups)...)...)),
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
		TrafficUploadBps:    req.TrafficShaper.UploadBps,
		TrafficDownloadBps:  req.TrafficShaper.DownloadBps,
		TrafficLatencyMs:    req.TrafficShaper.LatencyMillis,
	}

	if err := gdb.Create(&peer).Error; err != nil {
		log.Printf("Failed to save peer: %v", err)
		http.Error(w, "Failed to save peer (public key must be unique)", http.StatusInternalServerError)
		return
	}

	// Update expanded ACLs before returning the new config material.
	pushACLsToDaemon()

	// Sync directly to uwgsocks API
	pushPeerToDaemon(peer)

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
	st := fetchDaemonStatus()
	trafficPeers := make([]Peer, 0, len(st.Peers))
	for _, p := range st.Peers {
		peer := Peer{
			PublicKey:            p.PublicKey,
			EndpointIP:           p.EndpointIP,
			LastHandshakeTime:    p.LastHandshakeTime,
			TransmitBytes:        p.TransmitBytes,
			ReceiveBytes:         p.ReceiveBytes,
			HasHandshake:         p.HasHandshake,
			TransportName:        p.TransportName,
			TransportState:       p.TransportState,
			TransportEndpoint:    p.TransportEndpoint,
			TransportSourceAddr:  p.TransportSourceAddr,
			TransportCarrierAddr: p.TransportCarrierRemoteAddr,
		}
		trafficPeers = append(trafficPeers, peer)
		statsMap[p.PublicKey] = peer
	}
	trafficHistory.Record(trafficPeers, time.Now())

	// Auto-persist last-seen endpoint for distribute peers
	go func() {
		for pubKey, stat := range statsMap {
			if stat.EndpointIP == "" {
				continue
			}
			var dbPeer Peer
			if err := gdb.First(&dbPeer, "public_key = ? AND is_distribute = ?", pubKey, true).Error; err != nil {
				continue
			}
			// Only auto-update if DistributeEndpoint is empty (not manually overridden)
			if dbPeer.DistributeEndpoint == "" {
				gdb.Model(&dbPeer).Update("distribute_endpoint", stat.EndpointIP)
			}
		}
	}()

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
			p.TransportName = stat.TransportName
			p.TransportState = stat.TransportState
			p.TransportEndpoint = stat.TransportEndpoint
			p.TransportSourceAddr = stat.TransportSourceAddr
			p.TransportCarrierAddr = stat.TransportCarrierAddr
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
	generateCanonicalYAML()
	pushACLsToDaemon()
	w.WriteHeader(http.StatusOK)
}

type DistributePeerInfo struct {
	PublicKey  string `json:"public_key"`
	AllowedIPs string `json:"allowed_ips"`
	Endpoint   string `json:"endpoint"`
	Name       string `json:"name"`
}

func getDistributePeers() []DistributePeerInfo {
	var peers []Peer
	gdb.Where("is_distribute = ? AND enabled = ?", true, true).Find(&peers)
	var result []DistributePeerInfo
	for _, p := range peers {
		ep := p.DistributeEndpoint
		if ep == "" {
			ep = p.EndpointIP
		}
		result = append(result, DistributePeerInfo{
			PublicKey:  p.PublicKey,
			AllowedIPs: p.AssignedIPs,
			Endpoint:   ep,
			Name:       p.Name,
		})
	}
	return result
}

func handleGetDistributePeers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	peers := getDistributePeers()
	if peers == nil {
		peers = []DistributePeerInfo{}
	}
	json.NewEncoder(w).Encode(peers)
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
		Name               *string    `json:"name"`
		Tags               *string    `json:"tags"`
		Groups             *string    `json:"groups"`
		AssignedIPs        *string    `json:"assigned_ips"`
		Keepalive          *int       `json:"keepalive"`
		Enabled            *bool      `json:"enabled"`
		StaticEndpoint     *string    `json:"static_endpoint"`
		ExpiresAt          *time.Time `json:"expires_at"`
		IsDistribute       *bool      `json:"is_distribute"`
		DistributeEndpoint *string    `json:"distribute_endpoint"`
		TrafficShaper      *struct {
			UploadBps     int64 `json:"upload_bps"`
			DownloadBps   int64 `json:"download_bps"`
			LatencyMillis int   `json:"latency_ms"`
		} `json:"traffic_shaper"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	if req.Name != nil {
		peer.Name = *req.Name
	}
	aclNeedsRefresh := false
	if req.Groups != nil && isAdmin {
		peer.Tags = normalizeGroupList(splitCSVList(*req.Groups))
		aclNeedsRefresh = true
	} else if req.Tags != nil && isAdmin {
		peer.Tags = normalizeGroupList(splitCSVList(*req.Tags))
		aclNeedsRefresh = true
	}
	if req.AssignedIPs != nil && isAdmin {
		peer.AssignedIPs = *req.AssignedIPs
		aclNeedsRefresh = true
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
	if req.IsDistribute != nil && isAdmin {
		peer.IsDistribute = *req.IsDistribute
	}
	if req.DistributeEndpoint != nil && isAdmin {
		peer.DistributeEndpoint = *req.DistributeEndpoint
	}
	if req.TrafficShaper != nil && isAdmin {
		peer.TrafficUploadBps = req.TrafficShaper.UploadBps
		peer.TrafficDownloadBps = req.TrafficShaper.DownloadBps
		peer.TrafficLatencyMs = req.TrafficShaper.LatencyMillis
	}

	gdb.Save(&peer)
	if aclNeedsRefresh {
		pushACLsToDaemon()
	}

	if peer.Enabled && (peer.ExpiresAt == nil || peer.ExpiresAt.After(time.Now())) {
		pushPeerToDaemon(peer)
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
		Username     string `json:"username"`
		Password     string `json:"password"`
		IsAdmin      bool   `json:"is_admin"`
		Tags         string `json:"tags"`   // legacy field
		Groups       string `json:"groups"` // additional groups
		PrimaryGroup string `json:"primary_group"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Merge legacy tags + groups fields.
	additionalGroups := req.Groups
	if additionalGroups == "" {
		additionalGroups = req.Tags
	}

	// Default primary group to "default".
	primaryGroup := normalizeGroupName(req.PrimaryGroup)
	if primaryGroup == "" {
		primaryGroup = "default"
	}
	if _, ok := primaryGroupExists(primaryGroup); !ok {
		http.Error(w, "Primary group must exist and have a subnet", http.StatusBadRequest)
		return
	}

	// The admin group is authoritative; the is_admin flag is accepted for legacy clients.
	groups := splitCSVList(additionalGroups)
	if req.IsAdmin && !containsToken(groups, "admin") {
		groups = append(groups, "admin")
	}
	isAdmin := req.IsAdmin || containsToken(groups, "admin")

	hp, _ := hashPassword(req.Password)
	user := User{
		Username:     req.Username,
		PasswordHash: hp,
		IsAdmin:      isAdmin,
		PrimaryGroup: primaryGroup,
		Tags:         normalizeGroupList(groups),
	}
	if err := gdb.Create(&user).Error; err != nil {
		http.Error(w, "Username already exists", http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var user User
	if err := gdb.First(&user, id).Error; err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	var req struct {
		Tags         *string `json:"tags"` // legacy
		Groups       *string `json:"groups"`
		PrimaryGroup *string `json:"primary_group"`
		IsAdmin      *bool   `json:"is_admin"`
		MaxConfigs   *int    `json:"max_configs"`
		Password     *string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	// Accept both "groups" and legacy "tags" for the additional groups field.
	if req.Groups != nil {
		user.Tags = normalizeGroupList(splitCSVList(*req.Groups))
	} else if req.Tags != nil {
		user.Tags = normalizeGroupList(splitCSVList(*req.Tags))
	}
	if req.PrimaryGroup != nil {
		pg := normalizeGroupName(*req.PrimaryGroup)
		if pg != "" {
			if _, ok := primaryGroupExists(pg); !ok {
				http.Error(w, "Primary group must exist and have a subnet", http.StatusBadRequest)
				return
			}
			user.PrimaryGroup = pg
		}
	}
	if req.IsAdmin != nil {
		user.IsAdmin = *req.IsAdmin
		// Sync admin group membership.
		groups := splitCSVList(user.Tags)
		hasAdmin := containsToken(groups, "admin")
		if *req.IsAdmin && !hasAdmin {
			groups = append(groups, "admin")
			user.Tags = normalizeGroupList(groups)
		} else if !*req.IsAdmin && hasAdmin {
			newGroups := make([]string, 0, len(groups))
			for _, g := range groups {
				if !strings.EqualFold(g, "admin") {
					newGroups = append(newGroups, g)
				}
			}
			user.Tags = normalizeGroupList(newGroups)
		}
	}
	user.IsAdmin = containsToken(userGroups(user), "admin")
	if user.ID == 1 && !user.IsAdmin {
		groups := splitCSVList(user.Tags)
		if !containsToken(groups, "admin") {
			groups = append(groups, "admin")
		}
		user.Tags = normalizeGroupList(groups)
		user.IsAdmin = true
	}
	if req.MaxConfigs != nil {
		user.MaxConfigs = *req.MaxConfigs
	}
	if req.Password != nil && strings.TrimSpace(*req.Password) != "" {
		if user.OIDCSubject != nil {
			http.Error(w, "Cannot set password for OIDC user", http.StatusBadRequest)
			return
		}
		hp, err := hashPassword(*req.Password)
		if err != nil {
			http.Error(w, "Failed to hash password", http.StatusInternalServerError)
			return
		}
		user.PasswordHash = hp
	}
	gdb.Save(&user)
	generateCanonicalYAML()
	pushACLsToDaemon()
	w.WriteHeader(http.StatusOK)
}

func handleAdminDeleteUserTOTP(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var user User
	if err := gdb.First(&user, id).Error; err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	gdb.Model(&user).Updates(map[string]interface{}{"totp_enabled": false, "totp_secret": ""})
	w.WriteHeader(http.StatusNoContent)
}

func handleUpdateMe(w http.ResponseWriter, r *http.Request) {
	user, ok := currentUserFromRequest(w, r)
	if !ok {
		return
	}
	var req struct {
		Password    *string `json:"password"`
		OldPassword *string `json:"old_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	if req.Password != nil {
		if user.OIDCSubject != nil {
			http.Error(w, "Cannot set password for OIDC account", http.StatusBadRequest)
			return
		}
		if req.OldPassword == nil || !verifyPassword(*req.OldPassword, user.PasswordHash) {
			http.Error(w, "Current password is incorrect", http.StatusUnauthorized)
			return
		}
		hp, err := hashPassword(*req.Password)
		if err != nil {
			http.Error(w, "Failed to hash password", http.StatusInternalServerError)
			return
		}
		gdb.Model(&user).Update("password_hash", hp)
	}
	w.WriteHeader(http.StatusNoContent)
}

func handleGetMyProxyCredentials(w http.ResponseWriter, r *http.Request) {
	user, ok := currentUserFromRequest(w, r)
	if !ok {
		return
	}
	var creds []AccessProxyCredential
	gdb.Where("user_id = ?", user.ID).Find(&creds)
	w.Header().Set("Content-Type", "application/json")
	if creds == nil {
		creds = []AccessProxyCredential{}
	}
	json.NewEncoder(w).Encode(creds)
}

func handleCreateMyProxyCredential(w http.ResponseWriter, r *http.Request) {
	user, ok := currentUserFromRequest(w, r)
	if !ok {
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		req.Name = "Proxy access"
	}
	// Re-use the existing admin credential creation logic
	b := make([]byte, 16)
	rand.Read(b)
	rawPw := hex.EncodeToString(b)
	hp, err := hashPassword(rawPw)
	if err != nil {
		http.Error(w, "Failed to create credential", http.StatusInternalServerError)
		return
	}
	username := fmt.Sprintf("u%d-%s", user.ID, hex.EncodeToString(b[:4]))
	cred := AccessProxyCredential{
		UserID:       user.ID,
		Username:     username,
		PasswordHash: hp,
		Name:         req.Name,
		Enabled:      true,
	}
	if err := gdb.Create(&cred).Error; err != nil {
		http.Error(w, "Failed to create credential", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":       cred.ID,
		"username": cred.Username,
		"password": rawPw,
		"name":     cred.Name,
	})
}

func handleDeleteMyProxyCredential(w http.ResponseWriter, r *http.Request) {
	user, ok := currentUserFromRequest(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	result := gdb.Where("id = ? AND user_id = ?", id, user.ID).Delete(&AccessProxyCredential{})
	if result.RowsAffected == 0 {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "1" {
		http.Error(w, "Cannot delete primary admin", http.StatusForbidden)
		return
	}
	gdb.Delete(&User{}, id)
	generateCanonicalYAML()
	pushACLsToDaemon()
	w.WriteHeader(http.StatusOK)
}

func handleGetTags(w http.ResponseWriter, r *http.Request) {
	var groups []Group
	gdb.Order("name asc").Find(&groups)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(groups)
}

func handleCreateTag(w http.ResponseWriter, r *http.Request) {
	var tag Group
	if err := json.NewDecoder(r.Body).Decode(&tag); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	tag.Name = normalizeGroupName(tag.Name)
	tag.ExtraCIDRs = joinCSVList(splitCSVList(tag.ExtraCIDRs))
	tag.ParentGroups = normalizeGroupList(splitCSVList(tag.ParentGroups))
	if tag.Name == "" {
		http.Error(w, "Group name is required", http.StatusBadRequest)
		return
	}
	// If the caller requested a subnet but didn't supply one, auto-assign.
	// If they supplied an empty Subnet explicitly, the group is non-primary-capable.
	// If they didn't supply Subnet at all, it defaults to empty string (non-primary-capable).
	// To auto-assign, the caller sends subnet="auto".
	if strings.ToLower(strings.TrimSpace(tag.Subnet)) == "auto" {
		s, sv6 := nextAvailableGroupSubnet()
		tag.Subnet = s
		if tag.SubnetIPv6 == "" {
			tag.SubnetIPv6 = sv6
		}
	}
	// Subnet is fixed after creation — ensure it's stored normalized.
	if tag.Subnet != "" {
		p, err := netip.ParsePrefix(tag.Subnet)
		if err != nil {
			http.Error(w, "Invalid subnet: "+err.Error(), http.StatusBadRequest)
			return
		}
		if !p.Addr().Is4() {
			http.Error(w, "Group subnet must be IPv4", http.StatusBadRequest)
			return
		}
		tag.Subnet = p.Masked().String()
	}
	if tag.SubnetIPv6 != "" {
		p, err := netip.ParsePrefix(tag.SubnetIPv6)
		if err != nil {
			http.Error(w, "Invalid IPv6 subnet: "+err.Error(), http.StatusBadRequest)
			return
		}
		if !p.Addr().Is6() || p.Addr().Is4() {
			http.Error(w, "Group IPv6 subnet must be IPv6", http.StatusBadRequest)
			return
		}
		tag.SubnetIPv6 = p.Masked().String()
	}
	if err := validateGroupGraph(&tag); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := gdb.Create(&tag).Error; err != nil {
		http.Error(w, "Group already exists", http.StatusConflict)
		return
	}
	generateCanonicalYAML()
	pushACLsToDaemon()
	w.WriteHeader(http.StatusCreated)
}

func handleUpdateTag(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var tag Group
	if err := gdb.First(&tag, id).Error; err != nil {
		http.Error(w, "Group not found", http.StatusNotFound)
		return
	}
	var req Group
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	// Built-in groups keep their names; others can be renamed.
	if !tag.BuiltIn && strings.TrimSpace(req.Name) != "" {
		tag.Name = normalizeGroupName(req.Name)
	}
	tag.ExtraCIDRs = joinCSVList(splitCSVList(req.ExtraCIDRs))
	tag.ParentGroups = normalizeGroupList(splitCSVList(req.ParentGroups))
	// Subnet is immutable after creation — silently ignore changes.
	if err := validateGroupGraph(&tag); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := gdb.Save(&tag).Error; err != nil {
		http.Error(w, "Failed to update group", http.StatusConflict)
		return
	}
	generateCanonicalYAML()
	pushACLsToDaemon()
	w.WriteHeader(http.StatusOK)
}

func handleDeleteTag(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var tag Group
	if gdb.First(&tag, id).Error == nil && tag.BuiltIn {
		http.Error(w, "Cannot delete built-in group", http.StatusForbidden)
		return
	}
	if tag.Name != "" {
		var userCount int64
		gdb.Model(&User{}).Where("primary_group = ?", tag.Name).Count(&userCount)
		var peerCount int64
		gdb.Model(&Peer{}).Where("primary_group = ?", tag.Name).Count(&peerCount)
		if userCount > 0 || peerCount > 0 {
			http.Error(w, "Cannot delete a group used as a primary group", http.StatusConflict)
			return
		}
	}
	gdb.Delete(&Group{}, id)
	generateCanonicalYAML()
	pushACLsToDaemon()
	w.WriteHeader(http.StatusNoContent)
}

func handleGetACLs(w http.ResponseWriter, r *http.Request) {
	var acls []ACLRule
	gdb.Order("sort_order asc, id asc").Find(&acls)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(acls)
}

func normalizeACLRule(a *ACLRule) {
	a.Src = joinCSVList(splitCSVList(a.Src))
	a.SrcUsers = joinCSVList(splitCSVList(a.SrcUsers))
	a.SrcTags = joinCSVList(splitCSVList(a.SrcTags))
	a.SrcPeers = joinCSVList(splitCSVList(a.SrcPeers))
	a.Dst = joinCSVList(splitCSVList(a.Dst))
	a.DstUsers = joinCSVList(splitCSVList(a.DstUsers))
	a.DstTags = joinCSVList(splitCSVList(a.DstTags))
	a.DstPeers = joinCSVList(splitCSVList(a.DstPeers))
}

func handleCreateACL(w http.ResponseWriter, r *http.Request) {
	var a ACLRule
	if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	normalizeACLRule(&a)
	// Assign sort_order = max + 1
	var maxOrder int
	gdb.Model(&ACLRule{}).Where("list_name = ?", a.ListName).Select("COALESCE(MAX(sort_order), -1)").Scan(&maxOrder)
	a.SortOrder = maxOrder + 1
	gdb.Create(&a)
	pushACLsToDaemon()
	w.WriteHeader(http.StatusCreated)
}

func handleUpdateACL(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var a ACLRule
	if err := gdb.First(&a, id).Error; err != nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}
	if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	normalizeACLRule(&a)
	gdb.Save(&a)
	pushACLsToDaemon()
	w.WriteHeader(http.StatusOK)
}

func handleDeleteACL(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	gdb.Delete(&ACLRule{}, id)
	pushACLsToDaemon()
	w.WriteHeader(http.StatusOK)
}

func handleReorderACLs(w http.ResponseWriter, r *http.Request) {
	var req []struct {
		ID        uint `json:"id"`
		SortOrder int  `json:"sort_order"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	for _, item := range req {
		gdb.Model(&ACLRule{}).Where("id = ?", item.ID).Update("sort_order", item.SortOrder)
	}
	pushACLsToDaemon()
	w.WriteHeader(http.StatusOK)
}

func handleACLTokenSearch(w http.ResponseWriter, r *http.Request) {
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	type token struct {
		Type  string `json:"type"`
		Value string `json:"value"`
		Label string `json:"label"`
	}
	var results []token

	// Users
	var users []User
	gdb.Order("username asc").Find(&users)
	for _, u := range users {
		if q == "" || strings.Contains(strings.ToLower(u.Username), q) {
			results = append(results, token{"user", u.Username, u.Username})
		}
	}

	// Groups
	var groups []Group
	gdb.Order("name asc").Find(&groups)
	for _, g := range groups {
		label := g.Name
		if g.Subnet != "" {
			label = g.Name + " (" + g.Subnet + ")"
		}
		if q == "" || strings.Contains(strings.ToLower(g.Name), q) {
			results = append(results, token{"tag", g.Name, label})
		}
	}

	// Peers
	var peers []Peer
	gdb.Order("name asc").Find(&peers)
	for _, p := range peers {
		if q == "" || strings.Contains(strings.ToLower(p.Name), q) {
			label := p.Name
			if p.AssignedIPs != "" {
				label = p.Name + " (" + p.AssignedIPs + ")"
			}
			results = append(results, token{"peer", p.Name, label})
		}
	}

	// If query looks like a CIDR or IP, include it as a suggestion
	if q != "" {
		if _, _, err := net.ParseCIDR(q); err == nil {
			results = append(results, token{"cidr", q, q})
		} else if net.ParseIP(q) != nil {
			results = append(results, token{"cidr", q, q})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if results == nil {
		results = []token{}
	}
	json.NewEncoder(w).Encode(results)
}

func handleGetForwards(w http.ResponseWriter, r *http.Request) {
	var fwds []TunnelForward
	gdb.Order("sort_order asc, id asc").Find(&fwds)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(fwds)
}

func handleCreateForward(w http.ResponseWriter, r *http.Request) {
	var f TunnelForward
	if err := json.NewDecoder(r.Body).Decode(&f); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	if f.Proto == "" || f.Listen == "" || f.Target == "" {
		http.Error(w, "proto, listen, and target are required", http.StatusBadRequest)
		return
	}
	var maxOrder int
	gdb.Model(&TunnelForward{}).Select("COALESCE(MAX(sort_order), -1)").Scan(&maxOrder)
	f.ID = 0
	f.RuntimeName = ""
	f.SortOrder = maxOrder + 1
	if err := gdb.Create(&f).Error; err != nil {
		http.Error(w, "Failed to save forward", http.StatusInternalServerError)
		return
	}
	generateCanonicalYAML()
	if runtimeName, err := pushForwardToDaemon(f); err != nil {
		log.Printf("Live forward push failed (%s -> %s), falling back to restart: %v", f.Listen, f.Target, err)
		go restartManagedDaemonIfEnabled()
	} else {
		f.RuntimeName = runtimeName
		gdb.Model(&f).Update("runtime_name", runtimeName)
	}
	w.WriteHeader(http.StatusCreated)
}

func handleUpdateForward(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var existing TunnelForward
	if err := gdb.First(&existing, id).Error; err != nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}
	var req TunnelForward
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	if req.Proto == "" || req.Listen == "" || req.Target == "" {
		http.Error(w, "proto, listen, and target are required", http.StatusBadRequest)
		return
	}
	f := existing
	f.Name = req.Name
	f.Reverse = req.Reverse
	f.Proto = req.Proto
	f.Listen = req.Listen
	f.Target = req.Target
	f.ProxyProtocol = req.ProxyProtocol
	f.SortOrder = req.SortOrder
	if f.SortOrder == 0 && existing.SortOrder != 0 {
		f.SortOrder = existing.SortOrder
	}
	oldRuntimeName := findDaemonForwardName(existing)
	f.RuntimeName = ""
	if err := gdb.Save(&f).Error; err != nil {
		http.Error(w, "Failed to save forward", http.StatusInternalServerError)
		return
	}
	generateCanonicalYAML()
	if runtimeName, err := applyForwardChangeLive(oldRuntimeName, f); err != nil {
		log.Printf("Live forward update failed (%s -> %s), falling back to restart: %v", f.Listen, f.Target, err)
		go restartManagedDaemonIfEnabled()
	} else {
		f.RuntimeName = runtimeName
		gdb.Model(&f).Update("runtime_name", runtimeName)
	}
	w.WriteHeader(http.StatusOK)
}

func handleDeleteForward(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var f TunnelForward
	if err := gdb.First(&f, id).Error; err != nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}
	runtimeName := findDaemonForwardName(f)
	gdb.Delete(&TunnelForward{}, id)
	generateCanonicalYAML()
	if err := removeForwardFromDaemon(runtimeName); err != nil {
		log.Printf("Live forward delete failed (%s), falling back to restart: %v", runtimeName, err)
		go restartManagedDaemonIfEnabled()
	}
	w.WriteHeader(http.StatusOK)
}

func handleGetTransports(w http.ResponseWriter, r *http.Request) {
	var ts []TransportConfig
	gdb.Find(&ts)
	runtime := fetchDaemonStatus()
	runtimeByName := make(map[string]daemonTransportSnapshot, len(runtime.Transports))
	for _, rt := range runtime.Transports {
		runtimeByName[rt.Name] = rt
	}
	for i := range ts {
		if rt, ok := runtimeByName[ts[i].Name]; ok {
			ts[i].ActiveSessions = rt.ActiveSessions
			ts[i].Connected = rt.Connected
			ts[i].CarrierProtocol = rt.CarrierProtocol
			ts[i].CarrierLocalAddr = rt.CarrierLocalAddr
			ts[i].CarrierRemoteAddr = rt.CarrierRemoteAddr
			ts[i].RelayAddr = rt.RelayAddr
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ts)
}

func handleCreateTransport(w http.ResponseWriter, r *http.Request) {
	var t TransportConfig
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil || t.Name == "" || t.Base == "" {
		http.Error(w, "Invalid request: name and base are required", http.StatusBadRequest)
		return
	}
	t.ID = 0
	if err := gdb.Create(&t).Error; err != nil {
		http.Error(w, "Transport name already exists", http.StatusConflict)
		return
	}
	generateCanonicalYAML()
	go applyTransportChangeLive("", t)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(t)
}

func handleUpdateTransport(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var t TransportConfig
	if err := gdb.First(&t, id).Error; err != nil {
		http.Error(w, "Transport not found", http.StatusNotFound)
		return
	}
	oldName := t.Name
	var req TransportConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	req.ID = t.ID
	if err := gdb.Save(&req).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	generateCanonicalYAML()
	go applyTransportChangeLive(oldName, req)
	w.WriteHeader(http.StatusOK)
}

func handleDeleteTransport(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var t TransportConfig
	if err := gdb.First(&t, id).Error; err == nil {
		gdb.Delete(&TransportConfig{}, id)
		generateCanonicalYAML()
		go func() { removeTransportFromDaemon(t.Name) }()
	}
	w.WriteHeader(http.StatusOK)
}

// getTransportsConfig returns the transports section for the canonical YAML.
func getTransportsConfig() []map[string]interface{} {
	var ts []TransportConfig
	gdb.Find(&ts)
	var out []map[string]interface{}
	for _, t := range ts {
		base := t.Base
		if strings.EqualFold(base, "udp") && strings.EqualFold(t.ProxyType, "turn") {
			base = "turn"
		}
		m := map[string]interface{}{
			"name":   t.Name,
			"base":   base,
			"listen": t.Listen,
		}
		if t.ListenPort > 0 {
			m["listen_port"] = t.ListenPort
		}
		if t.ListenAddrs != "" {
			var addrs []string
			for _, a := range strings.Split(t.ListenAddrs, ",") {
				if a = strings.TrimSpace(a); a != "" {
					addrs = append(addrs, a)
				}
			}
			if len(addrs) > 0 {
				m["listen_addresses"] = addrs
			}
		}
		if t.URL != "" {
			m["url"] = t.URL
		}
		if t.WSPath != "" || t.ConnectHost != "" || t.HostHeader != "" {
			ws := map[string]interface{}{}
			if t.WSPath != "" {
				ws["path"] = t.WSPath
			}
			if t.ConnectHost != "" {
				ws["connect_host"] = t.ConnectHost
			}
			if t.HostHeader != "" {
				ws["host_header"] = t.HostHeader
			}
			m["websocket"] = ws
		}
		tls := map[string]interface{}{}
		if t.TLSCertFile != "" {
			tls["cert_file"] = t.TLSCertFile
		}
		if t.TLSKeyFile != "" {
			tls["key_file"] = t.TLSKeyFile
		}
		if t.TLSCAFile != "" {
			tls["ca_file"] = t.TLSCAFile
		}
		if t.TLSVerifyPeer {
			tls["verify_peer"] = true
		}
		if t.TLSServerSNI != "" {
			tls["server_sni"] = t.TLSServerSNI
		}
		if len(tls) > 0 {
			m["tls"] = tls
		}
		if strings.EqualFold(base, "turn") {
			turnCfg := map[string]interface{}{
				"server": t.TurnServer,
			}
			if strings.EqualFold(t.ProxyType, "turn") {
				turnCfg["server"] = t.ProxyServer
				if t.ProxyUsername != "" {
					turnCfg["username"] = t.ProxyUsername
					turnCfg["password"] = t.ProxyPassword
				}
			} else {
				if t.TurnUsername != "" {
					turnCfg["username"] = t.TurnUsername
					turnCfg["password"] = t.TurnPassword
				}
			}
			if t.TurnRealm != "" {
				turnCfg["realm"] = t.TurnRealm
			}
			if t.TurnProtocol != "" {
				turnCfg["protocol"] = t.TurnProtocol
			}
			if t.TurnNoCreatePermission {
				turnCfg["no_create_permission"] = true
			}
			if t.TurnIncludeWGPublicKey {
				turnCfg["include_wg_public_key"] = true
			}
			if strings.TrimSpace(t.TurnPermissions) != "" {
				var permissions []string
				for _, p := range strings.Split(t.TurnPermissions, ",") {
					if p = strings.TrimSpace(p); p != "" {
						permissions = append(permissions, p)
					}
				}
				if len(permissions) > 0 {
					turnCfg["permissions"] = permissions
				}
			}
			if len(tls) > 0 {
				turnCfg["tls"] = tls
				delete(m, "tls")
			}
			m["turn"] = turnCfg
		}
		if t.ProxyType != "" && t.ProxyType != "none" && !strings.EqualFold(t.ProxyType, "turn") {
			proxy := map[string]interface{}{"type": t.ProxyType}
			switch t.ProxyType {
			case "socks5":
				s := map[string]interface{}{"server": t.ProxyServer}
				if t.ProxyUsername != "" {
					s["username"] = t.ProxyUsername
					s["password"] = t.ProxyPassword
				}
				proxy["socks5"] = s
			case "http":
				h := map[string]interface{}{"server": t.ProxyServer}
				if t.ProxyUsername != "" {
					h["username"] = t.ProxyUsername
					h["password"] = t.ProxyPassword
				}
				proxy["http"] = h
			}
			m["proxy"] = proxy
		}
		out = append(out, m)
	}
	return out
}

func getACLConfig() map[string]interface{} {
	getRules := func(list string) []map[string]interface{} {
		var rules []ACLRule
		gdb.Where("list_name = ?", list).Order("sort_order asc, id asc").Find(&rules)
		var out []map[string]interface{}
		for _, r := range rules {
			sources := expandACLRuleSources(r)
			dests := expandACLRuleDests(r)
			if len(sources) == 0 {
				sources = []string{""}
			}
			if len(dests) == 0 {
				dests = []string{""}
			}
			for _, src := range sources {
				for _, dst := range dests {
					out = append(out, aclRuleMap(r, src, dst))
				}
			}
		}
		return out
	}

	acl := map[string]interface{}{
		"inbound_default":  strings.ToLower(strings.TrimSpace(getConfig("acl_inbound_default"))),
		"outbound_default": strings.ToLower(strings.TrimSpace(getConfig("acl_outbound_default"))),
		"relay_default":    strings.ToLower(strings.TrimSpace(getConfig("acl_relay_default"))),
		"inbound":          getRules("inbound"),
		"outbound":         getRules("outbound"),
		"relay":            getRules("relay"),
	}
	for _, key := range []string{"inbound_default", "outbound_default", "relay_default"} {
		if acl[key] != "allow" && acl[key] != "deny" {
			switch key {
			case "relay_default":
				acl[key] = "deny"
			default:
				acl[key] = "allow"
			}
		}
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

func aclRuleMap(r ACLRule, source string, dest string) map[string]interface{} {
	m := map[string]interface{}{"action": r.Action}
	if source != "" {
		m["source"] = source
	}
	if r.Proto != "" && strings.ToLower(r.Proto) != "any" {
		m["protocol"] = strings.ToUpper(r.Proto)
	}
	if dest != "" {
		m["destination"] = dest
	}
	if r.DPort != "" {
		m["destination_port"] = r.DPort
	}
	return m
}

func pushACLsToDaemon() {
	acl := getACLConfig()
	data, _ := json.Marshal(acl)
	sum := sha256.Sum256(data)
	hash := fmt.Sprintf("%x", sum[:])

	aclPushMu.Lock()
	if hash == lastPushedACLHash {
		aclPushMu.Unlock()
		return
	}
	aclPushMu.Unlock()

	resp, err := uwgRequestWithContext(context.Background(), "PUT", "/v1/acls", bytes.NewReader(data))
	if err != nil {
		log.Printf("Failed to push ACLs to daemon: %v", err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		log.Printf("Daemon returned error pushing ACLs: %d", resp.StatusCode)
		return
	}
	aclPushMu.Lock()
	lastPushedACLHash = hash
	aclPushMu.Unlock()
}

// --- IP Allocation & Logic ---

// nextAvailableGroupSubnet finds the next free subnet block in the configured
// group base pool. Returns empty strings if the pool is exhausted or misconfigured.
func nextAvailableGroupSubnet() (subnetV4, subnetV6 string) {
	base := getConfig("group_base_subnet")
	bitsStr := getConfig("group_subnet_bits")
	bits, err := strconv.Atoi(bitsStr)
	if err != nil || base == "" {
		return "", ""
	}
	basePrefix, err := netip.ParsePrefix(base)
	if err != nil {
		return "", ""
	}
	if bits <= basePrefix.Bits() {
		return "", ""
	}

	// Collect all assigned group subnets.
	var groups []Group
	gdb.Find(&groups)
	used := map[string]bool{}
	for _, g := range groups {
		if g.Subnet != "" {
			used[g.Subnet] = true
		}
	}

	// Walk /bits blocks within the base prefix.
	addr := basePrefix.Addr()
	for {
		candidate := netip.PrefixFrom(addr, bits).Masked()
		if !basePrefix.Contains(candidate.Addr()) {
			break
		}
		if !used[candidate.String()] {
			subnetV4 = candidate.String()
			break
		}
		// Advance by 2^(128-bits) addresses.
		addr = advanceBySubnet(addr, bits)
	}

	// IPv6 counterpart.
	baseV6 := getConfig("group_base_subnet_ipv6")
	bitsV6Str := getConfig("group_subnet_ipv6_bits")
	bitsV6, err := strconv.Atoi(bitsV6Str)
	if err == nil && baseV6 != "" {
		basePrefV6, err2 := netip.ParsePrefix(baseV6)
		if err2 == nil && bitsV6 > basePrefV6.Bits() {
			usedV6 := map[string]bool{}
			for _, g := range groups {
				if g.SubnetIPv6 != "" {
					usedV6[g.SubnetIPv6] = true
				}
			}
			addrV6 := basePrefV6.Addr()
			for {
				candidate := netip.PrefixFrom(addrV6, bitsV6).Masked()
				if !basePrefV6.Contains(candidate.Addr()) {
					break
				}
				if !usedV6[candidate.String()] {
					subnetV6 = candidate.String()
					break
				}
				addrV6 = advanceBySubnet(addrV6, bitsV6)
			}
		}
	}
	return subnetV4, subnetV6
}

// advanceBySubnet moves addr forward by one prefix-sized block.
func advanceBySubnet(addr netip.Addr, bits int) netip.Addr {
	if addr.Is4() {
		if bits < 0 || bits > 32 {
			return netip.Addr{}
		}
		raw := addr.As4()
		n := binary.BigEndian.Uint32(raw[:])
		if bits < 32 {
			n += uint32(1) << uint(32-bits)
		} else {
			n++
		}
		var out [4]byte
		binary.BigEndian.PutUint32(out[:], n)
		return netip.AddrFrom4(out)
	}
	if bits < 0 || bits > 128 {
		return netip.Addr{}
	}
	step := new(big.Int).Lsh(big.NewInt(1), uint(128-bits))
	rawAddr := addr.As16()
	n := new(big.Int).SetBytes(rawAddr[:])
	n.Add(n, step)
	raw := n.FillBytes(make([]byte, 16))
	a, _ := netip.AddrFromSlice(raw)
	return a
}

// allocateIPInGroup allocates the next free /32 (IPv4) and /128 (IPv6) within
// the given group's subnet. Falls back to the global pool if the group has no
// subnet or is not found.
func allocateIPInGroup(groupName string) (string, error) {
	mu.Lock()
	defer mu.Unlock()

	// Look up the group's subnet.
	var group Group
	useGroupSubnet := false
	if groupName != "" {
		if err := gdb.First(&group, "name = ?", strings.ToLower(strings.TrimSpace(groupName))).Error; err == nil {
			useGroupSubnet = group.Subnet != ""
		}
	}

	// Build the used-IP map from all peers.
	var assignedIPs []string
	gdb.Model(&Peer{}).Pluck("assigned_ips", &assignedIPs)
	usedMap := make(map[string]bool)
	for _, u := range assignedIPs {
		for _, part := range strings.Split(u, ",") {
			ip, _, _ := strings.Cut(strings.TrimSpace(part), "/")
			usedMap[ip] = true
		}
	}

	// IPv4 allocation.
	subnetV4 := getConfig("client_subnet_ipv4")
	if useGroupSubnet {
		subnetV4 = group.Subnet
	}
	prefV4, err := netip.ParsePrefix(subnetV4)
	if err != nil {
		return "", fmt.Errorf("v4 subnet: %w", err)
	}
	v4 := ""
	addr := prefV4.Addr()
	for {
		addr = addr.Next()
		if !prefV4.Contains(addr) {
			break
		}
		sl := addr.As4()
		if sl[3] == 0 || sl[3] == 1 || sl[3] == 255 {
			continue
		}
		if !usedMap[addr.String()] {
			v4 = addr.String() + "/32"
			break
		}
	}
	if v4 == "" {
		return "", fmt.Errorf("ipv4 subnet %s exhausted", subnetV4)
	}

	// IPv6 allocation.
	subnetV6 := getConfig("client_subnet_ipv6")
	if useGroupSubnet && group.SubnetIPv6 != "" {
		subnetV6 = group.SubnetIPv6
	}
	prefV6, err := netip.ParsePrefix(subnetV6)
	if err != nil {
		return v4, nil
	}
	v6 := ""
	for i := 0; i < 10; i++ {
		suffix := make([]byte, 8)
		rand.Read(suffix)
		raw := prefV6.Addr().As16()
		copy(raw[8:], suffix)
		v6Addr, _ := netip.AddrFromSlice(raw[:])
		if !usedMap[v6Addr.String()] {
			v6 = v6Addr.String() + "/128"
			break
		}
	}
	if v6 == "" {
		return v4, nil
	}
	return v4 + ", " + v6, nil
}

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

	if v4 == "" {
		return "", errors.New("ipv4 subnet exhausted")
	}

	// Always allocate IPv6 — visibility is controlled by enable_client_ipv6, not allocation
	subnetV6 := getConfig("client_subnet_ipv6")
	prefV6, err := netip.ParsePrefix(subnetV6)
	if err != nil {
		return v4, nil
	}
	v6 := ""
	for i := 0; i < 10; i++ {
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

	if v6 == "" {
		return v4, nil
	}
	return v4 + ", " + v6, nil
}

// --- UWGSocks API & Process Management ---

func uwgRequest(method, path string, body io.Reader) (*http.Response, error) {
	return uwgRequestWithContext(context.Background(), method, path, body)
}

func pushPeerToDaemon(peer Peer) {
	var allowed []string
	for _, ip := range strings.Split(peer.AssignedIPs, ",") {
		allowed = append(allowed, strings.TrimSpace(ip))
	}
	payload := map[string]interface{}{
		"public_key":  peer.PublicKey,
		"allowed_ips": allowed,
	}
	if peer.Keepalive > 0 {
		payload["persistent_keepalive"] = peer.Keepalive
	}
	psk := decryptAtRest(peer.PresharedKey)
	if psk != "" {
		payload["preshared_key"] = psk
	}
	if peer.StaticEndpoint != "" {
		payload["endpoint"] = peer.StaticEndpoint
	}
	if peer.TrafficUploadBps > 0 || peer.TrafficDownloadBps > 0 || peer.TrafficLatencyMs > 0 {
		payload["traffic_shaper"] = map[string]interface{}{
			"upload_bps":   peer.TrafficUploadBps,
			"download_bps": peer.TrafficDownloadBps,
			"latency_ms":   peer.TrafficLatencyMs,
		}
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

// transportConfigToAPIPayload converts a DB TransportConfig to the JSON payload
// accepted by uwgsocks POST /v1/transports.
func transportConfigToAPIPayload(t TransportConfig) map[string]interface{} {
	base := t.Base
	if strings.EqualFold(base, "udp") && strings.EqualFold(t.ProxyType, "turn") {
		base = "turn"
	}
	m := map[string]interface{}{
		"name":   t.Name,
		"base":   base,
		"listen": t.Listen,
	}
	if t.ListenPort > 0 {
		p := t.ListenPort
		m["listen_port"] = &p
	}
	if t.ListenAddrs != "" {
		var addrs []string
		for _, a := range strings.Split(t.ListenAddrs, ",") {
			if a = strings.TrimSpace(a); a != "" {
				addrs = append(addrs, a)
			}
		}
		if len(addrs) > 0 {
			m["listen_addresses"] = addrs
		}
	}
	if t.URL != "" {
		m["url"] = t.URL
	}
	if t.WSPath != "" || t.ConnectHost != "" || t.HostHeader != "" {
		ws := map[string]interface{}{}
		if t.WSPath != "" {
			ws["path"] = t.WSPath
		}
		if t.HostHeader != "" {
			ws["host_header"] = t.HostHeader
		}
		m["websocket"] = ws
	}
	if t.TLSCertFile != "" || t.TLSKeyFile != "" || t.TLSCAFile != "" || t.TLSVerifyPeer || t.TLSServerSNI != "" {
		tls := map[string]interface{}{}
		if t.TLSCertFile != "" {
			tls["cert_file"] = t.TLSCertFile
		}
		if t.TLSKeyFile != "" {
			tls["key_file"] = t.TLSKeyFile
		}
		if t.TLSCAFile != "" {
			tls["ca_file"] = t.TLSCAFile
		}
		if t.TLSVerifyPeer {
			tls["verify_peer"] = true
		}
		if t.TLSServerSNI != "" {
			tls["server_sni"] = t.TLSServerSNI
		}
		if strings.EqualFold(base, "turn") {
			turnCfg := m["turn"]
			if tc, ok := turnCfg.(map[string]interface{}); ok {
				tc["tls"] = tls
			}
		} else {
			m["tls"] = tls
		}
	}
	if strings.EqualFold(base, "turn") {
		turnCfg := map[string]interface{}{}
		srv := t.TurnServer
		if srv == "" && t.ProxyServer != "" {
			srv = t.ProxyServer
		}
		if srv != "" {
			turnCfg["server"] = srv
		}
		if t.TurnUsername != "" {
			turnCfg["username"] = t.TurnUsername
			turnCfg["password"] = t.TurnPassword
		} else if t.ProxyUsername != "" {
			turnCfg["username"] = t.ProxyUsername
			turnCfg["password"] = t.ProxyPassword
		}
		if t.TurnRealm != "" {
			turnCfg["realm"] = t.TurnRealm
		}
		if t.TurnProtocol != "" {
			turnCfg["protocol"] = t.TurnProtocol
		}
		if t.TurnNoCreatePermission {
			turnCfg["no_create_permission"] = true
		}
		if t.TurnIncludeWGPublicKey {
			turnCfg["include_wg_public_key"] = true
		}
		m["turn"] = turnCfg
	} else if t.ProxyType != "" && t.ProxyType != "none" {
		proxy := map[string]interface{}{"type": t.ProxyType}
		switch t.ProxyType {
		case "socks5":
			s := map[string]interface{}{"server": t.ProxyServer}
			if t.ProxyUsername != "" {
				s["username"] = t.ProxyUsername
				s["password"] = t.ProxyPassword
			}
			proxy["socks5"] = s
		case "http":
			h := map[string]interface{}{"server": t.ProxyServer}
			if t.ProxyUsername != "" {
				h["username"] = t.ProxyUsername
				h["password"] = t.ProxyPassword
			}
			proxy["http"] = h
		}
		m["proxy"] = proxy
	}
	return m
}

func pushTransportToDaemon(t TransportConfig) error {
	payload := transportConfigToAPIPayload(t)
	b, _ := json.Marshal(payload)
	resp, err := uwgRequest("POST", "/v1/transports", bytes.NewBuffer(b))
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("daemon returned %d for transport push", resp.StatusCode)
	}
	return nil
}

func removeTransportFromDaemon(name string) {
	resp, err := uwgRequest("DELETE", "/v1/transports/"+name, nil)
	if err == nil {
		resp.Body.Close()
	}
}

func applyTransportChangeLive(oldName string, t TransportConfig) {
	if oldName != "" && oldName != t.Name {
		removeTransportFromDaemon(oldName)
	} else if oldName != "" {
		removeTransportFromDaemon(oldName)
	}
	if err := pushTransportToDaemon(t); err != nil {
		log.Printf("Live transport push failed (%s), falling back to restart: %v", t.Name, err)
		go restartManagedDaemonIfEnabled()
	}
}

type daemonForwardSnapshot struct {
	Name          string `json:"name"`
	Reverse       bool   `json:"reverse"`
	Proto         string `json:"proto"`
	Listen        string `json:"listen"`
	Target        string `json:"target"`
	ProxyProtocol string `json:"proxy_protocol,omitempty"`
}

func forwardToDaemonPayload(f TunnelForward) map[string]interface{} {
	payload := map[string]interface{}{
		"reverse": f.Reverse,
		"proto":   f.Proto,
		"listen":  f.Listen,
		"target":  f.Target,
	}
	if f.ProxyProtocol != "" {
		payload["proxy_protocol"] = f.ProxyProtocol
	}
	return payload
}

func pushForwardToDaemon(f TunnelForward) (string, error) {
	payload := forwardToDaemonPayload(f)
	b, _ := json.Marshal(payload)
	resp, err := uwgRequest("POST", "/v1/forwards", bytes.NewBuffer(b))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("daemon returned %d for forward push: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out daemonForwardSnapshot
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("decode forward response: %w", err)
	}
	if out.Name == "" {
		return "", errors.New("daemon forward response missing name")
	}
	return out.Name, nil
}

func removeForwardFromDaemon(name string) error {
	if strings.TrimSpace(name) == "" {
		return nil
	}
	resp, err := uwgRequest("DELETE", "/v1/forwards?name="+url.QueryEscape(name), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotFound {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return fmt.Errorf("daemon returned %d for forward delete: %s", resp.StatusCode, strings.TrimSpace(string(body)))
}

func applyForwardChangeLive(oldRuntimeName string, f TunnelForward) (string, error) {
	if err := removeForwardFromDaemon(oldRuntimeName); err != nil {
		return "", err
	}
	return pushForwardToDaemon(f)
}

func findDaemonForwardName(f TunnelForward) string {
	if strings.TrimSpace(f.RuntimeName) != "" {
		return f.RuntimeName
	}
	resp, err := uwgRequest("GET", "/v1/forwards", nil)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var forwards []daemonForwardSnapshot
	if err := json.NewDecoder(resp.Body).Decode(&forwards); err != nil {
		return ""
	}
	for _, rt := range forwards {
		if forwardSnapshotsMatch(f, rt) {
			return rt.Name
		}
	}
	return ""
}

func forwardSnapshotsMatch(f TunnelForward, rt daemonForwardSnapshot) bool {
	return f.Reverse == rt.Reverse &&
		strings.EqualFold(strings.TrimSpace(f.Proto), strings.TrimSpace(rt.Proto)) &&
		strings.TrimSpace(f.Listen) == strings.TrimSpace(rt.Listen) &&
		strings.TrimSpace(f.Target) == strings.TrimSpace(rt.Target) &&
		strings.TrimSpace(f.ProxyProtocol) == strings.TrimSpace(rt.ProxyProtocol)
}

func syncPeersToDaemon() {
	log.Println("Syncing peers to uwgsocks daemon...")
	var peers []Peer
	gdb.Where("enabled = ? AND (expires_at IS NULL OR expires_at > ?)", true, time.Now()).Find(&peers)
	for _, p := range peers {
		pushPeerToDaemon(p)
	}
}

// serverWireGuardAddresses returns the addresses for the server's WireGuard interface.
// IPv6 is omitted when enable_client_ipv6 is false.
func serverWireGuardAddresses() []string {
	v4 := getConfig("client_dns") + "/24"
	if getConfig("enable_client_ipv6") != "true" {
		return []string{v4}
	}
	// Derive an IPv6 gateway from the client_subnet_ipv6 (use the ::1 address of that prefix)
	subnetV6 := getConfig("client_subnet_ipv6")
	prefV6, err := netip.ParsePrefix(subnetV6)
	if err != nil {
		return []string{v4}
	}
	gw := prefV6.Addr().Next()
	return []string{v4, gw.String() + "/64"}
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

func buildProxyConfig() map[string]interface{} {
	m := map[string]interface{}{
		"socks5":        "127.0.0.1:" + getConfig("yaml_socks5_port"),
		"udp_associate": getConfig("yaml_socks5_udp") == "true",
	}
	if p := strings.TrimSpace(getConfig("yaml_http_port")); p != "" && p != "0" {
		m["http"] = "127.0.0.1:" + p
	}
	if u := strings.TrimSpace(getConfig("yaml_proxy_username")); u != "" {
		m["username"] = u
		m["password"] = getConfig("yaml_proxy_password")
	}
	return m
}

func generateCanonicalYAML() {
	os.WriteFile(resolvePath("uwg_canonical.yaml"), buildCanonicalYAMLBytes(true), 0644)
}

func buildCanonicalYAMLBytes(applyCustom bool) []byte {
	port := 51820
	mtu, _ := strconv.Atoi(getConfig("global_mtu"))

	// Ensure unix sockets are absolute paths relative to dataDir
	apiListen := daemonAPIListenAddress(*uwgsocksURL)
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
		}, "proxy": buildProxyConfig(),
		"inbound": map[string]interface{}{
			"transparent": getConfig("yaml_inbound_transparent") == "true",
		},
		"wireguard": map[string]interface{}{
			"private_key": getConfig("server_privkey"),
			"addresses":   serverWireGuardAddresses(),
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

	// host_forward: enabled when redirect IP is non-empty
	redirectIP := strings.TrimSpace(getConfig("yaml_host_forward_redirect_ip"))
	if redirectIP != "" {
		managed["host_forward"] = map[string]interface{}{
			"proxy":   map[string]interface{}{"enabled": true, "redirect_ip": redirectIP},
			"inbound": map[string]interface{}{"enabled": true, "redirect_ip": redirectIP},
		}
	} else {
		managed["host_forward"] = map[string]interface{}{
			"proxy":   map[string]interface{}{"enabled": false},
			"inbound": map[string]interface{}{"enabled": false},
		}
	}

	// Port forwards and reverse forwards
	var fwRecords []TunnelForward
	gdb.Order("sort_order asc, id asc").Find(&fwRecords)
	var fwds []map[string]interface{}
	var revFwds []map[string]interface{}
	for _, f := range fwRecords {
		m := map[string]interface{}{
			"proto":  f.Proto,
			"listen": f.Listen,
			"target": f.Target,
		}
		if f.ProxyProtocol != "" {
			m["proxy_protocol"] = f.ProxyProtocol
		}
		if f.Reverse {
			revFwds = append(revFwds, m)
		} else {
			fwds = append(fwds, m)
		}
	}
	if len(fwds) > 0 {
		managed["forwards"] = fwds
	}
	if len(revFwds) > 0 {
		managed["reverse_forwards"] = revFwds
	}

	if *turnServer != "" {
		managed["turn"] = map[string]interface{}{
			"server":                *turnServer,
			"username":              *turnUser,
			"password":              *turnPass,
			"realm":                 *turnRealm,
			"include_wg_public_key": *turnIncludeWGPublicKey,
		}
	}

	managed["acl"] = getACLConfig()
	if def := strings.TrimSpace(getConfig("default_transport")); def != "" {
		managedWG := managed["wireguard"].(map[string]interface{})
		managedWG["default_transport"] = def
	}

	ts := getTransportsConfig()
	if getConfig("socket_proxy_enabled") == "true" {
		if p, err := strconv.Atoi(getConfig("socket_proxy_http_port")); err == nil && p > 0 {
			ts = append(ts, map[string]interface{}{
				"name":             "ui-socket-http",
				"base":             "http",
				"listen":           true,
				"listen_port":      p,
				"listen_addresses": []string{"127.0.0.1", "::1"},
				"websocket": map[string]interface{}{
					"path": "/socket",
				},
			})
		}
	}
	if len(ts) > 0 {
		managed["transports"] = ts
	}

	// Merge managed onto baseline
	deepMerge(config, managed)

	d, _ := yaml.Marshal(config)
	if applyCustom && getConfig("custom_yaml_enabled") == "true" {
		custom := strings.TrimSpace(getConfig("custom_yaml"))
		if custom != "" {
			var parsed map[string]interface{}
			if err := yaml.Unmarshal([]byte(custom), &parsed); err != nil {
				log.Printf("Custom YAML override is invalid, keeping generated canonical YAML: %v", err)
			} else {
				d = []byte(custom)
				if !bytes.HasSuffix(d, []byte("\n")) {
					d = append(d, '\n')
				}
			}
		}
	}
	return d
}

func startDaemon() {
	if err := startManagedDaemon(); err != nil {
		log.Printf("Failed to start daemon: %v", err)
	}
}
