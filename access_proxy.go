package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const serviceAuthPath = "/.well-known/_service_auth"

type AccessProxyCredential struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	UserID       uint      `gorm:"not null" json:"user_id"`
	User         User      `gorm:"foreignKey:UserID" json:"-"`
	Username     string    `gorm:"uniqueIndex;not null" json:"username"`
	PasswordHash string    `json:"-"`
	Name         string    `json:"name"`
	Enabled      bool      `gorm:"default:true" json:"enabled"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type ExposedService struct {
	ID                 uint      `gorm:"primaryKey" json:"id"`
	Name               string    `gorm:"uniqueIndex;not null" json:"name"`
	Host               string    `gorm:"uniqueIndex;not null" json:"host"`
	TargetURL          string    `gorm:"not null" json:"target_url"`
	AuthMode           string    `gorm:"default:login" json:"auth_mode"` // open|login
	BypassCIDRs        string    `json:"bypass_cidrs,omitempty"`
	CORSProtection     bool      `gorm:"default:true" json:"cors_protection"`
	AllowedOrigins     string    `json:"allowed_origins,omitempty"`
	InsecureSkipVerify bool      `gorm:"default:false" json:"insecure_skip_verify"`
	CAPEM              string    `json:"ca_pem,omitempty"`
	ClientCertPEM      string    `json:"client_cert_pem,omitempty"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

type serviceAuthToken struct {
	SessionID string `json:"session_id"`
	Service   string `json:"service"`
	Expires   int64  `json:"expires"`
}

type serviceCookieToken struct {
	SessionID string `json:"session_id"`
	Service   string `json:"service"`
}

var serviceProxyCache sync.Map

func wrapRootHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if getConfig("socket_proxy_enabled") == "true" && r.URL.Path == "/socket" {
			handleSocketProxy(w, r)
			return
		}
		if getConfig("http_proxy_access_enabled") == "true" && isHTTPAccessProxyRequest(r) {
			handleHTTPAccessProxy(w, r)
			return
		}
		if svc, ok := serviceForRequest(r); ok {
			handleExposedService(w, r, svc)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isHTTPAccessProxyRequest(r *http.Request) bool {
	return r.Method == http.MethodConnect ||
		r.URL.IsAbs() ||
		r.URL.Path == "/proxy" ||
		strings.HasPrefix(r.URL.Path, "/proxy/")
}

func registerAccessProxyRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /service-auth", handleServiceAuthStart)
	mux.HandleFunc("GET /api/admin/proxy-credentials", authMiddleware(adminMiddleware(handleListAccessProxyCredentials)))
	mux.HandleFunc("POST /api/admin/proxy-credentials", authMiddleware(adminMiddleware(handleCreateAccessProxyCredential)))
	mux.HandleFunc("DELETE /api/admin/proxy-credentials/{id}", authMiddleware(adminMiddleware(handleDeleteAccessProxyCredential)))
	mux.HandleFunc("GET /api/admin/exposed-services", authMiddleware(adminMiddleware(handleListExposedServices)))
	mux.HandleFunc("POST /api/admin/exposed-services", authMiddleware(adminMiddleware(handleCreateExposedService)))
	mux.HandleFunc("PATCH /api/admin/exposed-services/{id}", authMiddleware(adminMiddleware(handleUpdateExposedService)))
	mux.HandleFunc("DELETE /api/admin/exposed-services/{id}", authMiddleware(adminMiddleware(handleDeleteExposedService)))
}

func handleListAccessProxyCredentials(w http.ResponseWriter, r *http.Request) {
	var creds []AccessProxyCredential
	gdb.Order("created_at desc").Find(&creds)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(creds)
}

func handleCreateAccessProxyCredential(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name     string `json:"name"`
		Username string `json:"username"`
		Enabled  *bool  `json:"enabled"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	username := strings.TrimSpace(req.Username)
	if username == "" {
		username = "proxy-" + randomSecret(6)
	}
	password := randomSecret(24)
	hash, _ := hashPassword(password)
	userID, _ := strconv.ParseUint(r.Header.Get("X-User-Id"), 10, 64)
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	cred := AccessProxyCredential{
		UserID:       uint(userID),
		Username:     username,
		PasswordHash: hash,
		Name:         strings.TrimSpace(req.Name),
		Enabled:      enabled,
	}
	if cred.Name == "" {
		cred.Name = username
	}
	if err := gdb.Create(&cred).Error; err != nil {
		http.Error(w, "Failed to create proxy credential", http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":         cred.ID,
		"name":       cred.Name,
		"username":   cred.Username,
		"password":   password,
		"enabled":    cred.Enabled,
		"created_at": cred.CreatedAt,
	})
}

func handleDeleteAccessProxyCredential(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	gdb.Delete(&AccessProxyCredential{}, id)
	w.WriteHeader(http.StatusNoContent)
}

func handleListExposedServices(w http.ResponseWriter, r *http.Request) {
	var services []ExposedService
	gdb.Order("host asc").Find(&services)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(services)
}

func handleCreateExposedService(w http.ResponseWriter, r *http.Request) {
	var svc ExposedService
	if err := json.NewDecoder(r.Body).Decode(&svc); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	normalizeExposedService(&svc)
	if err := validateExposedService(svc); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := gdb.Create(&svc).Error; err != nil {
		http.Error(w, "Failed to create service", http.StatusConflict)
		return
	}
	serviceProxyCache.Delete(svc.ID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(svc)
}

func handleUpdateExposedService(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	var svc ExposedService
	if err := gdb.First(&svc, id).Error; err != nil {
		http.Error(w, "Service not found", http.StatusNotFound)
		return
	}
	var req ExposedService
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	req.ID = svc.ID
	normalizeExposedService(&req)
	if err := validateExposedService(req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	svc.Name = req.Name
	svc.Host = req.Host
	svc.TargetURL = req.TargetURL
	svc.AuthMode = req.AuthMode
	svc.BypassCIDRs = req.BypassCIDRs
	svc.CORSProtection = req.CORSProtection
	svc.AllowedOrigins = req.AllowedOrigins
	svc.InsecureSkipVerify = req.InsecureSkipVerify
	svc.CAPEM = req.CAPEM
	svc.ClientCertPEM = req.ClientCertPEM
	if err := gdb.Save(&svc).Error; err != nil {
		http.Error(w, "Failed to update service", http.StatusConflict)
		return
	}
	serviceProxyCache.Delete(svc.ID)
	w.WriteHeader(http.StatusOK)
}

func handleDeleteExposedService(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	gdb.Delete(&ExposedService{}, id)
	serviceProxyCache.Delete(uint(id))
	w.WriteHeader(http.StatusNoContent)
}

func normalizeExposedService(svc *ExposedService) {
	svc.Name = strings.TrimSpace(svc.Name)
	svc.Host = hostWithoutPort(svc.Host)
	svc.TargetURL = strings.TrimSpace(svc.TargetURL)
	svc.AuthMode = strings.ToLower(strings.TrimSpace(svc.AuthMode))
	if svc.AuthMode == "" {
		svc.AuthMode = "login"
	}
	if !svc.CORSProtection && svc.AuthMode == "" {
		svc.CORSProtection = true
	}
}

func validateExposedService(svc ExposedService) error {
	if svc.Name == "" || svc.Host == "" || svc.TargetURL == "" {
		return fmt.Errorf("name, host, and target_url are required")
	}
	if svc.AuthMode != "open" && svc.AuthMode != "login" {
		return fmt.Errorf("auth_mode must be open or login")
	}
	u, err := url.Parse(svc.TargetURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("target_url must be an http:// or https:// URL")
	}
	return nil
}

func serviceForRequest(r *http.Request) (ExposedService, bool) {
	if getConfig("exposed_services_enabled") != "true" {
		return ExposedService{}, false
	}
	var svc ExposedService
	if err := gdb.First(&svc, "lower(host) = ?", hostWithoutPort(r.Host)).Error; err != nil {
		return ExposedService{}, false
	}
	return svc, true
}

func handleExposedService(w http.ResponseWriter, r *http.Request, svc ExposedService) {
	w.Header().Set("Access-Control-Allow-Origin", serviceExternalScheme(r)+"://"+r.Host)
	w.Header().Set("Vary", "Origin, Referer")
	if r.URL.Path == serviceAuthPath && r.Method == http.MethodPost {
		handleServiceAuthCallback(w, r, svc)
		return
	}
	var identity accessIdentity
	hasIdentity := false
	if svc.AuthMode == "login" && !serviceBypassAllowed(r, svc) {
		var ok bool
		identity, ok = serviceCookieIdentity(r, svc)
		if !ok {
			redirectToServiceAuth(w, r, svc)
			return
		}
		hasIdentity = true
		if svc.CORSProtection && !serviceCORSAllowed(r, svc) {
			handleServiceCORSBlocked(w, r)
			return
		}
	}
	targetURL, _ := url.Parse(svc.TargetURL)
	host, port, ok := hostPortForAccessTarget(svc.TargetURL, targetURL.Scheme)
	if ok && !accessAllowedByACL(r, identity, host, port, "tcp") {
		if hasIdentity {
			http.Error(w, "Blocked by ACL for "+identity.Username, http.StatusForbidden)
		} else {
			http.Error(w, "Blocked by ACL", http.StatusForbidden)
		}
		return
	}
	proxy := reverseProxyForService(svc)
	proxy.ServeHTTP(w, r)
}

func redirectToServiceAuth(w http.ResponseWriter, r *http.Request, svc ExposedService) {
	nextURL := serviceExternalScheme(r) + "://" + r.Host + r.URL.RequestURI()
	target := canonicalBaseURL(r) + "/service-auth?service=" + url.QueryEscape(svc.Name) + "&next=" + url.QueryEscape(nextURL)
	http.Redirect(w, r, target, http.StatusFound)
}

func handleServiceAuthStart(w http.ResponseWriter, r *http.Request) {
	token := bearerTokenFromRequest(r)
	if token == "" {
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
		return
	}
	var user User
	if err := gdb.First(&user, "token = ?", token).Error; err != nil {
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
		return
	}
	serviceName := r.URL.Query().Get("service")
	nextURL := r.URL.Query().Get("next")
	var svc ExposedService
	if err := gdb.First(&svc, "name = ?", serviceName).Error; err != nil {
		http.Error(w, "Service not found", http.StatusNotFound)
		return
	}
	if nextURL == "" {
		nextURL = serviceExternalScheme(r) + "://" + svc.Host + "/"
	}
	authToken := encryptServiceAuthToken(serviceAuthToken{
		SessionID: token,
		Service:   svc.Name,
		Expires:   time.Now().Add(5 * time.Minute).Unix(),
	})
	postURL := serviceExternalScheme(r) + "://" + svc.Host + serviceAuthPath
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><title>Continue</title><form id="f" method="post" action=%q><input type="hidden" name="auth_token" value=%q><input type="hidden" name="next" value=%q></form><script>document.getElementById("f").submit()</script><p>Continuing...</p>`, postURL, authToken, nextURL)
}

func serviceExternalScheme(r *http.Request) string {
	base, err := url.Parse(canonicalBaseURL(r))
	if err == nil && (base.Scheme == "http" || base.Scheme == "https") {
		return base.Scheme
	}
	return requestScheme(r)
}

func handleServiceAuthCallback(w http.ResponseWriter, r *http.Request, svc ExposedService) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	token, ok := decryptServiceAuthToken(r.Form.Get("auth_token"))
	if !ok || token.Service != svc.Name || token.Expires < time.Now().Unix() {
		http.Error(w, "Invalid service authentication token", http.StatusUnauthorized)
		return
	}
	var user User
	if err := gdb.First(&user, "token = ?", token.SessionID).Error; err != nil {
		http.Error(w, "Session expired", http.StatusUnauthorized)
		return
	}
	maxAge := int((12 * time.Hour).Seconds())
	if configured, err := strconv.Atoi(getConfig("service_auth_cookie_seconds")); err == nil && configured > 0 {
		maxAge = configured
	}
	http.SetCookie(w, &http.Cookie{
		Name:     serviceCookieName(svc),
		Value:    encryptServiceCookie(serviceCookieToken{SessionID: token.SessionID, Service: svc.Name}),
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   requestScheme(r) == "https",
		SameSite: http.SameSiteLaxMode,
	})
	nextURL := r.Form.Get("next")
	if nextURL == "" {
		nextURL = "/"
	}
	http.Redirect(w, r, nextURL, http.StatusFound)
}

func serviceCookieIdentity(r *http.Request, svc ExposedService) (accessIdentity, bool) {
	cookie, err := r.Cookie(serviceCookieName(svc))
	if err != nil {
		return accessIdentity{}, false
	}
	token, ok := decryptServiceCookie(cookie.Value)
	if !ok || token.Service != svc.Name || token.SessionID == "" {
		return accessIdentity{}, false
	}
	return identityFromSessionToken(token.SessionID)
}

func serviceCookieName(svc ExposedService) string {
	sum := sha256.Sum256([]byte(svc.Name + "\x00" + svc.Host))
	return "uwgs_svc_" + hex.EncodeToString(sum[:8])
}

func encryptServiceAuthToken(token serviceAuthToken) string {
	b, _ := json.Marshal(token)
	return encryptAtRest(string(b))
}

func decryptServiceAuthToken(raw string) (serviceAuthToken, bool) {
	var token serviceAuthToken
	plain := decryptAtRest(raw)
	if plain == "" || json.Unmarshal([]byte(plain), &token) != nil {
		return token, false
	}
	return token, true
}

func encryptServiceCookie(token serviceCookieToken) string {
	b, _ := json.Marshal(token)
	return encryptAtRest(string(b))
}

func decryptServiceCookie(raw string) (serviceCookieToken, bool) {
	var token serviceCookieToken
	plain := decryptAtRest(raw)
	if plain == "" || json.Unmarshal([]byte(plain), &token) != nil {
		return token, false
	}
	return token, true
}

func serviceBypassAllowed(r *http.Request, svc ExposedService) bool {
	ip, err := netip.ParseAddr(clientIPForRequest(r))
	if err != nil {
		return false
	}
	for _, part := range strings.FieldsFunc(svc.BypassCIDRs, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	}) {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(part))
		if err == nil && prefix.Contains(ip.Unmap()) {
			return true
		}
	}
	return false
}

func serviceCORSAllowed(r *http.Request, svc ExposedService) bool {
	if r.URL.Query().Get("_uwgs_continue") == "1" && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		return true
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		origin = strings.TrimSpace(r.Header.Get("Referer"))
	}
	if origin == "" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || hostWithoutPort(u.Host) == "" {
		return false
	}
	if hostWithoutPort(u.Host) == hostWithoutPort(r.Host) {
		return true
	}
	for _, allowed := range strings.FieldsFunc(svc.AllowedOrigins, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	}) {
		au, err := url.Parse(strings.TrimSpace(allowed))
		if err == nil && strings.EqualFold(au.Scheme, u.Scheme) && hostWithoutPort(au.Host) == hostWithoutPort(u.Host) {
			return true
		}
	}
	return false
}

func handleServiceCORSBlocked(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		http.Error(w, "Origin not allowed", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Cross-origin request blocked", http.StatusForbidden)
		return
	}
	next := *r.URL
	q := next.Query()
	q.Set("_uwgs_continue", "1")
	next.RawQuery = q.Encode()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><title>Continue</title><p>This request came from another site.</p><p><a href=%q>Open this service URL</a></p>`, next.String())
}

func reverseProxyForService(svc ExposedService) *httputil.ReverseProxy {
	if cached, ok := serviceProxyCache.Load(svc.ID); ok {
		return cached.(*httputil.ReverseProxy)
	}
	target, _ := url.Parse(svc.TargetURL)
	proxy := httputil.NewSingleHostReverseProxy(target)
	origDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalHost := req.Host
		origDirector(req)
		req.Host = target.Host
		req.Header.Set("X-Forwarded-For", clientIPForRequest(req))
		req.Header.Set("X-Forwarded-Host", originalHost)
		req.Header.Set("X-Forwarded-Proto", requestScheme(req))
		stripCookie(req, serviceCookieName(svc))
	}
	proxy.Transport = serviceTransport(svc)
	serviceProxyCache.Store(svc.ID, proxy)
	return proxy
}

func serviceTransport(svc ExposedService) http.RoundTripper {
	tr := &http.Transport{
		Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: "127.0.0.1:" + getConfig("yaml_http_port")}),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: svc.InsecureSkipVerify,
		},
	}
	if strings.TrimSpace(svc.CAPEM) != "" {
		pool := x509.NewCertPool()
		if pool.AppendCertsFromPEM([]byte(svc.CAPEM)) {
			tr.TLSClientConfig.RootCAs = pool
		}
	}
	if svc.ClientCertPEM != "" {
		if cert, err := tls.X509KeyPair([]byte(svc.ClientCertPEM), []byte(svc.ClientCertPEM)); err == nil {
			tr.TLSClientConfig.Certificates = []tls.Certificate{cert}
		}
	}
	return proxyAuthTransport{base: tr}
}

func handleSocketProxy(w http.ResponseWriter, r *http.Request) {
	port := strings.TrimSpace(getConfig("socket_proxy_http_port"))
	if port == "" || port == "0" {
		http.Error(w, "Socket proxy is not configured", http.StatusServiceUnavailable)
		return
	}
	target, _ := url.Parse("http://127.0.0.1:" + port)
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Director = func(req *http.Request) {
		req.URL.Scheme = "http"
		req.URL.Host = target.Host
		req.URL.Path = "/socket"
		req.Host = target.Host
		req.Header.Set("X-Forwarded-For", clientIPForRequest(r))
		req.Header.Set("X-Forwarded-Proto", requestScheme(r))
	}
	proxy.ServeHTTP(w, r)
}

func handleHTTPAccessProxy(w http.ResponseWriter, r *http.Request) {
	identity, ok := httpProxyCredentialIdentity(r)
	if !ok {
		w.Header().Set("Proxy-Authenticate", `Basic realm="uwgsocks-ui proxy"`)
		w.Header().Set("WWW-Authenticate", `Basic realm="uwgsocks-ui proxy"`)
		http.Error(w, "Proxy authentication required", http.StatusProxyAuthRequired)
		return
	}
	if r.Method != http.MethodConnect {
		handleHTTPAccessProxyRequest(w, r, identity)
		return
	}
	handleHTTPAccessProxyConnect(w, r, identity)
}

func handleHTTPAccessProxyRequest(w http.ResponseWriter, r *http.Request, identity accessIdentity) {
	if !r.URL.IsAbs() {
		http.Error(w, "Expected absolute-form proxy URL", http.StatusBadRequest)
		return
	}
	host, port, ok := hostPortForAccessTarget(r.URL.String(), r.URL.Scheme)
	if !ok || !accessAllowedByACL(r, identity, host, port, "tcp") {
		http.Error(w, "Blocked by ACL", http.StatusForbidden)
		return
	}
	out := r.Clone(r.Context())
	out.RequestURI = ""
	out.URL = cloneURL(r.URL)
	out.Header = r.Header.Clone()
	replaceUpstreamProxyAuth(out.Header)
	out.Header.Set("X-Forwarded-For", clientIPForRequest(r))
	resp, err := proxyHTTPClient().Do(out)
	if err != nil {
		http.Error(w, "Upstream proxy request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func handleHTTPAccessProxyConnect(w http.ResponseWriter, r *http.Request, identity accessIdentity) {
	if r.Method != http.MethodConnect {
		http.Error(w, "Only CONNECT is supported on /proxy", http.StatusMethodNotAllowed)
		return
	}
	target := strings.TrimPrefix(r.URL.Path, "/proxy/")
	if target == "" {
		target = r.URL.Host
	}
	if target == "" {
		http.Error(w, "Missing CONNECT target", http.StatusBadRequest)
		return
	}
	host, port, ok := hostPortForAccessTarget(target, "https")
	if !ok || !accessAllowedByACL(r, identity, host, port, "tcp") {
		http.Error(w, "Blocked by ACL", http.StatusForbidden)
		return
	}
	upstream := "127.0.0.1:" + getConfig("yaml_http_port")
	conn, err := net.DialTimeout("tcp", upstream, 10*time.Second)
	if err != nil {
		http.Error(w, "Failed to reach uwgsocks HTTP proxy", http.StatusBadGateway)
		return
	}
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nX-Forwarded-For: %s\r\n", target, target, clientIPForRequest(r))
	if auth := upstreamProxyAuthorization(); auth != "" {
		fmt.Fprintf(conn, "Proxy-Authorization: %s\r\n", auth)
	}
	io.WriteString(conn, "\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, r)
	if err != nil {
		http.Error(w, "Invalid upstream proxy response", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		http.Error(w, "Upstream proxy rejected CONNECT", resp.StatusCode)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking is not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		return
	}
	defer clientConn.Close()
	io.WriteString(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(conn, clientConn)
	}()
	go func() {
		defer wg.Done()
		if br.Buffered() > 0 {
			io.Copy(clientConn, io.MultiReader(br, conn))
			return
		}
		io.Copy(clientConn, conn)
	}()
	wg.Wait()
}

type proxyAuthTransport struct {
	base http.RoundTripper
}

func (t proxyAuthTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	req := r.Clone(r.Context())
	req.Header = r.Header.Clone()
	replaceUpstreamProxyAuth(req.Header)
	return t.base.RoundTrip(req)
}

func proxyHTTPClient() *http.Client {
	return &http.Client{Transport: proxyAuthTransport{base: &http.Transport{
		Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: "127.0.0.1:" + getConfig("yaml_http_port")}),
	}}}
}

func upstreamProxyAuthorization() string {
	username := strings.TrimSpace(getConfig("yaml_proxy_username"))
	if username == "" {
		return ""
	}
	raw := username + ":" + getConfig("yaml_proxy_password")
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(raw))
}

func replaceUpstreamProxyAuth(header http.Header) {
	header.Del("Proxy-Authorization")
	if auth := upstreamProxyAuthorization(); auth != "" {
		header.Set("Proxy-Authorization", auth)
	}
}

func cloneURL(u *url.URL) *url.URL {
	c := *u
	return &c
}

func copyHeader(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func httpProxyCredentialIdentity(r *http.Request) (accessIdentity, bool) {
	header := r.Header.Get("Proxy-Authorization")
	if header == "" {
		header = r.Header.Get("Authorization")
	}
	if !strings.HasPrefix(strings.ToLower(header), "basic ") {
		return accessIdentity{}, false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(header[6:]))
	if err != nil {
		return accessIdentity{}, false
	}
	username, password, ok := strings.Cut(string(raw), ":")
	if !ok {
		return accessIdentity{}, false
	}
	var cred AccessProxyCredential
	if err := gdb.First(&cred, "username = ? AND enabled = ?", username, true).Error; err != nil {
		return accessIdentity{}, false
	}
	if !verifyPassword(password, cred.PasswordHash) {
		return accessIdentity{}, false
	}
	var user User
	if err := gdb.First(&user, cred.UserID).Error; err != nil {
		return accessIdentity{}, false
	}
	return identityForUser(user), true
}

func stripCookie(r *http.Request, name string) {
	cookies := r.Cookies()
	r.Header.Del("Cookie")
	for _, cookie := range cookies {
		if cookie.Name != name {
			r.AddCookie(cookie)
		}
	}
}
