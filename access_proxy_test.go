package main

import (
	"bufio"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func setTestConfig(t *testing.T, key, value string) {
	t.Helper()
	if err := setConfigValue(key, value); err != nil {
		t.Fatalf("set config %s: %v", key, err)
	}
}

func TestTrustedProxyClientIPAndCanonicalURL(t *testing.T) {
	setupTestDB(t)
	setTestConfig(t, "trusted_proxy_cidrs", "192.0.2.0/24, 2001:db8::/32")

	req := httptest.NewRequest("GET", "http://ui.internal/app", nil)
	req.RemoteAddr = "192.0.2.10:12345"
	req.Header.Set("X-Forwarded-For", "198.51.100.77, 192.0.2.10")
	req.Header.Set("X-Forwarded-Proto", "https")

	if got := clientIPForRequest(req); got != "198.51.100.77" {
		t.Fatalf("client IP = %q", got)
	}
	if got := canonicalBaseURL(req); got != "https://ui.internal" {
		t.Fatalf("canonical base URL = %q", got)
	}

	setTestConfig(t, "web_base_url", "https://wireguard.example.com/base/")
	if got := canonicalBaseURL(req); got != "https://wireguard.example.com/base" {
		t.Fatalf("configured canonical base URL = %q", got)
	}
}

func TestSocketProxyForwardsToLoopbackTransport(t *testing.T) {
	setupTestDB(t)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/socket" {
			t.Fatalf("unexpected socket path %q", r.URL.Path)
		}
		w.Header().Set("X-Seen-Forwarded-For", r.Header.Get("X-Forwarded-For"))
		w.Write([]byte("socket-ok"))
	}))
	defer backend.Close()
	u, _ := url.Parse(backend.URL)
	_, port, _ := net.SplitHostPort(u.Host)
	setTestConfig(t, "socket_proxy_enabled", "true")
	setTestConfig(t, "socket_proxy_http_port", port)

	req := httptest.NewRequest("GET", "http://ui.example/socket", nil)
	req.RemoteAddr = "203.0.113.9:1234"
	w := httptest.NewRecorder()
	wrapRootHandler(http.NewServeMux()).ServeHTTP(w, req)
	if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != "socket-ok" {
		t.Fatalf("socket proxy response %d %q", w.Code, w.Body.String())
	}
}

func TestSocketProxyTransportYAML(t *testing.T) {
	setupTestDB(t)
	setTestConfig(t, "socket_proxy_enabled", "true")
	setTestConfig(t, "socket_proxy_http_port", "19090")
	yml := string(buildCanonicalYAMLBytes(false))
	for _, want := range []string{"name: ui-socket-http", "base: http", "listen_port: 19090", "path: /socket"} {
		if !strings.Contains(yml, want) {
			t.Fatalf("generated YAML missing %q:\n%s", want, yml)
		}
	}
}

func TestServiceAuthFlowAndCORSGuard(t *testing.T) {
	setupTestDB(t)
	_, token := createTestUser(t, "admin", true)
	setTestConfig(t, "web_base_url", "https://wireguard.example.com")
	svc := ExposedService{
		Name:           "switch",
		Host:           "switch.wireguard.example.com",
		TargetURL:      "http://100.64.0.10",
		AuthMode:       "login",
		CORSProtection: true,
	}
	if err := gdb.Create(&svc).Error; err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "http://switch.wireguard.example.com/admin", nil)
	req.Host = svc.Host
	w := httptest.NewRecorder()
	wrapRootHandler(http.NewServeMux()).ServeHTTP(w, req)
	if w.Code != http.StatusFound || !strings.Contains(w.Header().Get("Location"), "/service-auth") {
		t.Fatalf("expected service auth redirect, got %d %q", w.Code, w.Header().Get("Location"))
	}

	authToken := encryptServiceAuthToken(serviceAuthToken{
		SessionID: token,
		Service:   svc.Name,
		Expires:   time.Now().Add(5 * time.Minute).Unix(),
	})
	form := "auth_token=" + url.QueryEscape(authToken) + "&next=" + url.QueryEscape("https://"+svc.Host+"/admin")
	req = httptest.NewRequest("POST", "https://"+svc.Host+serviceAuthPath, strings.NewReader(form))
	req.Host = svc.Host
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	wrapRootHandler(http.NewServeMux()).ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("expected service auth callback redirect, got %d: %s", w.Code, w.Body.String())
	}
	cookies := w.Result().Cookies()
	if len(cookies) == 0 || cookies[0].Name != serviceCookieName(svc) {
		t.Fatalf("expected service cookie, got %#v", cookies)
	}

	req = httptest.NewRequest("POST", "https://"+svc.Host+"/admin/reboot", nil)
	req.Host = svc.Host
	req.AddCookie(cookies[0])
	req.Header.Set("Origin", "https://evil.example")
	w = httptest.NewRecorder()
	wrapRootHandler(http.NewServeMux()).ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected CORS guarded POST to be rejected, got %d", w.Code)
	}
}

func TestHTTPAccessProxyConnect(t *testing.T) {
	setupTestDB(t)
	setTestConfig(t, "http_proxy_access_enabled", "true")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Host != "example.internal:443" {
			t.Fatalf("unexpected upstream CONNECT %s %s", r.Method, r.Host)
		}
		hj, _ := w.(http.Hijacker)
		conn, _, _ := hj.Hijack()
		defer conn.Close()
		io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\npong")
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	_, port, _ := net.SplitHostPort(u.Host)
	setTestConfig(t, "yaml_http_port", port)
	hash, _ := hashPassword("secret")
	gdb.Create(&AccessProxyCredential{UserID: 1, Username: "proxy-user", PasswordHash: hash, Name: "test", Enabled: true})

	server := httptest.NewServer(wrapRootHandler(http.NewServeMux()))
	defer server.Close()
	conn, err := net.Dial("tcp", strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	auth := base64.StdEncoding.EncodeToString([]byte("proxy-user:secret"))
	io.WriteString(conn, "CONNECT /proxy/example.internal:443 HTTP/1.1\r\nHost: "+strings.TrimPrefix(server.URL, "http://")+"\r\nProxy-Authorization: Basic "+auth+"\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT response = %d", resp.StatusCode)
	}
}

func TestHTTPAccessProxyAbsoluteRequestRewritesUpstreamAuth(t *testing.T) {
	setupTestDB(t)
	setTestConfig(t, "http_proxy_access_enabled", "true")
	setTestConfig(t, "yaml_proxy_username", "uwg")
	setTestConfig(t, "yaml_proxy_password", "daemon-secret")
	wantUpstreamAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("uwg:daemon-secret"))
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !r.URL.IsAbs() || r.URL.String() != "http://service.internal/status" {
			t.Fatalf("unexpected upstream URL %q", r.URL.String())
		}
		if got := r.Header.Get("Proxy-Authorization"); got != wantUpstreamAuth {
			t.Fatalf("upstream proxy auth = %q, want %q", got, wantUpstreamAuth)
		}
		w.Write([]byte("proxied"))
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	_, port, _ := net.SplitHostPort(u.Host)
	setTestConfig(t, "yaml_http_port", port)
	hash, _ := hashPassword("user-secret")
	gdb.Create(&AccessProxyCredential{UserID: 1, Username: "proxy-user", PasswordHash: hash, Name: "test", Enabled: true})

	req := httptest.NewRequest("GET", "http://service.internal/status", nil)
	req.RequestURI = "http://service.internal/status"
	req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("proxy-user:user-secret")))
	w := httptest.NewRecorder()
	wrapRootHandler(http.NewServeMux()).ServeHTTP(w, req)
	if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != "proxied" {
		t.Fatalf("absolute proxy response %d %q", w.Code, w.Body.String())
	}
}
