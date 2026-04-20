package main

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

func trustedProxyPrefixes() []netip.Prefix {
	var out []netip.Prefix
	for _, part := range strings.FieldsFunc(getConfig("trusted_proxy_cidrs"), func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	}) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(part)
		if err == nil {
			out = append(out, prefix)
			continue
		}
		if addr, err := netip.ParseAddr(part); err == nil {
			bits := 128
			if addr.Unmap().Is4() {
				addr = addr.Unmap()
				bits = 32
			}
			out = append(out, netip.PrefixFrom(addr, bits))
		}
	}
	return out
}

func remoteAddrIP(r *http.Request) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

func isTrustedProxyRequest(r *http.Request) bool {
	addr, ok := remoteAddrIP(r)
	if !ok {
		return false
	}
	for _, prefix := range trustedProxyPrefixes() {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func clientIPForRequest(r *http.Request) string {
	if isTrustedProxyRequest(r) {
		if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
			if first := strings.TrimSpace(strings.Split(xff, ",")[0]); first != "" {
				return strings.Trim(first, "[]")
			}
		}
	}
	if addr, ok := remoteAddrIP(r); ok {
		return addr.String()
	}
	return r.RemoteAddr
}

func requestScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if isTrustedProxyRequest(r) {
		proto := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]))
		if proto == "https" {
			return "https"
		}
	}
	return "http"
}

func canonicalBaseURL(r *http.Request) string {
	if base := strings.TrimSpace(getConfig("web_base_url")); base != "" {
		return strings.TrimRight(base, "/")
	}
	return requestScheme(r) + "://" + r.Host
}

func requestOrigin(r *http.Request) string {
	return requestScheme(r) + "://" + r.Host
}

func hostWithoutPort(host string) string {
	h := strings.TrimSpace(host)
	if parsed, _, err := net.SplitHostPort(h); err == nil {
		return strings.ToLower(strings.Trim(parsed, "[]"))
	}
	return strings.ToLower(strings.Trim(h, "[]"))
}
