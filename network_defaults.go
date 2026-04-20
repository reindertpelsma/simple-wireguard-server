package main

import (
	"encoding/json"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

type daemonStatusSnapshot struct {
	Peers      []daemonPeerSnapshot      `json:"peers"`
	Transports []daemonTransportSnapshot `json:"transports"`
}

type daemonPeerSnapshot struct {
	PublicKey                  string `json:"public_key"`
	Endpoint                   string `json:"endpoint,omitempty"`
	EndpointIP                 string `json:"endpoint_ip,omitempty"`
	LastHandshakeTime          string `json:"last_handshake_time,omitempty"`
	TransmitBytes              uint64 `json:"transmit_bytes"`
	ReceiveBytes               uint64 `json:"receive_bytes"`
	HasHandshake               bool   `json:"has_handshake"`
	TransportName              string `json:"transport_name,omitempty"`
	TransportState             string `json:"transport_state,omitempty"`
	TransportEndpoint          string `json:"transport_endpoint,omitempty"`
	TransportSourceAddr        string `json:"transport_source_addr,omitempty"`
	TransportCarrierRemoteAddr string `json:"transport_carrier_remote_addr,omitempty"`
}

type daemonTransportSnapshot struct {
	Name              string `json:"name"`
	Base              string `json:"base,omitempty"`
	ActiveSessions    int    `json:"active_sessions,omitempty"`
	Connected         bool   `json:"connected,omitempty"`
	CarrierProtocol   string `json:"carrier_protocol,omitempty"`
	CarrierLocalAddr  string `json:"carrier_local_addr,omitempty"`
	CarrierRemoteAddr string `json:"carrier_remote_addr,omitempty"`
	RelayAddr         string `json:"relay_addr,omitempty"`
}

func fetchDaemonStatus() daemonStatusSnapshot {
	var out daemonStatusSnapshot
	resp, err := uwgRequest("GET", "/v1/status", nil)
	if err != nil {
		return out
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return out
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out
}

func resolveDefaultTransportNameUI() string {
	if explicit := strings.TrimSpace(getConfig("default_transport")); explicit != "" {
		return explicit
	}
	var transports []TransportConfig
	gdb.Order("id asc").Find(&transports)
	for _, t := range transports {
		if !uiTransportIsConnectionOriented(t) {
			return t.Name
		}
	}
	if len(transports) > 0 {
		return transports[0].Name
	}
	return ""
}

func resolveDefaultTransportConfigUI() *TransportConfig {
	name := resolveDefaultTransportNameUI()
	var transports []TransportConfig
	gdb.Order("id asc").Find(&transports)
	if name != "" {
		for i := range transports {
			if transports[i].Name == name {
				return &transports[i]
			}
		}
	}
	if len(transports) > 0 {
		return &transports[0]
	}
	return nil
}

func uiTransportIsConnectionOriented(t TransportConfig) bool {
	switch strings.ToLower(strings.TrimSpace(t.Base)) {
	case "tcp", "tls", "dtls", "http", "https", "quic", "quic-ws", "url":
		return true
	}
	switch strings.ToLower(strings.TrimSpace(t.ProxyType)) {
	case "socks5", "http":
		return true
	}
	return false
}

func transportNeedsExplicitClientLine(t *TransportConfig) bool {
	if t == nil {
		return false
	}
	base := strings.ToLower(strings.TrimSpace(t.Base))
	if base == "" {
		base = "udp"
	}
	proxy := strings.ToLower(strings.TrimSpace(t.ProxyType))
	return !(base == "udp" && (proxy == "" || proxy == "none") && t.Name == "udp")
}

func resolvedServerEndpoint() string {
	if configured := strings.TrimSpace(getConfig("server_endpoint")); configured != "" {
		return configured
	}
	if t := resolveDefaultTransportConfigUI(); t != nil && strings.EqualFold(strings.TrimSpace(t.Base), "turn") {
		status := fetchDaemonStatus()
		for _, ts := range status.Transports {
			if ts.Name == t.Name && ts.RelayAddr != "" {
				return ts.RelayAddr
			}
		}
	}
	host := detectDefaultBootstrapIP()
	if host == "" {
		host = "127.0.0.1"
	}
	port := 51820
	if t := resolveDefaultTransportConfigUI(); t != nil && t.ListenPort > 0 {
		port = t.ListenPort
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return netip.AddrPortFrom(addr, uint16(port)).String()
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func detectDefaultBootstrapIP() string {
	if ip := detectDefaultRouteSourceIP(); ip.IsValid() && !ip.IsLoopback() {
		if iface := interfaceForAddr(ip); iface != nil && !looksTunnelInterface(iface.Name) {
			return ip.String()
		}
	}
	var first string
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || looksTunnelInterface(iface.Name) {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, raw := range addrs {
			prefix, err := netip.ParsePrefix(raw.String())
			if err != nil {
				continue
			}
			ip := prefix.Addr().Unmap()
			if !ip.IsValid() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() {
				continue
			}
			if first == "" {
				first = ip.String()
			}
		}
	}
	return first
}

func detectDefaultRouteSourceIP() netip.Addr {
	for _, target := range []string{"1.1.1.1:53", "8.8.8.8:53", "[2606:4700:4700::1111]:53"} {
		conn, err := net.Dial("udp", target)
		if err != nil {
			continue
		}
		addr := conn.LocalAddr()
		_ = conn.Close()
		if addr == nil {
			continue
		}
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			continue
		}
		ip, err := netip.ParseAddr(host)
		if err == nil {
			return ip.Unmap()
		}
	}
	return netip.Addr{}
}

func interfaceForAddr(ip netip.Addr) *net.Interface {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, raw := range addrs {
			prefix, err := netip.ParsePrefix(raw.String())
			if err != nil {
				continue
			}
			if prefix.Addr().Unmap() == ip {
				return &iface
			}
		}
	}
	return nil
}

func detectIPv6Internet() bool {
	targets := []string{"[2606:4700:4700::1111]:53", "[2001:4860:4860::8888]:53", "[2620:fe::fe]:53"}
	for _, t := range targets {
		conn, err := net.DialTimeout("udp", t, 2*time.Second)
		if err != nil {
			continue
		}
		conn.Close()
		return true
	}
	return false
}

func looksTunnelInterface(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, prefix := range []string{"tun", "tap", "wg", "utun", "zt", "tailscale"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}
