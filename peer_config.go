package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
)

var publicConfigKeys = []string{
	"allow_custom_private_key",
	"client_allowed_ips",
	"client_dns",
	"client_config_tcp",
	"client_config_turn_url",
	"client_config_skipverifytls",
	"client_config_url",
	"peer_sync_mode",
	"default_transport",
	"e2e_encryption_enabled",
	"enable_client_ipv6",
	"endpoints_visible",
	"socket_proxy_enabled",
	"global_mtu",
	"public_keys_visible",
	"server_endpoint",
	"server_pubkey",
}

type clientTransportProfile struct {
	Name          string `json:"name"`
	Label         string `json:"label"`
	Base          string `json:"base,omitempty"`
	Endpoint      string `json:"endpoint,omitempty"`
	Transport     string `json:"transport,omitempty"`
	DirectiveTCP  string `json:"directive_tcp,omitempty"`
	DirectiveTURN string `json:"directive_turn,omitempty"`
	DirectiveURL  string `json:"directive_url,omitempty"`
	Preferred     bool   `json:"preferred,omitempty"`
}

var configFileNameSanitizer = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func publicConfigMap() map[string]string {
	configs := configMapForKeys(publicConfigKeys)
	configs["server_endpoint"] = resolvedServerEndpoint()
	configs["default_transport"] = resolveDefaultTransportNameUI()
	configs["client_config_control_url"] = resolvedPeerSyncControlURL()
	if profiles, err := json.Marshal(buildClientTransportProfiles("")); err == nil {
		configs["client_transport_profiles"] = string(profiles)
	}
	return configs
}

func adminConfigMap() map[string]string {
	configs := make(map[string]string)
	var list []GlobalConfig
	gdb.Find(&list)
	for _, c := range list {
		configs[c.Key] = c.Value
	}
	return configs
}

func configMapForKeys(keys []string) map[string]string {
	configs := make(map[string]string, len(keys))
	for _, key := range keys {
		configs[key] = getConfig(key)
	}
	return configs
}

func peerHasPrivateKeyMaterial(peer Peer) bool {
	return strings.TrimSpace(peer.PrivateKey) != "" || strings.TrimSpace(peer.EncryptedPrivateKey) != ""
}

func peerSyncMode() string {
	switch strings.TrimSpace(getConfig("peer_sync_mode")) {
	case "enabled", "opt_in":
		return strings.TrimSpace(getConfig("peer_sync_mode"))
	default:
		return "disabled"
	}
}

func peerSyncActiveForPeer(peer Peer) bool {
	switch peerSyncMode() {
	case "enabled":
		return true
	case "opt_in":
		return peer.PeerSyncEnabled
	default:
		return false
	}
}

func resolvedPeerSyncControlURL() string {
	if peerSyncMode() == "disabled" {
		return ""
	}
	host := strings.TrimSpace(getConfig("client_dns"))
	port := strings.TrimSpace(getConfig("peer_sync_port"))
	if host == "" || port == "" {
		return ""
	}
	return "http://" + host + ":" + port
}

func configDownloadName(name string) string {
	safe := strings.TrimSpace(configFileNameSanitizer.ReplaceAllString(name, "_"))
	safe = strings.Trim(safe, "._")
	if safe == "" {
		safe = "wireguard-client"
	}
	return safe + ".conf"
}

func buildClientTransportProfiles(baseURL string) []clientTransportProfile {
	var transports []TransportConfig
	gdb.Order("id asc").Find(&transports)
	defaultName := resolveDefaultTransportNameUI()
	defaultEndpoint := resolvedServerEndpoint()
	status := fetchDaemonStatus()
	relayByName := make(map[string]string, len(status.Transports))
	for _, ts := range status.Transports {
		if ts.RelayAddr != "" {
			relayByName[ts.Name] = ts.RelayAddr
		}
	}

	out := make([]clientTransportProfile, 0, len(transports)+1)
	for _, t := range transports {
		profile := clientTransportProfile{
			Name:      t.Name,
			Label:     clientTransportLabel(t),
			Base:      strings.ToLower(strings.TrimSpace(normalizedTransportBase(t))),
			Preferred: t.Name == defaultName,
		}
		switch profile.Base {
		case "tcp":
			profile.Endpoint = advertisedEndpointForTransport(t, defaultEndpoint)
			profile.DirectiveTCP = "required"
		case "udp":
			profile.Endpoint = advertisedEndpointForTransport(t, defaultEndpoint)
			if transportNeedsExplicitClientLine(&t) {
				profile.Transport = t.Name
			}
		case "tls", "dtls":
			profile.Endpoint = advertisedEndpointForTransport(t, defaultEndpoint)
			profile.Transport = t.Name
		case "turn":
			profile.Endpoint = relayByName[t.Name]
			if profile.Endpoint == "" {
				profile.Endpoint = defaultEndpoint
			}
			profile.DirectiveTURN = advertisedTurnURL(t)
			if profile.DirectiveTURN == "" && transportNeedsExplicitClientLine(&t) {
				profile.Transport = t.Name
			}
		case "http", "https", "quic", "quic-ws", "url":
			profile.DirectiveURL = advertisedURLForTransport(t)
			if profile.DirectiveURL == "" {
				profile.Transport = t.Name
			}
			if profile.Endpoint == "" {
				profile.Endpoint = endpointFromURL(profile.DirectiveURL)
			}
			if profile.Endpoint == "" {
				profile.Endpoint = defaultEndpoint
			}
		default:
			profile.Endpoint = advertisedEndpointForTransport(t, defaultEndpoint)
			if transportNeedsExplicitClientLine(&t) {
				profile.Transport = t.Name
			}
		}
		if profile.Endpoint == "" && profile.DirectiveURL == "" && profile.DirectiveTURN == "" {
			continue
		}
		out = append(out, profile)
	}

	if getConfig("socket_proxy_enabled") == "true" && strings.TrimSpace(baseURL) != "" {
		socketURL := strings.TrimRight(baseURL, "/") + "/socket"
		out = append(out, clientTransportProfile{
			Name:         "ui-socket-http",
			Label:        "Single-domain /socket",
			Base:         "http",
			Endpoint:     endpointFromURL(socketURL),
			DirectiveURL: socketURL,
			Preferred:    defaultName == "ui-socket-http",
		})
	}

	if len(out) == 0 {
		out = append(out, clientTransportProfile{
			Name:      "udp",
			Label:     "WireGuard UDP",
			Base:      "udp",
			Endpoint:  defaultEndpoint,
			Preferred: true,
		})
	}
	return out
}

func clientTransportLabel(t TransportConfig) string {
	base := strings.ToLower(strings.TrimSpace(normalizedTransportBase(t)))
	switch base {
	case "turn":
		proto := strings.ToLower(strings.TrimSpace(t.TurnProtocol))
		if proto == "" {
			proto = "udp"
		}
		return "TURN " + strings.ToUpper(proto) + " (" + t.Name + ")"
	case "udp":
		return "WireGuard UDP (" + t.Name + ")"
	case "tcp":
		return "WireGuard TCP (" + t.Name + ")"
	case "tls":
		return "WireGuard TLS (" + t.Name + ")"
	case "dtls":
		return "WireGuard DTLS (" + t.Name + ")"
	case "http":
		return "WireGuard HTTP (" + t.Name + ")"
	case "https":
		return "WireGuard HTTPS (" + t.Name + ")"
	case "quic":
		return "WireGuard QUIC (" + t.Name + ")"
	case "quic-ws":
		return "WireGuard QUIC-WS (" + t.Name + ")"
	case "url":
		return "Auto URL (" + t.Name + ")"
	default:
		return strings.ToUpper(base) + " (" + t.Name + ")"
	}
}

func normalizedTransportBase(t TransportConfig) string {
	base := strings.ToLower(strings.TrimSpace(t.Base))
	if base == "udp" && strings.EqualFold(strings.TrimSpace(t.ProxyType), "turn") {
		return "turn"
	}
	return base
}

func advertisedEndpointForTransport(t TransportConfig, fallback string) string {
	raw := strings.TrimSpace(t.ExternalEndpoint)
	if raw != "" {
		if strings.Contains(raw, "://") {
			if hostport := endpointFromURL(raw); hostport != "" {
				return hostport
			}
		} else {
			return raw
		}
	}
	host := hostWithoutPort(strings.TrimSpace(getConfig("server_endpoint")))
	if host == "" {
		host = hostWithoutPort(fallback)
	}
	port := t.ListenPort
	if port <= 0 {
		port = 51820
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return netip.AddrPortFrom(addr, uint16(port)).String()
	}
	if host != "" {
		return net.JoinHostPort(host, fmt.Sprintf("%d", port))
	}
	return fallback
}

func advertisedTurnURL(t TransportConfig) string {
	if raw := strings.TrimSpace(t.ExternalEndpoint); raw != "" {
		return raw
	}
	server := strings.TrimSpace(t.TurnServer)
	if server == "" && strings.EqualFold(strings.TrimSpace(t.ProxyType), "turn") {
		server = strings.TrimSpace(t.ProxyServer)
	}
	if server == "" {
		return ""
	}
	proto := strings.ToLower(strings.TrimSpace(t.TurnProtocol))
	switch proto {
	case "", "udp":
		proto = "udp"
	case "tcp", "tls", "dtls", "http", "https", "quic":
	default:
		proto = strings.TrimPrefix(proto, "turn+")
	}
	path := ""
	switch proto {
	case "http", "https", "quic":
		path = "/turn"
	}
	user := strings.TrimSpace(t.TurnUsername)
	pass := strings.TrimSpace(t.TurnPassword)
	if user == "" && strings.EqualFold(strings.TrimSpace(t.ProxyType), "turn") {
		user = strings.TrimSpace(t.ProxyUsername)
		pass = strings.TrimSpace(t.ProxyPassword)
	}
	if user == "" {
		return proto + "://" + server + path
	}
	u := &url.URL{
		Scheme: proto,
		User:   url.UserPassword(user, pass),
		Host:   server,
		Path:   path,
	}
	return u.String()
}

func advertisedURLForTransport(t TransportConfig) string {
	if raw := strings.TrimSpace(t.ExternalEndpoint); raw != "" {
		return raw
	}
	if strings.EqualFold(strings.TrimSpace(t.Base), "url") {
		return strings.TrimSpace(t.URL)
	}
	return ""
}

func endpointFromURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return ""
	}
	host := u.Host
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	switch strings.ToLower(u.Scheme) {
	case "https", "wss", "quic", "turn+https", "turn+tls", "turn+quic", "turns":
		return net.JoinHostPort(host, "443")
	case "http", "ws":
		return net.JoinHostPort(host, "80")
	case "turn+http", "turn+tcp", "turn+udp", "turn+dtls", "turn", "tcp", "udp", "tls", "dtls":
		return net.JoinHostPort(host, "3478")
	default:
		return host
	}
}

func filterIPv6FromList(ips string) string {
	var parts []string
	for _, part := range strings.Split(ips, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(part)
		if err != nil || prefix.Addr().Unmap().Is4() {
			parts = append(parts, part)
		}
	}
	return strings.Join(parts, ", ")
}

func buildClientConfigText(peer Peer, privateKey, presharedKey string, revealEndpoint bool) string {
	profiles := buildClientTransportProfiles("")
	selected := profiles[0]
	for _, profile := range profiles {
		if profile.Preferred {
			selected = profile
			break
		}
	}
	endpoint := selected.Endpoint
	if endpoint == "" {
		endpoint = resolvedServerEndpoint()
	}
	if !revealEndpoint {
		endpoint = "HIDDEN"
	}

	// Address line: omit IPv6 component when disabled, but always show both if enabled
	assignedIPs := peer.AssignedIPs
	if getConfig("enable_client_ipv6") != "true" {
		assignedIPs = filterIPv6FromList(assignedIPs)
	}

	// AllowedIPs: always include ::/0 to prevent IPv6 bypass, configurable
	allowedIPs := strings.TrimSpace(getConfig("client_allowed_ips"))
	if allowedIPs == "" {
		allowedIPs = "0.0.0.0/0, ::/0"
	}

	lines := []string{
		"[Interface]",
		fmt.Sprintf("PrivateKey = %s", privateKey),
		fmt.Sprintf("Address = %s", assignedIPs),
		fmt.Sprintf("DNS = %s", getConfig("client_dns")),
		fmt.Sprintf("MTU = %s", getConfig("global_mtu")),
	}

	turnURL := strings.TrimSpace(selected.DirectiveTURN)
	if turnURL == "" {
		turnURL = strings.TrimSpace(getConfig("client_config_turn_url"))
	}
	if turnURL != "" {
		lines = append(lines, fmt.Sprintf("#!TURN=%s", turnURL))
	}

	lines = append(lines,
		"",
		"[Peer]",
		fmt.Sprintf("PublicKey = %s", getConfig("server_pubkey")),
		fmt.Sprintf("Endpoint = %s", endpoint),
		fmt.Sprintf("AllowedIPs = %s", allowedIPs),
	)

	if selected.Transport != "" {
		lines = append(lines, fmt.Sprintf("Transport = %s", selected.Transport))
	}

	tcpMode := strings.TrimSpace(selected.DirectiveTCP)
	if tcpMode == "" {
		tcpMode = strings.TrimSpace(getConfig("client_config_tcp"))
	}
	if tcpMode != "" && tcpMode != "no" {
		lines = append(lines, fmt.Sprintf("#!TCP=%s", tcpMode))
	}
	if strings.TrimSpace(getConfig("client_config_skipverifytls")) == "yes" {
		lines = append(lines, "#!SkipVerifyTLS=yes")
	}
	urlDirective := strings.TrimSpace(selected.DirectiveURL)
	if urlDirective == "" {
		urlDirective = strings.TrimSpace(getConfig("client_config_url"))
	}
	if u := urlDirective; u != "" {
		lines = append(lines, fmt.Sprintf("#!URL=%s", u))
	}
	if peerSyncActiveForPeer(peer) {
		if control := resolvedPeerSyncControlURL(); control != "" {
			lines = append(lines, fmt.Sprintf("#!Control=%s", control))
		}
	}

	if presharedKey != "" {
		lines = append(lines, fmt.Sprintf("PresharedKey = %s", presharedKey))
	}
	if peer.Keepalive > 0 {
		lines = append(lines, fmt.Sprintf("PersistentKeepalive = %d", peer.Keepalive))
	}

	// Append distribute peers
	for _, dp := range getDistributePeers() {
		if dp.PublicKey == peer.PublicKey {
			continue // Don't add self
		}
		if dp.Endpoint == "" {
			continue // Skip distribute peers without a known endpoint
		}
		lines = append(lines, "",
			"[Peer]",
			fmt.Sprintf("# %s (distributed)", dp.Name),
			fmt.Sprintf("PublicKey = %s", dp.PublicKey),
			fmt.Sprintf("AllowedIPs = %s", dp.AllowedIPs),
			fmt.Sprintf("Endpoint = %s", dp.Endpoint),
		)
	}

	return strings.Join(lines, "\n")
}
