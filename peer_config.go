package main

import (
	"fmt"
	"net/netip"
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
	"default_transport",
	"e2e_encryption_enabled",
	"enable_client_ipv6",
	"endpoints_visible",
	"global_mtu",
	"public_keys_visible",
	"server_endpoint",
	"server_pubkey",
}

var configFileNameSanitizer = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func publicConfigMap() map[string]string {
	configs := configMapForKeys(publicConfigKeys)
	configs["server_endpoint"] = resolvedServerEndpoint()
	configs["default_transport"] = resolveDefaultTransportNameUI()
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

func configDownloadName(name string) string {
	safe := strings.TrimSpace(configFileNameSanitizer.ReplaceAllString(name, "_"))
	safe = strings.Trim(safe, "._")
	if safe == "" {
		safe = "wireguard-client"
	}
	return safe + ".conf"
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
	endpoint := resolvedServerEndpoint()
	if !revealEndpoint {
		endpoint = "HIDDEN"
	}
	defaultTransport := resolveDefaultTransportNameUI()
	defaultTransportConfig := resolveDefaultTransportConfigUI()

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

	if turnURL := strings.TrimSpace(getConfig("client_config_turn_url")); turnURL != "" {
		lines = append(lines, fmt.Sprintf("#!TURN=%s", turnURL))
	}

	lines = append(lines,
		"",
		"[Peer]",
		fmt.Sprintf("PublicKey = %s", getConfig("server_pubkey")),
		fmt.Sprintf("Endpoint = %s", endpoint),
		fmt.Sprintf("AllowedIPs = %s", allowedIPs),
	)

	if defaultTransport != "" && transportNeedsExplicitClientLine(defaultTransportConfig) {
		lines = append(lines, fmt.Sprintf("Transport = %s", defaultTransport))
	}

	if tcp := strings.TrimSpace(getConfig("client_config_tcp")); tcp != "" && tcp != "no" {
		lines = append(lines, fmt.Sprintf("#!TCP=%s", tcp))
	}
	if strings.TrimSpace(getConfig("client_config_skipverifytls")) == "yes" {
		lines = append(lines, "#!SkipVerifyTLS=yes")
	}
	if u := strings.TrimSpace(getConfig("client_config_url")); u != "" {
		lines = append(lines, fmt.Sprintf("#!URL=%s", u))
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
