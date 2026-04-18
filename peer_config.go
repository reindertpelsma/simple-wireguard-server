package main

import (
	"fmt"
	"regexp"
	"strings"
)

var publicConfigKeys = []string{
	"allow_custom_private_key",
	"client_dns",
	"default_transport",
	"e2e_encryption_enabled",
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

func buildClientConfigText(peer Peer, privateKey, presharedKey string, revealEndpoint bool) string {
	endpoint := resolvedServerEndpoint()
	if !revealEndpoint {
		endpoint = "HIDDEN"
	}
	defaultTransport := resolveDefaultTransportNameUI()
	defaultTransportConfig := resolveDefaultTransportConfigUI()

	lines := []string{
		"[Interface]",
		fmt.Sprintf("PrivateKey = %s", privateKey),
		fmt.Sprintf("Address = %s", peer.AssignedIPs),
		fmt.Sprintf("DNS = %s", getConfig("client_dns")),
		fmt.Sprintf("MTU = %s", getConfig("global_mtu")),
		"",
		"[Peer]",
		fmt.Sprintf("PublicKey = %s", getConfig("server_pubkey")),
		fmt.Sprintf("Endpoint = %s", endpoint),
		"AllowedIPs = 0.0.0.0/0, ::/0",
	}
	if defaultTransport != "" && transportNeedsExplicitClientLine(defaultTransportConfig) {
		lines = append(lines, fmt.Sprintf("Transport = %s", defaultTransport))
	}

	if presharedKey != "" {
		lines = append(lines, fmt.Sprintf("PresharedKey = %s", presharedKey))
	}
	if peer.Keepalive > 0 {
		lines = append(lines, fmt.Sprintf("PersistentKeepalive = %d", peer.Keepalive))
	}

	return strings.Join(lines, "\n")
}
