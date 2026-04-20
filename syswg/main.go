package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/miekg/dns"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"gopkg.in/yaml.v3"
)

var (
	apiListen  = flag.String("api-listen", "unix:///tmp/uwgsocks.sock", "API listen address")
	ifName     = flag.String("interface", "wg0", "WireGuard interface name")
	wgConfig   = flag.String("config", "uwg_canonical.yaml", "Canonical YAML config")
	masquerade = flag.Bool("masquerade", true, "Enable NAT masquerading for peers")
)

type Manager struct {
	mu     sync.RWMutex
	client *wgctrl.Client
	nft    *nftables.Conn
	dns    *dns.Server

	aclMu        sync.RWMutex
	aclCfg       ACLConfig
	aclAvailable bool
}

type Action string

const (
	Allow Action = "allow"
	Deny  Action = "deny"
)

type PortRange struct {
	From uint16 `yaml:"from" json:"from"`
	To   uint16 `yaml:"to" json:"to"`
}

func (r PortRange) Contains(port uint16) bool {
	return port >= r.From && port <= r.To
}

type Rule struct {
	Action Action `yaml:"action" json:"action"`

	Source      string `yaml:"source" json:"source"`
	Destination string `yaml:"destination" json:"destination"`
	SourcePort  string `yaml:"source_port" json:"source_port"`
	DestPort    string `yaml:"destination_port" json:"destination_port"`
	Protocol    string `yaml:"protocol" json:"protocol"`
}

type ACLConfig struct {
	InboundDefault  Action `json:"inbound_default" yaml:"inbound_default"`
	OutboundDefault Action `json:"outbound_default" yaml:"outbound_default"`
	RelayDefault    Action `json:"relay_default" yaml:"relay_default"`

	Inbound  []Rule `json:"inbound" yaml:"inbound"`
	Outbound []Rule `json:"outbound" yaml:"outbound"`
	Relay    []Rule `json:"relay" yaml:"relay"`
}

func main() {
	flag.Parse()

	m, err := NewManager()
	if err != nil {
		log.Fatalf("Failed to initialize manager: %v", err)
	}

	// Initial config sync
	if err := m.SyncConfig(); err != nil {
		log.Printf("Warning: Initial config sync failed: %v", err)
	}

	// API Router
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", m.handleStatus)
	mux.HandleFunc("GET /v1/peers", m.handleGetPeers)
	mux.HandleFunc("GET /v1/peers/{pub}", m.handleGetPeer)
	mux.HandleFunc("POST /v1/peers", m.handleSetPeer)
	mux.HandleFunc("DELETE /v1/peers", m.handleDeletePeer)
	mux.HandleFunc("GET /v1/interface_ips", m.handleInterfaceIPs)
	mux.HandleFunc("GET /v1/ping", m.handlePing)
	mux.HandleFunc("PUT /v1/wireguard/config", m.handleUpdateConfig)
	mux.HandleFunc("GET /v1/acls", m.handleGetACLs)
	mux.HandleFunc("PUT /v1/acls", m.handleUpdateACLs)
	mux.HandleFunc("POST /v1/acls", m.handleUpdateACLs)
	mux.HandleFunc("PUT /v1/acl", m.handleUpdateACLs)
	mux.HandleFunc("POST /v1/acl", m.handleUpdateACLs)
	mux.HandleFunc("POST /v1/acls/{list}", m.handleAddACL)
	mux.HandleFunc("DELETE /v1/acls/{list}", m.handleDeleteACL)

	// Listen

	var ln net.Listener
	if strings.HasPrefix(*apiListen, "unix://") {
		path := strings.TrimPrefix(*apiListen, "unix://")
		os.Remove(path)
		ln, err = net.Listen("unix", path)
	} else {
		ln, err = net.Listen("tcp", *apiListen)
	}
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	go http.Serve(ln, mux)
	log.Printf("uwgkm (Kernel Manager) listening on %s", *apiListen)

	// Wait for signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	m.Cleanup()
}

func NewManager() (*Manager, error) {
	wg, err := wgctrl.New()
	if err != nil {
		return nil, err
	}

	m := &Manager{
		client: wg,
		nft:    &nftables.Conn{},
		aclCfg: ACLConfig{
			InboundDefault:  Allow,
			OutboundDefault: Allow,
			RelayDefault:    Allow,
		},
	}

	if err := m.ensureInterface(); err != nil {
		return nil, err
	}

	if err := m.applyACLs(m.aclCfg); err != nil {
		if isNFTUnavailable(err) {
			log.Printf("Warning: nftables unavailable; ACLs disabled: %v", err)
			m.aclAvailable = false
		} else {
			return nil, fmt.Errorf("failed to apply initial ACLs: %w", err)
		}
	} else {
		m.aclAvailable = true
	}

	return m, nil
}

func (m *Manager) ensureInterface() error {
	link, err := netlink.LinkByName(*ifName)
	if err != nil {
		// Create interface
		wgLink := &netlink.GenericLink{
			LinkAttrs: netlink.LinkAttrs{Name: *ifName},
			LinkType:  "wireguard",
		}
		if err := netlink.LinkAdd(wgLink); err != nil {
			return fmt.Errorf("failed to create wireguard interface: %w", err)
		}
		link = wgLink
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to set interface up: %w", err)
	}

	return nil
}

func (m *Manager) SyncConfig() error {
	data, err := os.ReadFile(*wgConfig)
	if err != nil {
		return err
	}

	var cfg struct {
		WireGuard struct {
			PrivateKey string   `yaml:"private_key"`
			Addresses  []string `yaml:"addresses"`
			ListenPort *int     `yaml:"listen_port"`
		} `yaml:"wireguard"`
		ACL ACLConfig `yaml:"acl"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return err
	}

	// 1. Set Private Key & Port
	if cfg.WireGuard.PrivateKey != "" {
		key, err := wgtypes.ParseKey(cfg.WireGuard.PrivateKey)
		if err != nil {
			return fmt.Errorf("invalid private key: %w", err)
		}

		port := 51820
		if cfg.WireGuard.ListenPort != nil {
			port = *cfg.WireGuard.ListenPort
		}

		err = m.client.ConfigureDevice(*ifName, wgtypes.Config{
			PrivateKey: &key,
			ListenPort: &port,
		})
		if err != nil {
			return fmt.Errorf("failed to configure device: %w", err)
		}
	}

	// 2. Set Interface IPs
	link, err := netlink.LinkByName(*ifName)
	if err != nil {
		return err
	}

	for _, addrStr := range cfg.WireGuard.Addresses {
		addr, err := netlink.ParseAddr(addrStr)
		if err != nil {
			log.Printf("Failed to parse address %s: %v", addrStr, err)
			continue
		}
		// Check if already exists
		existing, _ := netlink.AddrList(link, netlink.FAMILY_ALL)
		found := false
		for _, e := range existing {
			if e.IPNet.String() == addr.IPNet.String() {
				found = true
				break
			}
		}
		if !found {
			if err := netlink.AddrAdd(link, addr); err != nil {
				log.Printf("Failed to add address %s: %v", addrStr, err)
			}
		}
	}

	// 3. Start DNS Server
	m.startDNSServer(cfg.WireGuard.Addresses)

	// 4. Setup NAT
	if *masquerade {
		m.setupNAT(cfg.WireGuard.Addresses)
	}

	// 5. Setup ACLs
	if m.aclAvailable {
		if err := m.applyACLs(cfg.ACL); err != nil {
			log.Printf("Failed to apply ACLs from config: %v", err)
		} else {
			m.aclMu.Lock()
			m.aclCfg = cfg.ACL
			m.aclMu.Unlock()
		}
	}

	return nil
}

func (m *Manager) startDNSServer(addresses []string) {
	if len(addresses) == 0 {
		return
	}
	// Use first address (IP part)
	ip, _, _ := strings.Cut(addresses[0], "/")

	m.mu.Lock()
	if m.dns != nil {
		m.dns.Shutdown()
	}

	addr := net.JoinHostPort(ip, "53")
	m.dns = &dns.Server{Addr: addr, Net: "udp"}
	m.dns.Handler = dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		c := new(dns.Client)
		// Forward to system DNS (simple version)
		rs, _, err := c.Exchange(r, "8.8.8.8:53")
		if err != nil {
			dns.HandleFailed(w, r)
			return
		}
		w.WriteMsg(rs)
	})
	m.mu.Unlock()

	go func() {
		log.Printf("Embedded DNS listening on %s", addr)
		if err := m.dns.ListenAndServe(); err != nil {
			log.Printf("DNS server failed: %v", err)
		}
	}()
}

func (m *Manager) Cleanup() {
	m.mu.Lock()
	if m.dns != nil {
		_ = m.dns.Shutdown()
	}
	m.mu.Unlock()

	m.client.Close()
	log.Println("uwgkm shutting down...")
}

// --- API Handlers ---

func (m *Manager) handleInterfaceIPs(w http.ResponseWriter, r *http.Request) {
	link, _ := netlink.LinkByName(*ifName)
	addrs, _ := netlink.AddrList(link, netlink.FAMILY_ALL)
	var out []string
	for _, a := range addrs {
		out = append(out, a.IPNet.String())
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func (m *Manager) handleStatus(w http.ResponseWriter, r *http.Request) {
	d, err := m.client.Device(*ifName)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	res := map[string]interface{}{
		"name":        d.Name,
		"public_key":  d.PublicKey.String(),
		"listen_port": d.ListenPort,
		"num_peers":   len(d.Peers),
		"peers":       d.Peers,
		"aclDisabled": !m.aclAvailable,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func (m *Manager) handlePing(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		http.Error(w, "missing target", 400)
		return
	}

	count, _ := strconv.Atoi(r.URL.Query().Get("count"))
	if count == 0 {
		count = 1
	}

	log.Printf("Ping request: %s (count=%d)", target, count)

	// Execute system ping (simplest for kernel mode)
	cmd := exec.Command("ping", "-c", strconv.Itoa(count), "-W", "1", target)
	out, err := cmd.CombinedOutput()

	res := map[string]interface{}{
		"target":  target,
		"output":  string(out),
		"success": err == nil,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func (m *Manager) handleGetPeers(w http.ResponseWriter, r *http.Request) {
	d, err := m.client.Device(*ifName)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(d.Peers)
}

func (m *Manager) handleSetPeer(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PublicKey           string   `json:"public_key"`
		AllowedIPs          []string `json:"allowed_ips"`
		PresharedKey        string   `json:"preshared_key"`
		PersistentKeepalive int      `json:"persistent_keepalive"`
		Endpoint            string   `json:"endpoint"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	key, err := wgtypes.ParseKey(req.PublicKey)
	if err != nil {
		http.Error(w, "invalid public key", 400)
		return
	}

	var allowedIPs []net.IPNet
	for _, s := range req.AllowedIPs {
		_, n, err := net.ParseCIDR(s)
		if err == nil {
			allowedIPs = append(allowedIPs, *n)
		}
	}

	peer := wgtypes.PeerConfig{
		PublicKey:         key,
		ReplaceAllowedIPs: true,
		AllowedIPs:        allowedIPs,
	}

	if req.PresharedKey != "" {
		psk, _ := wgtypes.ParseKey(req.PresharedKey)
		peer.PresharedKey = &psk
	}
	if req.PersistentKeepalive > 0 {
		ka := time.Duration(req.PersistentKeepalive) * time.Second
		peer.PersistentKeepaliveInterval = &ka
	}
	if req.Endpoint != "" {
		addr, err := net.ResolveUDPAddr("udp", req.Endpoint)
		if err == nil {
			peer.Endpoint = addr
		}
	}

	err = m.client.ConfigureDevice(*ifName, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peer},
	})
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.WriteHeader(200)
}

func (m *Manager) handleDeletePeer(w http.ResponseWriter, r *http.Request) {
	pub := r.URL.Query().Get("public_key")
	key, err := wgtypes.ParseKey(pub)
	if err != nil {
		http.Error(w, "invalid key", 400)
		return
	}

	err = m.client.ConfigureDevice(*ifName, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{
			{PublicKey: key, Remove: true},
		},
	})
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.WriteHeader(200)
}

func (m *Manager) handleGetPeer(w http.ResponseWriter, r *http.Request) {
	pub := r.PathValue("pub")
	d, err := m.client.Device(*ifName)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	for _, p := range d.Peers {
		if p.PublicKey.String() == pub {
			json.NewEncoder(w).Encode(p)
			return
		}
	}
	http.Error(w, "peer not found", 404)
}

func (m *Manager) handleUpdateConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Config string `json:"config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	// Note: in kernel mode, we typically want to parse the canonical YAML
	// instead of raw UAPI text if possible, but we'll accept raw config
	// and write it to disk then sync.
	os.WriteFile(*wgConfig, []byte(req.Config), 0644)
	if err := m.SyncConfig(); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.WriteHeader(200)
}

func (m *Manager) handleGetACLs(w http.ResponseWriter, r *http.Request) {
	m.aclMu.RLock()
	cfg := m.aclCfg
	m.aclMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cfg)
}

func (m *Manager) handleUpdateACLs(w http.ResponseWriter, r *http.Request) {
	if !m.aclAvailable {
		http.Error(w, "ACL enforcement unavailable: nftables not supported or insufficient privileges", http.StatusServiceUnavailable)
		return
	}

	var next ACLConfig
	if err := json.NewDecoder(r.Body).Decode(&next); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := validateACLConfig(next); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := m.applyACLs(next); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	m.aclMu.Lock()
	m.aclCfg = next
	m.aclMu.Unlock()

	w.WriteHeader(http.StatusNoContent)
}

func (m *Manager) handleAddACL(w http.ResponseWriter, r *http.Request) {
	list := strings.ToLower(r.PathValue("list"))
	if list != "inbound" && list != "outbound" && list != "relay" {
		http.Error(w, "invalid ACL list; must be inbound, outbound, or relay", http.StatusBadRequest)
		return
	}

	if !m.aclAvailable {
		http.Error(w, "ACL enforcement unavailable: nftables not supported or insufficient privileges", http.StatusServiceUnavailable)
		return
	}

	var rule Rule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	m.aclMu.RLock()
	next := cloneACLConfig(m.aclCfg)
	m.aclMu.RUnlock()

	appendACLRuleByName(&next, list, rule)

	if err := validateACLConfig(next); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := m.applyACLs(next); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	m.aclMu.Lock()
	m.aclCfg = next
	m.aclMu.Unlock()

	w.WriteHeader(http.StatusNoContent)
}

func (m *Manager) handleDeleteACL(w http.ResponseWriter, r *http.Request) {
	list := strings.ToLower(r.PathValue("list"))
	if list != "inbound" && list != "outbound" && list != "relay" {
		http.Error(w, "invalid ACL list; must be inbound, outbound, or relay", http.StatusBadRequest)
		return
	}

	if !m.aclAvailable {
		http.Error(w, "ACL enforcement unavailable: nftables not supported or insufficient privileges", http.StatusServiceUnavailable)
		return
	}

	idxStr := r.URL.Query().Get("idx")
	if idxStr == "" {
		http.Error(w, "missing idx query parameter", http.StatusBadRequest)
		return
	}
	idx, err := strconv.Atoi(idxStr)
	if err != nil || idx < 0 {
		http.Error(w, "invalid idx", http.StatusBadRequest)
		return
	}

	m.aclMu.RLock()
	next := cloneACLConfig(m.aclCfg)
	m.aclMu.RUnlock()

	if !deleteACLRuleByName(&next, list, idx) {
		http.Error(w, "rule index out of range", http.StatusNotFound)
		return
	}

	if err := validateACLConfig(next); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := m.applyACLs(next); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	m.aclMu.Lock()
	m.aclCfg = next
	m.aclMu.Unlock()

	w.WriteHeader(http.StatusNoContent)
}

func cloneACLConfig(in ACLConfig) ACLConfig {
	out := ACLConfig{
		InboundDefault:  in.InboundDefault,
		OutboundDefault: in.OutboundDefault,
		RelayDefault:    in.RelayDefault,
		Inbound:         append([]Rule(nil), in.Inbound...),
		Outbound:        append([]Rule(nil), in.Outbound...),
		Relay:           append([]Rule(nil), in.Relay...),
	}
	return out
}

func appendACLRuleByName(c *ACLConfig, name string, rule Rule) {
	switch name {
	case "inbound":
		c.Inbound = append(c.Inbound, rule)
	case "outbound":
		c.Outbound = append(c.Outbound, rule)
	case "relay":
		c.Relay = append(c.Relay, rule)
	}
}

func deleteACLRuleByName(c *ACLConfig, name string, idx int) bool {
	switch name {
	case "inbound":
		if idx >= len(c.Inbound) {
			return false
		}
		c.Inbound = append(c.Inbound[:idx], c.Inbound[idx+1:]...)
	case "outbound":
		if idx >= len(c.Outbound) {
			return false
		}
		c.Outbound = append(c.Outbound[:idx], c.Outbound[idx+1:]...)
	case "relay":
		if idx >= len(c.Relay) {
			return false
		}
		c.Relay = append(c.Relay[:idx], c.Relay[idx+1:]...)
	default:
		return false
	}
	return true
}

func validateACLConfig(c ACLConfig) error {
	if err := validateAction(c.InboundDefault); err != nil {
		return fmt.Errorf("inbound_default: %w", err)
	}
	if err := validateAction(c.OutboundDefault); err != nil {
		return fmt.Errorf("outbound_default: %w", err)
	}
	if err := validateAction(c.RelayDefault); err != nil {
		return fmt.Errorf("relay_default: %w", err)
	}

	for i, r := range c.Inbound {
		if err := validateRule(r); err != nil {
			return fmt.Errorf("inbound[%d]: %w", i, err)
		}
	}
	for i, r := range c.Outbound {
		if err := validateRule(r); err != nil {
			return fmt.Errorf("outbound[%d]: %w", i, err)
		}
	}
	for i, r := range c.Relay {
		if err := validateRule(r); err != nil {
			return fmt.Errorf("relay[%d]: %w", i, err)
		}
	}
	return nil
}

func validateAction(a Action) error {
	switch a {
	case Allow, Deny:
		return nil
	default:
		return fmt.Errorf("must be %q or %q", Allow, Deny)
	}
}

func validateRule(r Rule) error {
	if err := validateAction(r.Action); err != nil {
		return fmt.Errorf("action: %w", err)
	}
	if _, _, err := parseCIDROpt(r.Source); err != nil {
		return fmt.Errorf("source: %w", err)
	}
	if _, _, err := parseCIDROpt(r.Destination); err != nil {
		return fmt.Errorf("destination: %w", err)
	}
	if _, err := parsePortRangeOpt(r.SourcePort); err != nil {
		return fmt.Errorf("source_port: %w", err)
	}
	if _, err := parsePortRangeOpt(r.DestPort); err != nil {
		return fmt.Errorf("destination_port: %w", err)
	}

	srcFam, _, _ := parseCIDROpt(r.Source)
	dstFam, _, _ := parseCIDROpt(r.Destination)
	if srcFam != 0 && dstFam != 0 && srcFam != dstFam {
		return errors.New("source and destination families differ")
	}

	return nil
}

func parseCIDROpt(s string) (family int, pfx *netip.Prefix, err error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" || s == "*" || s == "any" {
		return 0, nil, nil
	}

	p, err := netip.ParsePrefix(s)
	if err != nil {
		return 0, nil, err
	}

	if p.Addr().Is4() {
		return 4, &p, nil
	}
	if p.Addr().Is6() {
		return 6, &p, nil
	}
	return 0, nil, fmt.Errorf("unsupported prefix family")
}

func parsePortRangeOpt(s string) (*PortRange, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" || s == "*" || s == "any" {
		return nil, nil
	}

	if !strings.Contains(s, "-") {
		v, err := strconv.ParseUint(s, 10, 16)
		if err != nil {
			return nil, err
		}
		p := &PortRange{From: uint16(v), To: uint16(v)}
		return p, nil
	}

	parts := strings.SplitN(s, "-", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid port range")
	}

	from, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 16)
	if err != nil {
		return nil, err
	}
	to, err := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 16)
	if err != nil {
		return nil, err
	}
	if from > to {
		return nil, fmt.Errorf("port range start greater than end")
	}

	return &PortRange{From: uint16(from), To: uint16(to)}, nil
}

func (m *Manager) applyACLs(cfg ACLConfig) error {
	// Rebuild both IPv4 and IPv6 tables from scratch.
	if err := m.applyACLFamily(cfg, nftables.TableFamilyIPv4, "uwgkm_acl4"); err != nil {
		return err
	}
	if err := m.applyACLFamily(cfg, nftables.TableFamilyIPv6, "uwgkm_acl6"); err != nil {
		return err
	}
	return nil
}


func (m *Manager) applyACLFamily(cfg ACLConfig, family nftables.TableFamily, tableName string) error {
	existingConn := &nftables.Conn{}

	tables, err := existingConn.ListTablesOfFamily(family)
	if err != nil {
		// Treat ENOENT as "nothing exists yet" for this family.
		if !isNFTNoSuchFile(err) {
			return fmt.Errorf("list nft tables for family %v: %w", family, err)
		}
		tables = nil
	}

	var existing *nftables.Table
	for _, t := range tables {
		if t != nil && t.Name == tableName && t.Family == family {
			existing = t
			break
		}
	}

	if existing != nil {
		delConn := &nftables.Conn{}
		delConn.DelTable(existing)
		if err := delConn.Flush(); err != nil && !isNFTNoSuchFile(err) {
			return fmt.Errorf("delete old nft table %s: %w", tableName, err)
		}
	}

	c := &nftables.Conn{}

	table := c.AddTable(&nftables.Table{
		Family: family,
		Name:   tableName,
	})

	inputBase := c.AddChain(&nftables.Chain{
		Name:     "input",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
	})

	outputBase := c.AddChain(&nftables.Chain{
		Name:     "output",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFilter,
	})

	forwardBase := c.AddChain(&nftables.Chain{
		Name:     "forward",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
	})

	inboundChain := c.AddChain(&nftables.Chain{
		Name:  "uwg_inbound",
		Table: table,
	})
	outboundChain := c.AddChain(&nftables.Chain{
		Name:  "uwg_outbound",
		Table: table,
	})
	relayChain := c.AddChain(&nftables.Chain{
		Name:  "uwg_relay",
		Table: table,
	})

	// connection-based dispatch
	c.AddRule(&nftables.Rule{
		Table: table,
		Chain: inputBase,
		Exprs: append(
			append(matchIIFName(*ifName), matchCTEstablishedRelated()...),
			&expr.Verdict{Kind: expr.VerdictAccept},
		),
	})
	c.AddRule(&nftables.Rule{
		Table: table,
		Chain: inputBase,
		Exprs: append(
			append(matchIIFName(*ifName), matchCTInvalid()...),
			&expr.Verdict{Kind: expr.VerdictDrop},
		),
	})
	c.AddRule(&nftables.Rule{
		Table: table,
		Chain: inputBase,
		Exprs: append(
			append(matchIIFName(*ifName), matchCTNew()...),
			&expr.Verdict{Kind: expr.VerdictJump, Chain: inboundChain.Name},
		),
	})

	c.AddRule(&nftables.Rule{
		Table: table,
		Chain: outputBase,
		Exprs: append(
			append(matchOIFName(*ifName), matchCTEstablishedRelated()...),
			&expr.Verdict{Kind: expr.VerdictAccept},
		),
	})
	c.AddRule(&nftables.Rule{
		Table: table,
		Chain: outputBase,
		Exprs: append(
			append(matchOIFName(*ifName), matchCTInvalid()...),
			&expr.Verdict{Kind: expr.VerdictDrop},
		),
	})
	c.AddRule(&nftables.Rule{
		Table: table,
		Chain: outputBase,
		Exprs: append(
			append(matchOIFName(*ifName), matchCTNew()...),
			&expr.Verdict{Kind: expr.VerdictJump, Chain: outboundChain.Name},
		),
	})

	// relay first
	c.AddRule(&nftables.Rule{
		Table: table,
		Chain: forwardBase,
		Exprs: append(
			append(append(matchIIFName(*ifName), matchOIFName(*ifName)...), matchCTEstablishedRelated()...),
			&expr.Verdict{Kind: expr.VerdictAccept},
		),
	})
	c.AddRule(&nftables.Rule{
		Table: table,
		Chain: forwardBase,
		Exprs: append(
			append(append(matchIIFName(*ifName), matchOIFName(*ifName)...), matchCTInvalid()...),
			&expr.Verdict{Kind: expr.VerdictDrop},
		),
	})
	c.AddRule(&nftables.Rule{
		Table: table,
		Chain: forwardBase,
		Exprs: append(
			append(append(matchIIFName(*ifName), matchOIFName(*ifName)...), matchCTNew()...),
			&expr.Verdict{Kind: expr.VerdictJump, Chain: relayChain.Name},
		),
	})

	c.AddRule(&nftables.Rule{
		Table: table,
		Chain: forwardBase,
		Exprs: append(
			append(matchIIFName(*ifName), matchCTEstablishedRelated()...),
			&expr.Verdict{Kind: expr.VerdictAccept},
		),
	})
	c.AddRule(&nftables.Rule{
		Table: table,
		Chain: forwardBase,
		Exprs: append(
			append(matchIIFName(*ifName), matchCTInvalid()...),
			&expr.Verdict{Kind: expr.VerdictDrop},
		),
	})
	c.AddRule(&nftables.Rule{
		Table: table,
		Chain: forwardBase,
		Exprs: append(
			append(matchIIFName(*ifName), matchCTNew()...),
			&expr.Verdict{Kind: expr.VerdictJump, Chain: inboundChain.Name},
		),
	})

	c.AddRule(&nftables.Rule{
		Table: table,
		Chain: forwardBase,
		Exprs: append(
			append(matchOIFName(*ifName), matchCTEstablishedRelated()...),
			&expr.Verdict{Kind: expr.VerdictAccept},
		),
	})
	c.AddRule(&nftables.Rule{
		Table: table,
		Chain: forwardBase,
		Exprs: append(
			append(matchOIFName(*ifName), matchCTInvalid()...),
			&expr.Verdict{Kind: expr.VerdictDrop},
		),
	})
	c.AddRule(&nftables.Rule{
		Table: table,
		Chain: forwardBase,
		Exprs: append(
			append(matchOIFName(*ifName), matchCTNew()...),
			&expr.Verdict{Kind: expr.VerdictJump, Chain: outboundChain.Name},
		),
	})

	if err := addACLRules(c, table, inboundChain, family, cfg.Inbound, cfg.InboundDefault); err != nil {
		return fmt.Errorf("apply inbound ACLs (%s): %w", tableName, err)
	}
	if err := addACLRules(c, table, outboundChain, family, cfg.Outbound, cfg.OutboundDefault); err != nil {
		return fmt.Errorf("apply outbound ACLs (%s): %w", tableName, err)
	}
	if err := addACLRules(c, table, relayChain, family, cfg.Relay, cfg.RelayDefault); err != nil {
		return fmt.Errorf("apply relay ACLs (%s): %w", tableName, err)
	}

	if err := c.Flush(); err != nil {
		return fmt.Errorf("flush nftables %s: %w", tableName, err)
	}
	return nil
}

func isNFTNoSuchFile(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "no such file or directory") ||
		strings.Contains(s, "netlink receive: no such file or directory")
}

func addACLRules(c *nftables.Conn, table *nftables.Table, chain *nftables.Chain, family nftables.TableFamily, rules []Rule, def Action) error {
	for _, r := range rules {
		exprsList, err := buildRuleExprsByFamily(family, r)
		if err != nil {
			return err
		}
		for _, exprs := range exprsList {
			exprs = append(exprs, verdictForAction(r.Action))
			c.AddRule(&nftables.Rule{
				Table: table,
				Chain: chain,
				Exprs: exprs,
			})
		}
	}

	// Terminal default policy for the logical ACL chain.
	c.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{verdictForAction(def)},
	})

	return nil
}

func buildRuleExprsByFamily(family nftables.TableFamily, r Rule) ([][]expr.Any, error) {
	srcFam, srcPfx, err := parseCIDROpt(r.Source)
	if err != nil {
		return nil, err
	}
	dstFam, dstPfx, err := parseCIDROpt(r.Destination)
	if err != nil {
		return nil, err
	}
	srcPorts, err := parsePortRangeOpt(r.SourcePort)
	if err != nil {
		return nil, err
	}
	dstPorts, err := parsePortRangeOpt(r.DestPort)
	if err != nil {
		return nil, err
	}

	targetFam := 0
	if srcFam != 0 {
		targetFam = srcFam
	}
	if dstFam != 0 {
		if targetFam != 0 && dstFam != targetFam {
			return nil, fmt.Errorf("source and destination address families differ")
		}
		targetFam = dstFam
	}

	switch family {
	case nftables.TableFamilyIPv4:
		if targetFam != 0 && targetFam != 4 {
			return nil, nil
		}
	case nftables.TableFamilyIPv6:
		if targetFam != 0 && targetFam != 6 {
			return nil, nil
		}
	default:
		return nil, fmt.Errorf("unsupported nft family")
	}

	base := []expr.Any{}
	if srcPfx != nil {
		base = append(base, matchSourcePrefix(family, *srcPfx)...)
	}
	if dstPfx != nil {
		base = append(base, matchDestPrefix(family, *dstPfx)...)
	}

	hasPortConstraint := srcPorts != nil || dstPorts != nil
	if !hasPortConstraint {
		return [][]expr.Any{base}, nil
	}

	// Port constraints imply TCP/UDP-specific rules. Emit one rule for TCP and one for UDP.
	var out [][]expr.Any
	var protos []byte

	if r.Protocol == "TCP" {
            protos = []byte{6}
	} else if r.Protocol == "UDP" {
            protos = []byte{17}
	} else {
            protos = []byte{6, 17}
	}

	for _, proto := range protos { // TCP, UDP
		exprs := append([]expr.Any{}, base...)
		exprs = append(exprs, matchL4Proto(proto)...)
		if srcPorts != nil {
			exprs = append(exprs, matchTransportPortRange(0, *srcPorts)...)
		}
		if dstPorts != nil {
			exprs = append(exprs, matchTransportPortRange(2, *dstPorts)...)
		}
		out = append(out, exprs)
	}
	return out, nil
}

func verdictForAction(a Action) expr.Any {
	switch a {
	case Allow:
		return &expr.Verdict{Kind: expr.VerdictAccept}
	default:
		return &expr.Verdict{Kind: expr.VerdictDrop}
	}
}

func matchIIFName(name string) []expr.Any {
	b := ifnameBytes(name)
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: b},
	}
}

func matchOIFName(name string) []expr.Any {
	b := ifnameBytes(name)
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: b},
	}
}

func ifnameBytes(name string) []byte {
	// nftables interface-name comparisons are NUL-terminated.
	return append([]byte(name), 0x00)
}

func matchL4Proto(proto byte) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
	}
}

func matchTransportPortRange(offset uint32, pr PortRange) []expr.Any {
	from := make([]byte, 2)
	to := make([]byte, 2)
	binary.BigEndian.PutUint16(from, pr.From)
	binary.BigEndian.PutUint16(to, pr.To)

	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       offset,
			Len:          2,
		},
		&expr.Cmp{Op: expr.CmpOpGte, Register: 1, Data: from},
		&expr.Cmp{Op: expr.CmpOpLte, Register: 1, Data: to},
	}
}

func matchSourcePrefix(family nftables.TableFamily, pfx netip.Prefix) []expr.Any {
	addr := pfx.Addr()
	maskBytes := prefixMaskBytes(addr.BitLen(), pfx.Bits())
	ipBytes := addr.AsSlice()

	offset := uint32(12) // IPv4 src
	length := uint32(4)
	if family == nftables.TableFamilyIPv6 {
		offset = 8 // IPv6 src
		length = 16
	}

	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       offset,
			Len:          length,
		},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            length,
			Mask:           maskBytes,
			Xor:            zeroBytes(int(length)),
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     maskedBytes(ipBytes, maskBytes),
		},
	}
}

func matchDestPrefix(family nftables.TableFamily, pfx netip.Prefix) []expr.Any {
	addr := pfx.Addr()
	maskBytes := prefixMaskBytes(addr.BitLen(), pfx.Bits())
	ipBytes := addr.AsSlice()

	offset := uint32(16) // IPv4 dst
	length := uint32(4)
	if family == nftables.TableFamilyIPv6 {
		offset = 24 // IPv6 dst
		length = 16
	}

	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       offset,
			Len:          length,
		},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            length,
			Mask:           maskBytes,
			Xor:            zeroBytes(int(length)),
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     maskedBytes(ipBytes, maskBytes),
		},
	}
}

func prefixMaskBytes(totalBits, prefixBits int) []byte {
	n := totalBits / 8
	out := make([]byte, n)
	full := prefixBits / 8
	rem := prefixBits % 8

	for i := 0; i < full; i++ {
		out[i] = 0xff
	}
	if rem > 0 && full < len(out) {
		out[full] = ^byte(0xff >> rem)
	}
	return out
}

func maskedBytes(ip, mask []byte) []byte {
	out := make([]byte, len(ip))
	copy(out, ip)
	for i := range out {
		out[i] &= mask[i]
	}
	return out
}

func zeroBytes(n int) []byte {
	return bytes.Repeat([]byte{0x00}, n)
}

func (m *Manager) setupNAT(addresses []string) {
	c := &nftables.Conn{}

	// Create table
	table := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "uwgkm",
	})

	// Create chain
	chain := c.AddChain(&nftables.Chain{
		Name:     "postrouting",
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
	})

	// Add masquerade rule for each subnet
	for _, addrStr := range addresses {
		ip, net, err := net.ParseCIDR(addrStr)
		if err != nil || ip.To4() == nil {
			continue
		}

		c.AddRule(&nftables.Rule{
			Table: table,
			Chain: chain,
			Exprs: []expr.Any{
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       12, // src IP offset in IPv4
					Len:          4,
				},
				&expr.Bitwise{
					SourceRegister: 1,
					DestRegister:   1,
					Len:            4,
					Mask:           net.Mask,
					Xor:            net.IP.To4(),
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte{0, 0, 0, 0}, // Result should be 0 if in subnet
				},
				&expr.Masq{},
			},
		})
	}

	if err := c.Flush(); err != nil {
		log.Printf("Failed to apply nftables: %v", err)
	} else {
		log.Println("Applied nftables masquerade")
	}
}

const (
	ctStateInvalid     uint32 = 1 << 0
	ctStateEstablished uint32 = 1 << 1
	ctStateRelated     uint32 = 1 << 2
	ctStateNew         uint32 = 1 << 3
)

func matchCTStateBitsAny(bits uint32) []expr.Any {
	bufMask := make([]byte, 4)
	bufZero := make([]byte, 4)
	binary.BigEndian.PutUint32(bufMask, bits)

	return []expr.Any{
		&expr.Ct{
			Key:      expr.CtKeySTATE,
			Register: 1,
		},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           bufMask,
			Xor:            []byte{0, 0, 0, 0},
		},
		&expr.Cmp{
			Op:       expr.CmpOpNeq,
			Register: 1,
			Data:     bufZero,
		},
	}
}

func matchCTStateBitsAll(bits uint32) []expr.Any {
	bufMask := make([]byte, 4)
	bufVal := make([]byte, 4)
	binary.BigEndian.PutUint32(bufMask, bits)
	binary.BigEndian.PutUint32(bufVal, bits)

	return []expr.Any{
		&expr.Ct{
			Key:      expr.CtKeySTATE,
			Register: 1,
		},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           bufMask,
			Xor:            []byte{0, 0, 0, 0},
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     bufVal,
		},
	}
}

func matchCTNew() []expr.Any {
	return matchCTStateBitsAll(ctStateNew)
}

func matchCTEstablishedRelated() []expr.Any {
	return matchCTStateBitsAny(ctStateEstablished | ctStateRelated)
}

func matchCTInvalid() []expr.Any {
	return matchCTStateBitsAll(ctStateInvalid)
}

func isNFTUnavailable(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "operation not permitted") ||
		strings.Contains(s, "protocol not supported")
}
