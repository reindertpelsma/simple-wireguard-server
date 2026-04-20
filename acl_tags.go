package main

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// Group is the unified concept of a policy group. Every user and every peer
// config belongs to exactly one primary group, which determines the IPv4/IPv6
// subnet from which their addresses are allocated. Groups can inherit from
// parent groups for ACL expansion purposes.
type Group struct {
	ID uint `gorm:"primaryKey" json:"id"`
	// Name is the canonical lowercase group name.
	Name string `gorm:"uniqueIndex;not null" json:"name"`
	// Subnet is a fixed IPv4 CIDR assigned when the group is created.
	// Empty means the group is NOT primary-capable. Fixed after creation.
	Subnet string `json:"subnet,omitempty"`
	// SubnetIPv6 is the fixed IPv6 CIDR assigned alongside Subnet.
	// Empty means IPv6 is not allocated from a per-group prefix.
	SubnetIPv6 string `json:"subnet_ipv6,omitempty"`
	// ParentGroups is a CSV list of group names this group inherits.
	// Inherited groups are expanded transitively for ACL matching.
	ParentGroups string `json:"parent_groups,omitempty"`
	// ExtraCIDRs is a CSV list of additional CIDRs/IPs associated with
	// this group (e.g. on-premises subnets you want to allow alongside
	// the group members).
	ExtraCIDRs string `json:"extra_cidrs,omitempty"`
	// BuiltIn marks system-created groups (default, admin) that cannot
	// be deleted and whose names cannot be changed.
	BuiltIn bool `gorm:"default:false" json:"built_in"`
}

// PolicyTag is kept as a GORM model alias so the old policy_tags table
// can be migrated out of. New code uses Group / groups table.
type PolicyTag = Group

type legacyPolicyTag struct {
	ID         uint
	Name       string
	ExtraCIDRs string
	ParentTags string
}

func (legacyPolicyTag) TableName() string { return "policy_tags" }

type accessIdentity struct {
	User     *User
	Username string
	Tags     []string // expanded group names (for access ACL matching)
}

func splitCSVList(s string) []string {
	seen := map[string]bool{}
	var out []string
	for _, part := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == '\t'
	}) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key := strings.ToLower(part)
		if !seen[key] {
			seen[key] = true
			out = append(out, part)
		}
	}
	return out
}

func joinCSVList(parts []string) string {
	return strings.Join(splitCSVList(strings.Join(parts, ",")), ", ")
}

func normalizeGroupName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

func normalizeGroupList(groups []string) string {
	normalized := make([]string, 0, len(groups))
	for _, group := range groups {
		if name := normalizeGroupName(group); name != "" {
			normalized = append(normalized, name)
		}
	}
	return joinCSVList(normalized)
}

func hasAdminGroup(groups string) bool {
	return containsToken(splitCSVList(groups), "admin")
}

func userIsAdmin(user User) bool {
	return user.IsAdmin || containsToken(userGroups(user), "admin")
}

func primaryGroupExists(name string) (Group, bool) {
	name = normalizeGroupName(name)
	if name == "" {
		return Group{}, false
	}
	var group Group
	if err := gdb.First(&group, "name = ? AND subnet <> ?", name, "").Error; err != nil {
		return Group{}, false
	}
	return group, true
}

// userGroups returns all group names for a user (primary + additional),
// then expands through inherited parents.
func userGroups(user User) []string {
	all := splitCSVList(user.Tags)
	if user.PrimaryGroup != "" {
		all = append([]string{user.PrimaryGroup}, all...)
	}
	return expandGroupNames(all)
}

// peerGroups returns all group names for a peer (primary + additional),
// then expands through inherited parents.
func peerGroups(peer Peer) []string {
	all := splitCSVList(peer.Tags)
	if peer.PrimaryGroup != "" {
		all = append([]string{peer.PrimaryGroup}, all...)
	}
	return expandGroupNames(all)
}

// Legacy helpers kept for code that still calls the old names.
func userTags(user User) []string { return userGroups(user) }
func peerTags(peer Peer) []string { return peerGroups(peer) }

func identityForUser(user User) accessIdentity {
	return accessIdentity{User: &user, Username: user.Username, Tags: userGroups(user)}
}

func identityFromSessionToken(token string) (accessIdentity, bool) {
	if token == "" {
		return accessIdentity{}, false
	}
	var user User
	if err := gdb.First(&user, "token = ?", token).Error; err != nil {
		return accessIdentity{}, false
	}
	return identityForUser(user), true
}

func rawGroupName(g Group) string {
	return normalizeGroupName(g.Name)
}

func loadGroupMap() map[string]Group {
	var groups []Group
	gdb.Find(&groups)
	out := make(map[string]Group, len(groups))
	for _, g := range groups {
		name := rawGroupName(g)
		if name != "" {
			out[name] = g
		}
	}
	return out
}

func expandGroupNames(names []string) []string {
	groupMap := loadGroupMap()
	seen := map[string]bool{}
	var out []string
	var visit func(string)
	visit = func(name string) {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		out = append(out, name)
		g, ok := groupMap[name]
		if !ok {
			return
		}
		for _, parent := range splitCSVList(g.ParentGroups) {
			visit(parent)
		}
	}
	for _, name := range names {
		visit(name)
	}
	return out
}

func validateGroupGraph(candidate *Group) error {
	groupMap := loadGroupMap()
	if candidate != nil {
		name := rawGroupName(*candidate)
		if name == "" {
			return fmt.Errorf("group name is required")
		}
		for _, g := range groupMap {
			if g.ID != candidate.ID && rawGroupName(g) == name {
				return fmt.Errorf("group already exists")
			}
		}
		for oldName, g := range groupMap {
			if g.ID == candidate.ID && oldName != name {
				delete(groupMap, oldName)
			}
		}
		groupMap[name] = *candidate
	}

	for name, g := range groupMap {
		for _, parent := range splitCSVList(g.ParentGroups) {
			parent = strings.ToLower(strings.TrimSpace(parent))
			if parent == "" {
				continue
			}
			if parent == name {
				return fmt.Errorf("group %q cannot inherit itself", name)
			}
			if _, ok := groupMap[parent]; !ok {
				return fmt.Errorf("parent group %q does not exist", parent)
			}
		}
	}

	state := map[string]int{}
	var visit func(string) error
	visit = func(name string) error {
		switch state[name] {
		case 1:
			return fmt.Errorf("group inheritance cycle includes %q", name)
		case 2:
			return nil
		}
		state[name] = 1
		for _, parent := range splitCSVList(groupMap[name].ParentGroups) {
			parent = strings.ToLower(strings.TrimSpace(parent))
			if parent == "" {
				continue
			}
			if err := visit(parent); err != nil {
				return err
			}
		}
		state[name] = 2
		return nil
	}
	for name := range groupMap {
		if err := visit(name); err != nil {
			return err
		}
	}
	return nil
}

// Legacy wrapper used in main.go handlers.
func validatePolicyTagGraph(candidate *Group) error { return validateGroupGraph(candidate) }

func groupMatchesSelector(g Group, selector string) bool {
	selector = strings.ToLower(strings.TrimSpace(selector))
	if selector == "" {
		return false
	}
	return containsToken(expandGroupNames([]string{g.Name}), selector)
}

// Legacy alias.
func policyTagMatchesSelector(g Group, selector string) bool {
	return groupMatchesSelector(g, selector)
}

// ---------------------------------------------------------------------------
// CIDR aggregation
// ---------------------------------------------------------------------------

// aggregateCIDRs takes a deduplicated list of CIDR strings and returns a
// minimal equivalent set by removing covered prefixes and merging adjacent
// sibling prefixes into their parent.
func aggregateCIDRs(cidrs []string) []string {
	seen := map[string]bool{}
	var v4, v6 []netip.Prefix
	for _, cidr := range cidrs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		p, err := netip.ParsePrefix(cidr)
		if err != nil {
			addr, err2 := netip.ParseAddr(cidr)
			if err2 != nil {
				continue
			}
			bits := 128
			if addr.Is4() {
				bits = 32
			}
			p = netip.PrefixFrom(addr.Unmap(), bits)
		}
		p = p.Masked()
		key := p.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		if p.Addr().Is4() {
			v4 = append(v4, p)
		} else {
			v6 = append(v6, p)
		}
	}
	var out []string
	for _, p := range mergePrefixes(v4) {
		out = append(out, p.String())
	}
	for _, p := range mergePrefixes(v6) {
		out = append(out, p.String())
	}
	return out
}

// mergePrefixes sorts, deduplicates covered prefixes, then iteratively merges
// adjacent sibling pairs until stable.
func mergePrefixes(ps []netip.Prefix) []netip.Prefix {
	if len(ps) == 0 {
		return nil
	}
	sort.Slice(ps, func(i, j int) bool {
		ai := ps[i].Addr().As16()
		aj := ps[j].Addr().As16()
		for k := range ai {
			if ai[k] != aj[k] {
				return ai[k] < aj[k]
			}
		}
		return ps[i].Bits() < ps[j].Bits()
	})
	// Remove prefixes fully covered by an earlier (wider) prefix.
	deduped := ps[:1]
	for _, p := range ps[1:] {
		last := deduped[len(deduped)-1]
		if last.Bits() <= p.Bits() && last.Contains(p.Addr()) {
			continue
		}
		deduped = append(deduped, p)
	}
	// Iteratively merge adjacent siblings.
	for {
		merged := make([]netip.Prefix, 0, len(deduped))
		i := 0
		changed := false
		for i < len(deduped) {
			if i+1 < len(deduped) {
				p1, p2 := deduped[i], deduped[i+1]
				if p1.Bits() == p2.Bits() && p1.Bits() > 0 {
					par1 := netip.PrefixFrom(p1.Addr(), p1.Bits()-1).Masked()
					par2 := netip.PrefixFrom(p2.Addr(), p2.Bits()-1).Masked()
					if par1 == par2 {
						merged = append(merged, par1)
						i += 2
						changed = true
						continue
					}
				}
			}
			merged = append(merged, deduped[i])
			i++
		}
		deduped = merged
		if !changed {
			break
		}
	}
	return deduped
}

// ---------------------------------------------------------------------------
// CIDR expansion for ACL rules (sources / destinations)
// ---------------------------------------------------------------------------

// sourceCIDRsForUsers expands a list of usernames to their peer IPs.
func sourceCIDRsForUsers(usernames []string) []string {
	var out []string
	for _, username := range usernames {
		var user User
		if err := gdb.First(&user, "username = ?", strings.TrimSpace(username)).Error; err != nil {
			continue
		}
		var peers []Peer
		gdb.Where("user_id = ?", user.ID).Find(&peers)
		for _, peer := range peers {
			out = append(out, splitCSVList(peer.AssignedIPs)...)
		}
	}
	return out
}

// sourceCIDRsForGroups expands group selectors to CIDRs, using group-level
// subnets for primary-group members to minimise the number of rules needed.
func sourceCIDRsForGroups(tags []string) []string {
	var out []string
	groupMap := loadGroupMap()
	for _, selector := range tags {
		selector = strings.ToLower(strings.TrimSpace(selector))
		if selector == "" {
			continue
		}
		// Collect group-level extra CIDRs and subnets.
		primaryGroupSubnets := map[string]bool{} // subnets already added as a block
		for _, g := range groupMap {
			if !groupMatchesSelector(g, selector) {
				continue
			}
			out = append(out, splitCSVList(g.ExtraCIDRs)...)
			if g.Subnet != "" {
				// The entire group subnet covers all primary members.
				out = append(out, g.Subnet)
				if g.SubnetIPv6 != "" {
					out = append(out, g.SubnetIPv6)
				}
				primaryGroupSubnets[strings.ToLower(strings.TrimSpace(g.Name))] = true
			}
		}

		// Users: if primary group is covered by subnet, skip individual IPs.
		var users []User
		gdb.Find(&users)
		for _, user := range users {
			if !containsToken(userGroups(user), selector) {
				continue
			}
			if primaryGroupSubnets[strings.ToLower(strings.TrimSpace(user.PrimaryGroup))] {
				// Primary group's subnet was added as a block; individual IPs covered.
				continue
			}
			// Non-primary membership: add individual peer IPs.
			var peers []Peer
			gdb.Where("user_id = ?", user.ID).Find(&peers)
			for _, peer := range peers {
				out = append(out, splitCSVList(peer.AssignedIPs)...)
			}
		}

		// Peers: same logic — skip if primary group subnet is already added.
		var peers []Peer
		gdb.Find(&peers)
		for _, peer := range peers {
			if !containsToken(peerGroups(peer), selector) {
				continue
			}
			if primaryGroupSubnets[strings.ToLower(strings.TrimSpace(peer.PrimaryGroup))] {
				continue
			}
			out = append(out, splitCSVList(peer.AssignedIPs)...)
		}
	}
	return out
}

// Legacy name used by some tests.
func sourceCIDRsForTags(tags []string) []string { return sourceCIDRsForGroups(tags) }

func sourceCIDRsForPeers(names []string) []string {
	var out []string
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		var peer Peer
		if err := gdb.First(&peer, "name = ?", name).Error; err != nil {
			continue
		}
		out = append(out, splitCSVList(peer.AssignedIPs)...)
	}
	return out
}

// expandACLRuleSources returns aggregated CIDRs for daemon-push rules.
func expandACLRuleSources(rule ACLRule) []string {
	var sources []string
	sources = append(sources, splitCSVList(rule.Src)...)
	sources = append(sources, sourceCIDRsForUsers(splitCSVList(rule.SrcUsers))...)
	sources = append(sources, sourceCIDRsForGroups(splitCSVList(rule.SrcTags))...)
	sources = append(sources, sourceCIDRsForPeers(splitCSVList(rule.SrcPeers))...)
	return aggregateCIDRs(sources)
}

// expandACLRuleDests returns aggregated CIDRs (+ raw hostnames preserved) for daemon-push rules.
func expandACLRuleDests(rule ACLRule) []string {
	var dests []string
	dests = append(dests, splitCSVList(rule.Dst)...)
	dests = append(dests, sourceCIDRsForUsers(splitCSVList(rule.DstUsers))...)
	dests = append(dests, sourceCIDRsForGroups(splitCSVList(rule.DstTags))...)
	dests = append(dests, sourceCIDRsForPeers(splitCSVList(rule.DstPeers))...)
	return aggregateCIDRsKeepHostnames(dests)
}

// aggregateCIDRsKeepHostnames aggregates CIDRs like aggregateCIDRs but passes
// through non-CIDR strings (hostnames) unchanged. Used for access-proxy matching
// where the Dst field can contain hostnames.
func aggregateCIDRsKeepHostnames(entries []string) []string {
	var cidrs, hostnames []string
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if _, err := netip.ParsePrefix(e); err == nil {
			cidrs = append(cidrs, e)
		} else if _, err2 := netip.ParseAddr(e); err2 == nil {
			cidrs = append(cidrs, e)
		} else {
			hostnames = append(hostnames, e)
		}
	}
	out := aggregateCIDRs(cidrs)
	out = append(out, hostnames...)
	return out
}

func containsToken(list []string, token string) bool {
	token = strings.ToLower(strings.TrimSpace(token))
	for _, item := range list {
		if strings.ToLower(strings.TrimSpace(item)) == token {
			return true
		}
	}
	return false
}

func defaultPortForScheme(scheme string) int {
	switch strings.ToLower(scheme) {
	case "https", "wss":
		return 443
	default:
		return 80
	}
}

func hostPortForAccessTarget(rawTarget, scheme string) (string, int, bool) {
	target := strings.TrimSpace(rawTarget)
	if target == "" {
		return "", 0, false
	}
	host := target
	port := 0
	if strings.Contains(target, "://") {
		if u, err := url.Parse(target); err == nil {
			host = u.Hostname()
			if p := u.Port(); p != "" {
				port, _ = strconv.Atoi(p)
			} else {
				port = defaultPortForScheme(u.Scheme)
			}
		}
	} else {
		if h, p, err := net.SplitHostPort(target); err == nil {
			host = h
			port, _ = strconv.Atoi(p)
		}
	}
	if port == 0 {
		port = defaultPortForScheme(scheme)
	}
	return hostWithoutPort(host), port, host != ""
}

func accessAllowedByACL(r *http.Request, identity accessIdentity, host string, port int, proto string) bool {
	decision, ok := aclDecisionForAccess(r, identity, host, port, proto)
	if ok {
		return decision == "allow"
	}
	def := strings.ToLower(strings.TrimSpace(getConfig("acl_outbound_default")))
	if def != "deny" {
		def = "allow"
	}
	return def == "allow"
}

func aclDecisionForAccess(r *http.Request, identity accessIdentity, host string, port int, proto string) (string, bool) {
	var rules []ACLRule
	gdb.Where("list_name = ?", "outbound").Order("sort_order asc, id asc").Find(&rules)
	for _, rule := range rules {
		if !aclRuleMatchesAccess(rule, r, identity, host, port, proto) {
			continue
		}
		action := strings.ToLower(strings.TrimSpace(rule.Action))
		if action != "deny" {
			action = "allow"
		}
		return action, true
	}
	return "", false
}

func aclRuleMatchesAccess(rule ACLRule, r *http.Request, identity accessIdentity, host string, port int, proto string) bool {
	if rule.ListName != "outbound" {
		return false
	}

	// Check source (the connecting user/peer).
	srcMatched := rule.Src == "" && rule.SrcUsers == "" && rule.SrcTags == "" && rule.SrcPeers == ""
	if !srcMatched {
		srcIP := clientIPForRequest(r)
		srcs := expandACLRuleSources(rule)
		for _, s := range srcs {
			if prefixContainsString(s, srcIP) {
				srcMatched = true
				break
			}
		}
		if !srcMatched {
			// Also match by username/tags without converting to IP (for proxy ACL checks).
			if rule.SrcUsers != "" {
				for _, u := range splitCSVList(rule.SrcUsers) {
					if strings.EqualFold(u, identity.Username) {
						srcMatched = true
						break
					}
				}
			}
			if !srcMatched && rule.SrcTags != "" {
				for _, t := range splitCSVList(rule.SrcTags) {
					if containsToken(identity.Tags, t) {
						srcMatched = true
						break
					}
				}
			}
		}
		if !srcMatched {
			return false
		}
	}

	// Check destination (the target host/port/proto).
	dstMatched := rule.Dst == "" && rule.DstUsers == "" && rule.DstTags == "" && rule.DstPeers == ""
	if !dstMatched {
		dsts := expandACLRuleDests(rule)
		for _, d := range dsts {
			if prefixContainsString(d, host) || strings.EqualFold(d, host) {
				dstMatched = true
				break
			}
		}
		if !dstMatched {
			return false
		}
	}

	if rule.Proto != "" && !strings.EqualFold(rule.Proto, proto) && rule.Proto != "any" {
		return false
	}
	if rule.DPort != "" {
		portStr := strconv.Itoa(port)
		if !portMatchesSpec(rule.DPort, portStr) {
			return false
		}
	}
	return true
}

func prefixContainsString(cidr, ip string) bool {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return false
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return p.Contains(addr)
}

func portMatchesSpec(spec, port string) bool {
	spec = strings.TrimSpace(spec)
	port = strings.TrimSpace(port)
	if spec == "" || spec == "*" {
		return true
	}
	if strings.Contains(spec, "-") {
		parts := strings.SplitN(spec, "-", 2)
		from, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
		to, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
		p, err3 := strconv.Atoi(port)
		if err1 != nil || err2 != nil || err3 != nil {
			return false
		}
		return p >= from && p <= to
	}
	return spec == port
}
