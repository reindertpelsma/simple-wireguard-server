package main

import (
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

type PolicyTag struct {
	ID         uint   `gorm:"primaryKey" json:"id"`
	Name       string `gorm:"uniqueIndex;not null" json:"name"`
	ExtraCIDRs string `json:"extra_cidrs,omitempty"`
}

type accessIdentity struct {
	User     *User
	Username string
	Tags     []string
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

func userTags(user User) []string {
	return splitCSVList(user.Tags)
}

func peerTags(peer Peer) []string {
	return splitCSVList(peer.Tags)
}

func identityForUser(user User) accessIdentity {
	return accessIdentity{User: &user, Username: user.Username, Tags: userTags(user)}
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

func tagExtraCIDRs(tagName string) []string {
	var tag PolicyTag
	if err := gdb.First(&tag, "lower(name) = ?", strings.ToLower(strings.TrimSpace(tagName))).Error; err != nil {
		return nil
	}
	return splitCSVList(tag.ExtraCIDRs)
}

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

func sourceCIDRsForTags(tags []string) []string {
	var out []string
	for _, tag := range tags {
		out = append(out, tagExtraCIDRs(tag)...)
		var users []User
		gdb.Find(&users)
		for _, user := range users {
			if containsToken(userTags(user), tag) {
				var peers []Peer
				gdb.Where("user_id = ?", user.ID).Find(&peers)
				for _, peer := range peers {
					out = append(out, splitCSVList(peer.AssignedIPs)...)
				}
			}
		}
		var peers []Peer
		gdb.Find(&peers)
		for _, peer := range peers {
			if containsToken(peerTags(peer), tag) {
				out = append(out, splitCSVList(peer.AssignedIPs)...)
			}
		}
	}
	return out
}

func expandACLRuleSources(rule ACLRule) []string {
	var sources []string
	sources = append(sources, splitCSVList(rule.Src)...)
	sources = append(sources, sourceCIDRsForUsers(splitCSVList(rule.SrcUsers))...)
	sources = append(sources, sourceCIDRsForTags(splitCSVList(rule.SrcTags))...)
	return splitCSVList(strings.Join(sources, ","))
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
	gdb.Where("list_name = ?", "outbound").Order("priority desc").Find(&rules)
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
	if rule.Proto != "" && !strings.EqualFold(rule.Proto, proto) {
		return false
	}
	if rule.DPort != "" && !portMatches(rule.DPort, port) {
		return false
	}
	if rule.Dst != "" && !destinationMatches(rule.Dst, host) {
		return false
	}
	if rule.SrcUsers != "" {
		if identity.Username == "" || !containsToken(splitCSVList(rule.SrcUsers), identity.Username) {
			return false
		}
	}
	if rule.SrcTags != "" {
		ok := false
		for _, tag := range identity.Tags {
			if containsToken(splitCSVList(rule.SrcTags), tag) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if rule.Src != "" {
		ip, err := netip.ParseAddr(clientIPForRequest(r))
		if err != nil || !prefixListContains(rule.Src, ip.Unmap()) {
			return false
		}
	}
	return true
}

func portMatches(expr string, port int) bool {
	for _, part := range splitCSVList(expr) {
		if strings.Contains(part, "-") {
			a, b, ok := strings.Cut(part, "-")
			start, err1 := strconv.Atoi(strings.TrimSpace(a))
			end, err2 := strconv.Atoi(strings.TrimSpace(b))
			if ok && err1 == nil && err2 == nil && port >= start && port <= end {
				return true
			}
			continue
		}
		p, err := strconv.Atoi(part)
		if err == nil && p == port {
			return true
		}
	}
	return false
}

func destinationMatches(expr, host string) bool {
	if strings.TrimSpace(expr) == "" {
		return true
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return prefixListContains(expr, addr.Unmap())
	}
	for _, part := range splitCSVList(expr) {
		if strings.EqualFold(part, host) {
			return true
		}
		if _, prefix, err := net.ParseCIDR(part); err == nil {
			ips, _ := net.LookupIP(host)
			for _, ip := range ips {
				if prefix.Contains(ip) {
					return true
				}
			}
		}
	}
	return false
}

func prefixListContains(expr string, addr netip.Addr) bool {
	for _, part := range splitCSVList(expr) {
		if prefix, err := netip.ParsePrefix(part); err == nil && prefix.Contains(addr) {
			return true
		}
		if ip, err := netip.ParseAddr(part); err == nil && ip.Unmap() == addr {
			return true
		}
	}
	return false
}
