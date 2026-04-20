package main

import (
	"fmt"
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
	ParentTags string `json:"parent_tags,omitempty"`
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
	return expandTagNames(splitCSVList(user.Tags))
}

func peerTags(peer Peer) []string {
	return expandTagNames(splitCSVList(peer.Tags))
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

func rawTagName(tag PolicyTag) string {
	return strings.ToLower(strings.TrimSpace(tag.Name))
}

func loadPolicyTagMap() map[string]PolicyTag {
	var tags []PolicyTag
	gdb.Find(&tags)
	out := make(map[string]PolicyTag, len(tags))
	for _, tag := range tags {
		name := rawTagName(tag)
		if name != "" {
			out[name] = tag
		}
	}
	return out
}

func expandTagNames(tags []string) []string {
	tagMap := loadPolicyTagMap()
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
		tag, ok := tagMap[name]
		if !ok {
			return
		}
		for _, parent := range splitCSVList(tag.ParentTags) {
			visit(parent)
		}
	}
	for _, tag := range tags {
		visit(tag)
	}
	return out
}

func validatePolicyTagGraph(candidate *PolicyTag) error {
	tagMap := loadPolicyTagMap()
	if candidate != nil {
		name := rawTagName(*candidate)
		if name == "" {
			return fmt.Errorf("tag name is required")
		}
		for _, tag := range tagMap {
			if tag.ID != candidate.ID && rawTagName(tag) == name {
				return fmt.Errorf("tag already exists")
			}
		}
		for oldName, tag := range tagMap {
			if tag.ID == candidate.ID && oldName != name {
				delete(tagMap, oldName)
			}
		}
		tagMap[name] = *candidate
	}

	for name, tag := range tagMap {
		for _, parent := range splitCSVList(tag.ParentTags) {
			parent = strings.ToLower(strings.TrimSpace(parent))
			if parent == "" {
				continue
			}
			if parent == name {
				return fmt.Errorf("tag %q cannot inherit itself", name)
			}
			if _, ok := tagMap[parent]; !ok {
				return fmt.Errorf("parent tag %q does not exist", parent)
			}
		}
	}

	state := map[string]int{}
	var visit func(string) error
	visit = func(name string) error {
		switch state[name] {
		case 1:
			return fmt.Errorf("tag inheritance cycle includes %q", name)
		case 2:
			return nil
		}
		state[name] = 1
		for _, parent := range splitCSVList(tagMap[name].ParentTags) {
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
	for name := range tagMap {
		if err := visit(name); err != nil {
			return err
		}
	}
	return nil
}

func policyTagMatchesSelector(tag PolicyTag, selector string) bool {
	selector = strings.ToLower(strings.TrimSpace(selector))
	if selector == "" {
		return false
	}
	return containsToken(expandTagNames([]string{tag.Name}), selector)
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
	tagMap := loadPolicyTagMap()
	for _, selector := range tags {
		selector = strings.ToLower(strings.TrimSpace(selector))
		if selector == "" {
			continue
		}
		for _, tag := range tagMap {
			if policyTagMatchesSelector(tag, selector) {
				out = append(out, splitCSVList(tag.ExtraCIDRs)...)
			}
		}
		var users []User
		gdb.Find(&users)
		for _, user := range users {
			if containsToken(userTags(user), selector) {
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
			if containsToken(peerTags(peer), selector) {
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
