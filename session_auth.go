package main

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

const (
	defaultSessionTimeout = 7 * 24 * time.Hour
	defaultSudoTimeout    = 10 * time.Minute
)

func configDurationSeconds(key string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(getConfig(key))
	if raw == "" {
		return fallback
	}
	seconds, err := strconv.Atoi(raw)
	if err != nil || seconds <= 0 {
		return fallback
	}
	return time.Duration(seconds) * time.Second
}

func sessionTimeout() time.Duration {
	return configDurationSeconds("auth_session_timeout_seconds", defaultSessionTimeout)
}

func sudoTimeout() time.Duration {
	return configDurationSeconds("auth_sudo_timeout_seconds", defaultSudoTimeout)
}

func userSessionExpired(user User, now time.Time) bool {
	if user.TokenIssuedAt.IsZero() {
		return false
	}
	return now.After(user.TokenIssuedAt.Add(sessionTimeout()))
}

func userSudoExpiry(user User) time.Time {
	if user.SudoAuthAt.IsZero() {
		return time.Time{}
	}
	return user.SudoAuthAt.Add(sudoTimeout())
}

func userHasActiveSudo(user User, now time.Time) bool {
	expiry := userSudoExpiry(user)
	return !expiry.IsZero() && now.Before(expiry)
}

func refreshUserSudo(user *User) {
	now := time.Now()
	gdb.Model(user).Updates(map[string]interface{}{
		"sudo_auth_at":  now,
		"token_issued_at": now,
	})
	user.SudoAuthAt = now
	user.TokenIssuedAt = now
}

func writeSudoRequired(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusPreconditionRequired)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error":         "Re-authentication required",
		"sudo_required": true,
	})
}

func sudoMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := currentUserFromRequest(w, r)
		if !ok {
			return
		}
		if !userHasActiveSudo(user, time.Now()) {
			writeSudoRequired(w)
			return
		}
		next.ServeHTTP(w, r)
	}
}

func userCanManageTargetUser(actor, target User) bool {
	if actor.ID == 0 || target.ID == 0 || actor.ID == target.ID {
		return false
	}
	if userIsAdmin(actor) {
		return true
	}
	if !userIsModeratorOnly(actor) {
		return false
	}
	return !userIsAdmin(target) && !userIsModeratorOnly(target)
}

func validateConfigValue(key, value string) error {
	switch key {
	case "client_subnet_ipv4", "client_subnet_ipv6", "group_base_subnet", "group_base_subnet_ipv6":
		if strings.TrimSpace(value) == "" {
			return nil
		}
		if _, err := netip.ParsePrefix(strings.TrimSpace(value)); err != nil {
			return err
		}
	case "auth_sudo_timeout_seconds", "auth_session_timeout_seconds", "yaml_socks5_port", "yaml_http_port", "peer_sync_port":
		if strings.TrimSpace(value) == "" {
			return nil
		}
		n, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil || n < 0 {
			return strconv.ErrSyntax
		}
	}
	return nil
}
