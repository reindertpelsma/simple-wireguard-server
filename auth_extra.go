package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const sessionCookieName = "uwgsocks_ui_token"

func bearerTokenFromRequest(r *http.Request) string {
	token := r.Header.Get("Authorization")
	if strings.HasPrefix(token, "Bearer ") {
		token = strings.TrimPrefix(token, "Bearer ")
	}
	if token != "" {
		return token
	}
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		return cookie.Value
	}
	return ""
}

func issueUserToken(w http.ResponseWriter, user *User) string {
	b := make([]byte, 32)
	rand.Read(b)
	token := base64.URLEncoding.EncodeToString(b)
	now := time.Now()
	gdb.Model(user).Updates(map[string]interface{}{
		"token":           token,
		"token_issued_at": now,
		"sudo_auth_at":    now,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(sessionTimeout().Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	user.Token = token
	user.TokenIssuedAt = now
	user.SudoAuthAt = now
	return token
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	token := bearerTokenFromRequest(r)
	if token != "" {
		gdb.Model(&User{}).Where("token = ?", token).Updates(map[string]interface{}{
			"token":           "",
			"token_issued_at": time.Time{},
			"sudo_auth_at":    time.Time{},
		})
	}
	clearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func handleAuthMethods(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"password":     true,
		"oidc_enabled": oidcEnabled(),
		"oidc_login":   "/api/oidc/login",
	})
}

func handleMe(w http.ResponseWriter, r *http.Request) {
	user, ok := currentUserFromRequest(w, r)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":                   user.ID,
		"username":             user.Username,
		"is_admin":             userIsAdmin(user),
		"is_moderator":         userIsModeratorOnly(user),
		"role":                 userRole(user),
		"totp_enabled":         user.TOTPEnabled,
		"oidc_login":           user.OIDCSubject != nil,
		"sudo_active":          userHasActiveSudo(user, time.Now()),
		"sudo_expires_at":      userSudoExpiry(user),
		"can_manage_users":     userCanManageUsers(user),
		"can_manage_settings":  userIsAdmin(user),
		"can_manage_acls":      userIsAdmin(user),
		"can_manage_transports": userIsAdmin(user),
		"can_manage_forwards":  userIsAdmin(user),
		"can_manage_turn":      userIsAdmin(user),
	})
}

func generateTOTPSecret() (string, error) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return strings.TrimRight(base32.StdEncoding.EncodeToString(raw), "="), nil
}

func decodeTOTPSecret(secret string) ([]byte, error) {
	normalized := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	if padding := len(normalized) % 8; padding != 0 {
		normalized += strings.Repeat("=", 8-padding)
	}
	return base32.StdEncoding.DecodeString(normalized)
}

func totpCode(secret string, now time.Time) (string, error) {
	key, err := decodeTOTPSecret(secret)
	if err != nil {
		return "", err
	}
	counter := uint64(now.Unix() / 30)
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := int(sum[len(sum)-1] & 0x0f)
	bin := ((uint32(sum[offset]) & 0x7f) << 24) |
		((uint32(sum[offset+1]) & 0xff) << 16) |
		((uint32(sum[offset+2]) & 0xff) << 8) |
		(uint32(sum[offset+3]) & 0xff)
	code := bin % 1000000
	return fmt.Sprintf("%06d", code), nil
}

func verifyTOTPCode(secret, provided string, now time.Time) bool {
	provided = strings.TrimSpace(strings.ReplaceAll(provided, " ", ""))
	if len(provided) != 6 {
		return false
	}
	for drift := -1; drift <= 1; drift++ {
		code, err := totpCode(secret, now.Add(time.Duration(drift)*30*time.Second))
		if err == nil && subtleStringEqual(code, provided) {
			return true
		}
	}
	return false
}

func subtleStringEqual(a, b string) bool {
	return len(a) == len(b) && hmac.Equal([]byte(a), []byte(b))
}

func handleTOTPSetup(w http.ResponseWriter, r *http.Request) {
	user, ok := currentUserFromRequest(w, r)
	if !ok {
		return
	}
	secret, err := generateTOTPSecret()
	if err != nil {
		http.Error(w, "Failed to generate 2FA secret", http.StatusInternalServerError)
		return
	}
	user.TOTPSecret = encryptAtRest(secret)
	user.TOTPEnabled = false
	if err := gdb.Save(&user).Error; err != nil {
		http.Error(w, "Failed to save 2FA secret", http.StatusInternalServerError)
		return
	}
	issuer := url.QueryEscape("uwgsocks-ui")
	account := url.QueryEscape(user.Username)
	otpauth := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&digits=6&period=30", issuer, account, secret, issuer)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"secret":      secret,
		"otpauth_url": otpauth,
	})
}

func handleTOTPEnable(w http.ResponseWriter, r *http.Request) {
	user, ok := currentUserFromRequest(w, r)
	if !ok {
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	if !verifyTOTPCode(decryptAtRest(user.TOTPSecret), req.Code, time.Now()) {
		http.Error(w, "Invalid two-factor code", http.StatusUnauthorized)
		return
	}
	gdb.Model(&user).Updates(map[string]interface{}{"totp_enabled": true})
	w.WriteHeader(http.StatusNoContent)
}

func handleTOTPDisable(w http.ResponseWriter, r *http.Request) {
	user, ok := currentUserFromRequest(w, r)
	if !ok {
		return
	}
	gdb.Model(&user).Updates(map[string]interface{}{"totp_enabled": false, "totp_secret": ""})
	w.WriteHeader(http.StatusNoContent)
}

func handleReauth(w http.ResponseWriter, r *http.Request) {
	user, ok := currentUserFromRequest(w, r)
	if !ok {
		return
	}
	if user.OIDCSubject != nil {
		http.Error(w, "Password re-authentication is unavailable for OIDC accounts", http.StatusBadRequest)
		return
	}
	var req struct {
		Password string `json:"password"`
		TOTPCode string `json:"totp_code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	if !verifyPassword(req.Password, user.PasswordHash) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}
	if user.TOTPEnabled && !verifyTOTPCode(decryptAtRest(user.TOTPSecret), req.TOTPCode, time.Now()) {
		http.Error(w, "Invalid two-factor code", http.StatusUnauthorized)
		return
	}
	refreshUserSudo(&user)
	w.WriteHeader(http.StatusNoContent)
}

func currentUserFromRequest(w http.ResponseWriter, r *http.Request) (User, bool) {
	id, err := strconv.ParseUint(r.Header.Get("X-User-Id"), 10, 64)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return User{}, false
	}
	var user User
	if err := gdb.First(&user, uint(id)).Error; err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return User{}, false
	}
	return user, true
}
