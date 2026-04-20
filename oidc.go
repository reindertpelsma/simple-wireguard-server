package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type oidcDiscovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
}

type oidcUserinfo struct {
	Subject           string `json:"sub"`
	PreferredUsername string `json:"preferred_username"`
	Email             string `json:"email"`
	Name              string `json:"name"`
	// Groups / roles from the OIDC provider. When set on first login they are
	// used to populate the user's group memberships. Subsequent logins do NOT
	// update groups (admin can manage them manually after first sync).
	Groups []string `json:"groups"`
	// The OIDC claim key for groups varies by provider; check common aliases.
	Roles []string `json:"roles"`
}

func oidcEnabled() bool {
	return strings.TrimSpace(*oidcIssuer) != "" && strings.TrimSpace(*oidcClientID) != ""
}

func oidcRedirectURI(r *http.Request) string {
	if strings.TrimSpace(*oidcRedirectURL) != "" {
		return *oidcRedirectURL
	}
	return canonicalBaseURL(r) + "/api/oidc/callback"
}

func fetchOIDCDiscovery(ctxReq *http.Request) (oidcDiscovery, error) {
	issuer := strings.TrimRight(*oidcIssuer, "/")
	req, err := http.NewRequestWithContext(ctxReq.Context(), http.MethodGet, issuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return oidcDiscovery{}, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return oidcDiscovery{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return oidcDiscovery{}, fmt.Errorf("OIDC discovery returned %d", resp.StatusCode)
	}
	var d oidcDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return oidcDiscovery{}, err
	}
	if d.AuthorizationEndpoint == "" || d.TokenEndpoint == "" || d.UserinfoEndpoint == "" {
		return oidcDiscovery{}, fmt.Errorf("OIDC discovery is missing required endpoints")
	}
	return d, nil
}

func handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	if !oidcEnabled() {
		http.Error(w, "OIDC login is disabled", http.StatusNotFound)
		return
	}
	d, err := fetchOIDCDiscovery(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	state := randomSecret(24)
	http.SetCookie(w, &http.Cookie{
		Name:     "uwgsocks_oidc_state",
		Value:    state,
		Path:     "/api/oidc",
		MaxAge:   int((10 * time.Minute).Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	authURL, err := url.Parse(d.AuthorizationEndpoint)
	if err != nil {
		http.Error(w, "invalid OIDC authorization endpoint", http.StatusBadGateway)
		return
	}
	q := authURL.Query()
	q.Set("response_type", "code")
	q.Set("client_id", *oidcClientID)
	q.Set("redirect_uri", oidcRedirectURI(r))
	q.Set("scope", "openid profile email")
	q.Set("state", state)
	authURL.RawQuery = q.Encode()
	http.Redirect(w, r, authURL.String(), http.StatusFound)
}

func handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if !oidcEnabled() {
		http.Error(w, "OIDC login is disabled", http.StatusNotFound)
		return
	}
	stateCookie, err := r.Cookie("uwgsocks_oidc_state")
	if err != nil || !subtleStringEqual(stateCookie.Value, r.URL.Query().Get("state")) {
		http.Error(w, "Invalid OIDC state", http.StatusUnauthorized)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Missing OIDC code", http.StatusBadRequest)
		return
	}
	d, err := fetchOIDCDiscovery(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	accessToken, err := exchangeOIDCCode(r, d, code)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	info, err := fetchOIDCUserinfo(r, d, accessToken)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if info.Subject == "" {
		http.Error(w, "OIDC userinfo missing subject", http.StatusBadGateway)
		return
	}
	user, err := userForOIDC(info)
	if err != nil {
		http.Error(w, "Failed to map OIDC user", http.StatusInternalServerError)
		return
	}
	token := issueUserToken(w, &user)
	clearOIDCStateCookie(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><title>Signed in</title><script>localStorage.setItem("token", %q); location.replace("/app");</script><p>Signed in. Redirecting...</p>`, token)
}

func exchangeOIDCCode(r *http.Request, d oidcDiscovery, code string) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", oidcRedirectURI(r))
	form.Set("client_id", *oidcClientID)
	if *oidcClientSecret != "" {
		form.Set("client_secret", *oidcClientSecret)
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, d.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("OIDC token endpoint returned %d: %s", resp.StatusCode, bytes.TrimSpace(body))
	}
	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", err
	}
	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("OIDC token endpoint did not return an access_token")
	}
	return tokenResp.AccessToken, nil
}

func fetchOIDCUserinfo(r *http.Request, d oidcDiscovery, accessToken string) (oidcUserinfo, error) {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, d.UserinfoEndpoint, nil)
	if err != nil {
		return oidcUserinfo{}, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return oidcUserinfo{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return oidcUserinfo{}, fmt.Errorf("OIDC userinfo returned %d", resp.StatusCode)
	}
	var info oidcUserinfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return oidcUserinfo{}, err
	}
	return info, nil
}

func userForOIDC(info oidcUserinfo) (User, error) {
	provider := strings.TrimRight(*oidcIssuer, "/")
	var user User
	if err := gdb.First(&user, "oidc_provider = ? AND oidc_subject = ?", provider, info.Subject).Error; err == nil {
		return user, nil
	}
	username := info.PreferredUsername
	if username == "" {
		username = info.Email
	}
	if username == "" {
		username = info.Name
	}
	if username == "" {
		username = "oidc-" + info.Subject
	}
	username = uniqueOIDCUsername(username)
	sub := info.Subject
	hash, _ := hashPassword(randomSecret(24))

	// Merge groups from OIDC provider (Groups + Roles claims).
	oidcGroups := append(info.Groups, info.Roles...)
	additionalGroups := []string{}
	primaryGroup := "default"
	isAdmin := false
	for _, g := range oidcGroups {
		g = strings.ToLower(strings.TrimSpace(g))
		if g == "" {
			continue
		}
		if g == "admin" || g == "administrators" {
			isAdmin = true
			additionalGroups = append(additionalGroups, "admin")
		} else {
			// Validate that the group exists in the DB before assigning.
			var dbGroup Group
			if gdb.First(&dbGroup, "name = ?", g).Error == nil {
				additionalGroups = append(additionalGroups, g)
				if dbGroup.Subnet != "" && primaryGroup == "default" {
					primaryGroup = g
				}
			}
		}
	}

	user = User{
		Username:     username,
		PasswordHash: hash,
		OIDCProvider: provider,
		OIDCSubject:  &sub,
		MaxConfigs:   10,
		IsAdmin:      isAdmin,
		PrimaryGroup: primaryGroup,
		Tags:         joinCSVList(additionalGroups),
	}
	return user, gdb.Create(&user).Error
}

func uniqueOIDCUsername(base string) string {
	base = strings.TrimSpace(strings.NewReplacer(" ", "-", "/", "-", "\\", "-").Replace(base))
	if base == "" {
		base = "oidc-user"
	}
	candidate := base
	for i := 2; ; i++ {
		var count int64
		gdb.Model(&User{}).Where("username = ?", candidate).Count(&count)
		if count == 0 {
			return candidate
		}
		candidate = fmt.Sprintf("%s-%d", base, i)
	}
}

func clearOIDCStateCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "uwgsocks_oidc_state",
		Value:    "",
		Path:     "/api/oidc",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}
