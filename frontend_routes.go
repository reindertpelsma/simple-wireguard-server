package main

import (
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

func extractEmbeddedDist(target string) error {
	source, err := fs.Sub(frontendFS, "dist")
	if err != nil {
		return err
	}
	return fs.WalkDir(source, ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		dst := filepath.Join(target, filepath.FromSlash(name))
		if entry.IsDir() {
			return os.MkdirAll(dst, 0755)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		in, err := source.Open(name)
		if err != nil {
			return err
		}
		defer in.Close()
		if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
			return err
		}
		out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode())
		if err != nil {
			return err
		}
		defer out.Close()
		_, err = io.Copy(out, in)
		return err
	})
}

func frontendDist() (fs.FS, error) {
	if strings.TrimSpace(*frontendDir) != "" {
		return os.DirFS(*frontendDir), nil
	}
	return fs.Sub(frontendFS, "dist")
}

func registerFrontendRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /login", handlePublicLoginPage)
	mux.HandleFunc("GET /", handleFrontendRequest)
}

func handlePublicLoginPage(w http.ResponseWriter, r *http.Request) {
	if isFrontendAuthenticated(r) {
		http.Redirect(w, r, "/app", http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprint(w, loginPageHTML)
}

func handleFrontendRequest(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		http.NotFound(w, r)
		return
	}
	if r.URL.Path == "/" {
		if isFrontendAuthenticated(r) {
			http.Redirect(w, r, "/app", http.StatusFound)
		} else {
			http.Redirect(w, r, "/login", http.StatusFound)
		}
		return
	}

	// Shared config URLs are intentionally public capability links. The rest of
	// the dashboard bundle is cookie-gated so anonymous visitors only see login.
	if strings.HasPrefix(r.URL.Path, "/config/") {
		serveDistAsset(w, r, "index.html", true)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/assets/") && isSharedConfigReferer(r) {
		serveDistAsset(w, r, strings.TrimPrefix(r.URL.Path, "/"), false)
		return
	}

	if !isFrontendAuthenticated(r) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
	if name == "." || name == "app" || strings.HasPrefix(name, "app/") {
		name = "index.html"
	}
	serveDistAsset(w, r, name, true)
}

func isFrontendAuthenticated(r *http.Request) bool {
	token := bearerTokenFromRequest(r)
	if token == "" {
		return false
	}
	var user User
	if err := gdb.First(&user, "token = ?", token).Error; err != nil {
		return false
	}
	return !userSessionExpired(user, time.Now())
}

func isSharedConfigReferer(r *http.Request) bool {
	ref := r.Referer()
	if ref == "" {
		return false
	}
	return strings.HasPrefix(ref, "http://"+r.Host+"/config/") ||
		strings.HasPrefix(ref, "https://"+r.Host+"/config/")
}

func serveDistAsset(w http.ResponseWriter, r *http.Request, name string, spaFallback bool) {
	dist, err := frontendDist()
	if err != nil {
		http.Error(w, "frontend dist unavailable", http.StatusInternalServerError)
		return
	}
	name = strings.TrimPrefix(path.Clean("/"+name), "/")
	if name == "" || name == "." {
		name = "index.html"
	}
	stat, err := fs.Stat(dist, name)
	if err != nil || stat.IsDir() {
		if !spaFallback {
			http.NotFound(w, r)
			return
		}
		name = "index.html"
	}
	if ext := path.Ext(name); ext != "" {
		if contentType := mime.TypeByExtension(ext); contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
	}
	if name == "index.html" {
		w.Header().Set("Cache-Control", "no-store")
	}
	http.ServeFileFS(w, r, dist, name)
}

const loginPageHTML = `<!doctype html>
<!-- Only the lock is public -->
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sign in · Simple WireGuard Server</title>
  <link rel="icon" type="image/svg+xml" href="/favicon.svg">
  <style>
    :root { color-scheme: light; --bg:#edf3ea; --ink:#10222d; --muted:#5e7480; --panel:rgba(255,255,255,.86); --line:rgba(16,34,45,.14); --accent:#0f766e; --accent2:#d97706; --danger:#c2410c; --input:rgba(255,255,255,.94); }
    :root[data-theme="dark"] { color-scheme: dark; --bg:#07131a; --ink:#e6f3f2; --muted:#90a9b2; --panel:rgba(10,23,31,.9); --line:rgba(230,243,242,.12); --accent:#5eead4; --accent2:#fb923c; --danger:#fb923c; --input:rgba(7,19,26,.96); }
    * { box-sizing:border-box; }
    body { min-height:100vh; margin:0; display:grid; place-items:center; padding:24px; color:var(--ink); font-family:"Space Grotesk","Avenir Next","Segoe UI",sans-serif; background:radial-gradient(circle at 10% 10%,rgba(15,118,110,.18),transparent 30%),radial-gradient(circle at 90% 0,rgba(217,119,6,.16),transparent 26%),linear-gradient(180deg,var(--panel),var(--bg)); }
    main { width:min(100%,960px); display:grid; gap:20px; grid-template-columns:1.05fr .95fr; align-items:stretch; }
    section { border:1px solid var(--line); border-radius:30px; background:var(--panel); box-shadow:0 24px 70px rgba(16,34,45,.13); backdrop-filter:blur(18px); }
    .hero { padding:34px; display:flex; flex-direction:column; justify-content:space-between; gap:30px; }
    .card { padding:30px; }
    .eyebrow { display:inline-flex; width:max-content; border-radius:999px; padding:8px 12px; background:rgba(15,118,110,.12); color:var(--accent); font-size:12px; font-weight:800; letter-spacing:.16em; text-transform:uppercase; }
    h1,h2,p { margin:0; }
    h1 { font-size:clamp(36px,7vw,66px); line-height:.95; letter-spacing:-.06em; }
    h2 { font-size:28px; letter-spacing:-.03em; }
    p { color:var(--muted); line-height:1.65; }
    form { display:grid; gap:16px; margin-top:24px; }
    label { display:grid; gap:8px; color:var(--muted); font-size:12px; font-weight:800; letter-spacing:.14em; text-transform:uppercase; }
    input { width:100%; border:1px solid var(--line); border-radius:16px; padding:14px 15px; background:var(--input); color:var(--ink); color-scheme:inherit; -webkit-text-fill-color:var(--ink); font:inherit; outline:none; }
    input:focus { border-color:var(--accent); box-shadow:0 0 0 4px rgba(15,118,110,.13); }
    input:-webkit-autofill, input:-webkit-autofill:hover, input:-webkit-autofill:focus { -webkit-text-fill-color:var(--ink); box-shadow:0 0 0 1000px var(--input) inset; transition:background-color 9999s ease-out 0s; }
    button,a.button { display:inline-flex; justify-content:center; align-items:center; gap:8px; border-radius:999px; border:0; padding:14px 18px; color:#effcf9; background:linear-gradient(135deg,#115e59,#0f766e); font-weight:850; text-decoration:none; cursor:pointer; }
    button.secondary,a.secondary { border:1px solid var(--line); background:rgba(15,118,110,.1); color:var(--accent); }
    button:disabled { opacity:.6; cursor:wait; }
    .error { display:none; border:1px solid rgba(194,65,12,.28); background:rgba(194,65,12,.1); color:var(--danger); border-radius:18px; padding:12px 14px; }
    .error.show { display:block; }
    .topbar { position:fixed; top:20px; right:20px; display:flex; gap:12px; align-items:center; }
    .theme { display:inline-flex; align-items:center; gap:8px; border:1px solid var(--line); border-radius:999px; background:transparent; color:var(--ink); }
    .theme-icon { display:inline-flex; align-items:center; justify-content:center; width:18px; height:18px; }
    .powered { display:inline-flex; margin-top:18px; color:var(--accent); font-weight:700; text-decoration:none; }
    .tiles { display:grid; grid-template-columns:repeat(3,1fr); gap:10px; }
    .tile { border:1px solid var(--line); border-radius:20px; padding:14px; background:rgba(255,255,255,.62); font-weight:800; }
    .twofa { display:none; }
    .twofa.show { display:grid; }
    @media (max-width: 760px) { main { grid-template-columns:1fr; } .tiles { grid-template-columns:1fr; } }
  </style>
</head>
<body>
  <div class="topbar">
    <button id="theme-toggle" type="button" class="theme"><span id="theme-icon" class="theme-icon">☾</span><span id="theme-label">Dark</span></button>
  </div>
  <main>
    <section class="card">
      <span class="eyebrow">Simple WireGuard Server</span>
      <div style="display:grid;gap:8px;margin-top:14px">
        <h2>Sign in Wireguard</h2>
      </div>
      <form id="login-form">
        <label>Username <input id="username" autocomplete="username" placeholder="admin" required autofocus></label>
        <label>Password <input id="password" type="password" autocomplete="current-password" placeholder="••••••••••••" required></label>
        <label id="twofa-row" class="twofa">2FA Code <input id="totp" inputmode="numeric" autocomplete="one-time-code" placeholder="123456" pattern="[0-9 ]{6,8}"></label>
        <div id="error" class="error"></div>
        <button id="submit" type="submit">Enter dashboard</button>
        <a id="oidc" class="button secondary" href="/api/oidc/login" style="display:none">Continue with OIDC</a>
        <a class="powered" href="https://github.com/reindertpelsma/simple-wireguard-server" target="_blank" rel="noreferrer">Powered by simple-wireguard-server</a>
      </form>
    </section>
  </main>
  <script>
    const root = document.documentElement;
    const THEME_KEY = 'ui_theme';
    const OS_THEME_KEY = 'ui_theme_os';
    function cookieGet(name) {
      const prefix = name + '=';
      for (const part of document.cookie.split(';')) {
        const value = part.trim();
        if (value.startsWith(prefix)) return decodeURIComponent(value.slice(prefix.length));
      }
      return '';
    }
    function cookieSet(name, value) {
      document.cookie = name + '=' + encodeURIComponent(value) + '; Path=/; Max-Age=31536000; SameSite=Lax';
    }
    function detectOSTheme() {
      try {
        if (!window.matchMedia) return 'light';
        return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
      } catch {
        return 'light';
      }
    }
    function persistTheme(theme, osTheme) {
      try {
        localStorage.setItem(THEME_KEY, theme);
        localStorage.setItem(OS_THEME_KEY, osTheme);
      } catch {}
      cookieSet(THEME_KEY, theme);
      cookieSet(OS_THEME_KEY, osTheme);
    }
    function syncThemeButton() {
      const dark = root.dataset.theme === 'dark';
      document.getElementById('theme-icon').textContent = dark ? '☀' : '☾';
      document.getElementById('theme-label').textContent = dark ? 'Light' : 'Dark';
    }
    function resolveTheme() {
      const osTheme = detectOSTheme();
      let savedTheme = '';
      let savedOS = '';
      try {
        savedTheme = localStorage.getItem(THEME_KEY) || '';
        savedOS = localStorage.getItem(OS_THEME_KEY) || '';
      } catch {}
      if (!savedTheme) savedTheme = cookieGet(THEME_KEY);
      if (!savedOS) savedOS = cookieGet(OS_THEME_KEY);
      if (savedOS !== osTheme) {
        persistTheme(osTheme, osTheme);
        return osTheme;
      }
      if (savedTheme === 'dark' || savedTheme === 'light') {
        persistTheme(savedTheme, osTheme);
        return savedTheme;
      }
      persistTheme(osTheme, osTheme);
      return osTheme;
    }
    root.dataset.theme = resolveTheme();
    syncThemeButton();
    document.getElementById('theme-toggle').addEventListener('click', () => {
      const next = root.dataset.theme === 'dark' ? 'light' : 'dark';
      root.dataset.theme = next;
      persistTheme(next, detectOSTheme());
      syncThemeButton();
    });
    try {
      if (window.matchMedia) {
        const query = window.matchMedia('(prefers-color-scheme: dark)');
        const onChange = () => {
          const next = detectOSTheme();
          root.dataset.theme = next;
          persistTheme(next, next);
          syncThemeButton();
        };
        if (query.addEventListener) query.addEventListener('change', onChange);
        else if (query.addListener) query.addListener(onChange);
      }
    } catch {}
    const form = document.getElementById('login-form');
    const errorBox = document.getElementById('error');
    const submit = document.getElementById('submit');
    const twofaRow = document.getElementById('twofa-row');
    const oidc = document.getElementById('oidc');
    let needs2FA = false;
    fetch('/api/auth/methods').then(r => r.json()).then(m => {
      if (m.oidc_enabled) oidc.style.display = 'inline-flex';
    }).catch(() => {});
    function showError(message) {
      errorBox.textContent = message;
      errorBox.classList.add('show');
    }
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      errorBox.classList.remove('show');
      submit.disabled = true;
      submit.textContent = needs2FA ? 'Checking code…' : 'Signing in…';
      try {
        const payload = {
          username: document.getElementById('username').value,
          password: document.getElementById('password').value,
          totp_code: document.getElementById('totp').value
        };
        const response = await fetch('/api/login', {
          method: 'POST',
          headers: {'Content-Type':'application/json'},
          body: JSON.stringify(payload)
        });
        const text = await response.text();
        let data = {};
        try { data = text ? JSON.parse(text) : {}; } catch { data = {}; }
        if (response.status === 202 && data.requires_2fa) {
          needs2FA = true;
          twofaRow.classList.add('show');
          document.getElementById('totp').focus();
          submit.textContent = 'Verify 2FA code';
          return;
        }
        if (!response.ok) throw new Error(data.error || text || response.statusText);
        localStorage.setItem('token', data.token);
        location.replace('/app');
      } catch (err) {
        showError(err.message || 'Login failed');
      } finally {
        submit.disabled = false;
        if (!needs2FA) submit.textContent = 'Enter dashboard';
      }
    });
  </script>
</body>
</html>`
