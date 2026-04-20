import { useEffect, useState } from 'react';
import { KeyRound, Loader2, Shield } from 'lucide-react';
import { api } from '../lib/api';
import ThemeToggle from './ThemeToggle';

export default function Login({ theme = 'light', onToggleTheme = () => {}, onLogin }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [totpCode, setTotpCode] = useState('');
  const [requires2FA, setRequires2FA] = useState(false);
  const [authMethods, setAuthMethods] = useState({ oidc_enabled: false, oidc_login: '/api/oidc/login' });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    api.getAuthMethods()
      .then(setAuthMethods)
      .catch(() => {});
  }, []);

  const handleSubmit = async (event) => {
    event.preventDefault();
    setLoading(true);
    setError('');

    try {
      const result = await api.login(username, password, totpCode);
      if (result?.requires_2fa) {
        setRequires2FA(true);
        setError('');
        return;
      }
      const { token } = result;
      localStorage.setItem('token', token);
      const next = new URLSearchParams(window.location.search).get('next');
      if (next && next.startsWith('/')) {
        window.location.href = next;
        return;
      }
      onLogin();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="app-shell flex min-h-screen flex-col px-4 py-6 sm:px-6">
      <div className="mx-auto flex w-full max-w-6xl justify-end">
        <ThemeToggle theme={theme} onToggle={onToggleTheme} />
      </div>

      <div className="mx-auto flex w-full max-w-6xl flex-1 items-center py-8">
        <div className="grid w-full gap-6 lg:grid-cols-[1.1fr_0.9fr]">
          {/*<section className="hero-panel">
            <span className="eyebrow">uwgsocks-ui</span>
            <h1 className="text-4xl font-black tracking-tight sm:text-5xl">
              Rootless WireGuard management that still feels operationally sharp.
            </h1>
            <p className="max-w-2xl text-base text-[var(--muted)] sm:text-lg">
              Bootstrap an admin account, generate your first client config from the server process, and manage peer traffic, ACLs, and shared config links without leaving the browser.
            </p>

            <div className="grid gap-3 sm:grid-cols-3">
              <div className="stat-tile">
                <span className="stat-label">Bootstrap</span>
                <strong>Random admin password on first start</strong>
              </div>
              <div className="stat-tile">
                <span className="stat-label">Observe</span>
                <strong>Live traffic graphs from daemon status</strong>
              </div>
              <div className="stat-tile">
                <span className="stat-label">Share</span>
                <strong>Time-bound `.conf` links with fragment secrets</strong>
              </div>
            </div>
          </section>*/}

          <section className="panel p-6 sm:p-8">
            <div className="mb-6 flex items-center gap-3">
              <div className="brand-badge">
                <Shield size={22} />
              </div>
              <div>
                <h2 className="text-2xl font-black tracking-tight">Sign in Wireguard</h2>
              </div>
            </div>

            <form className="space-y-5" onSubmit={handleSubmit} role="form">
              <div className="space-y-2">
                <label className="field-label">Username</label>
                <input
                  type="text"
                  required
                  className="input-field"
                  placeholder="admin"
                  value={username}
                  onChange={(event) => setUsername(event.target.value)}
                />
              </div>

              <div className="space-y-2">
                <label className="field-label">Password</label>
                <input
                  type="password"
                  required
                  className="input-field"
                  placeholder="••••••••••••"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                />
              </div>

              {requires2FA && (
                <div className="space-y-2">
                  <label className="field-label">Two-factor code</label>
                  <input
                    type="text"
                    inputMode="numeric"
                    required
                    className="input-field"
                    placeholder="123456"
                    value={totpCode}
                    onChange={(event) => setTotpCode(event.target.value)}
                  />
                </div>
              )}

              {error && (
                <div className="error-banner">
                  {error}
                </div>
              )}

              <button type="submit" disabled={loading} className="primary-button w-full justify-center">
                {loading ? <Loader2 className="animate-spin" size={18} /> : null}
                <span>{loading ? 'Signing in…' : (requires2FA ? 'Verify 2FA code' : 'Enter dashboard')}</span>
              </button>

              {authMethods.oidc_enabled && (
                <a href={authMethods.oidc_login || '/api/oidc/login'} className="secondary-button w-full justify-center">
                  <KeyRound size={18} />
                  <span>Continue with OIDC</span>
                </a>
              )}
            </form>
          </section>
        </div>
      </div>
    </div>
  );
}
