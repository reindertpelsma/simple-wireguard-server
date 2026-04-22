import { useCallback, useEffect, useState } from 'react';
import { Eye, EyeOff, KeyRound, RadioTower, ShieldCheck, User } from 'lucide-react';
import { api } from '../lib/api';

export default function ProfileTab({ me: meProp, sudoActive = false, onRequireSudo = () => {}, onRefreshMe = () => {} }) {
  const [me, setMe] = useState(meProp);
  const [creds, setCreds] = useState([]);
  const [createdCred, setCreatedCred] = useState(null);
  const [turnCreds, setTurnCreds] = useState([]);
  const [createdTurnCred, setCreatedTurnCred] = useState(null);
  const [publicConfig, setPublicConfig] = useState({});
  const [totpSetup, setTotpSetup] = useState(null);
  const [totpCode, setTotpCode] = useState('');
  const [showQR, setShowQR] = useState(false);
  const [busy, setBusy] = useState('');
  const [turnForm, setTurnForm] = useState({ name: 'TURN relay', wireguard_public_key: '' });

  const [pwForm, setPwForm] = useState({ old_password: '', password: '', confirm: '' });
  const [pwError, setPwError] = useState('');
  const [showPw, setShowPw] = useState(false);

  const fetchData = useCallback(async () => {
    try {
      const [meData, credData, cfg] = await Promise.all([api.getMe(), api.getMyProxyCredentials(), api.getPublicConfig()]);
      setMe(meData);
      onRefreshMe();
      setCreds(credData);
      setPublicConfig(cfg || {});
      if ((cfg || {}).turn_hosting_enabled === 'true') {
        try {
          setTurnCreds(await api.getMyTURNCredentials());
        } catch {
          setTurnCreds([]);
        }
      } else {
        setTurnCreds([]);
      }
    } catch (err) {
      console.error(err);
    }
  }, [onRefreshMe]);

  useEffect(() => { setMe(meProp); }, [meProp]);
  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const handleChangePassword = async (e) => {
    e.preventDefault();
    setPwError('');
    if (pwForm.password !== pwForm.confirm) {
      setPwError('New passwords do not match.');
      return;
    }
    if (pwForm.password.length < 8) {
      setPwError('Password must be at least 8 characters.');
      return;
    }
    setBusy('pw');
    try {
      await api.updateMe({ old_password: pwForm.old_password, password: pwForm.password });
      setPwForm({ old_password: '', password: '', confirm: '' });
      alert('Password changed successfully.');
    } catch (err) {
      setPwError(err.message || 'Failed to change password.');
    } finally {
      setBusy('');
    }
  };

  const handleSetup2FA = async () => {
    if (!sudoActive) return onRequireSudo();
    setBusy('2fa');
    try {
      const res = await api.setupTOTP();
      setTotpSetup(res);
      setTotpCode('');
      setShowQR(true);
    } catch (err) {
      alert(err.message);
    } finally {
      setBusy('');
    }
  };

  const handleEnable2FA = async () => {
    if (!sudoActive) return onRequireSudo();
    setBusy('2fa');
    try {
      await api.enableTOTP(totpCode);
      setTotpSetup(null);
      setTotpCode('');
      setMe(await api.getMe());
      alert('Two-factor authentication enabled.');
    } catch (err) {
      alert(err.message);
    } finally {
      setBusy('');
    }
  };

  const handleDisable2FA = async () => {
    if (!sudoActive) return onRequireSudo();
    if (!confirm('Disable two-factor authentication for your account?')) return;
    setBusy('2fa');
    try {
      await api.disableTOTP();
      setMe(await api.getMe());
      setTotpSetup(null);
    } catch (err) {
      alert(err.message);
    } finally {
      setBusy('');
    }
  };

  const handleCreateCred = async () => {
    if (!sudoActive) return onRequireSudo();
    setBusy('cred');
    try {
      const res = await api.createMyProxyCredential({ name: 'Proxy access' });
      setCreatedCred(res);
      setCreds(await api.getMyProxyCredentials());
    } catch (err) {
      alert(err.message);
    } finally {
      setBusy('');
    }
  };

  const handleDeleteCred = async (id) => {
    if (!sudoActive) return onRequireSudo();
    if (!confirm('Delete this proxy credential?')) return;
    try {
      await api.deleteMyProxyCredential(id);
      setCreds(await api.getMyProxyCredentials());
    } catch (err) {
      alert(err.message);
    }
  };

  const handleCreateTurnCred = async () => {
    if (!sudoActive) return onRequireSudo();
    setBusy('turn');
    try {
      const res = await api.createMyTURNCredential(turnForm);
      setCreatedTurnCred(res);
      setTurnCreds(await api.getMyTURNCredentials());
    } catch (err) {
      alert(err.message);
    } finally {
      setBusy('');
    }
  };

  const handleDeleteTurnCred = async (id) => {
    if (!sudoActive) return onRequireSudo();
    if (!confirm('Delete this TURN credential?')) return;
    try {
      await api.deleteMyTURNCredential(id);
      setTurnCreds(await api.getMyTURNCredentials());
    } catch (err) {
      alert(err.message);
    }
  };

  const isOIDC = me?.oidc_login;
  const turnEnabled = publicConfig.turn_hosting_enabled === 'true';
  const turnSelfService = publicConfig.turn_allow_user_credentials === 'true';

  if (!me) return <div className="state-shell py-24 text-[var(--muted)]">Loading…</div>;

  return (
    <div className="grid gap-6 xl:grid-cols-2">
      {!sudoActive && (
        <section className="panel p-6 col-span-full">
          <div className="error-banner">Sensitive actions are locked. Use “Unlock changes” in the header before changing security settings or creating credentials.</div>
        </section>
      )}

      {/* Identity */}
      <section className="panel p-6 col-span-full">
        <div className="mb-4 flex items-center gap-3">
          <div className="brand-badge"><User size={18} /></div>
          <div>
            <span className="eyebrow">Account</span>
            <h3 className="text-2xl font-black tracking-tight">{me.username}</h3>
          </div>
        </div>
        <div className="flex flex-wrap gap-2 text-sm">
          <span className="stat-tile px-3 py-2">
            <span className="stat-label">Role</span>
            <strong>{me.is_admin ? 'Administrator' : 'User'}</strong>
          </span>
          <span className="stat-tile px-3 py-2">
            <span className="stat-label">Login method</span>
            <strong>{isOIDC ? 'OIDC / SSO' : 'Password'}</strong>
          </span>
          <span className="stat-tile px-3 py-2">
            <span className="stat-label">2FA</span>
            <strong>{me.totp_enabled ? 'Enabled' : 'Disabled'}</strong>
          </span>
        </div>
      </section>

      {/* Change password */}
      {!isOIDC && (
        <section className="panel p-6">
          <div className="mb-4 flex items-center gap-3">
            <div className="brand-badge"><KeyRound size={18} /></div>
            <div>
              <span className="eyebrow">Security</span>
              <h3 className="text-xl font-black tracking-tight">Change password</h3>
            </div>
          </div>
          <form onSubmit={handleChangePassword} className="space-y-3">
            <div className="space-y-1.5">
              <label className="field-label">Current password</label>
              <div className="relative">
                <input
                  className="input-field pr-10"
                  type={showPw ? 'text' : 'password'}
                  required
                  value={pwForm.old_password}
                  onChange={e => setPwForm({ ...pwForm, old_password: e.target.value })}
                />
                <button type="button" onClick={() => setShowPw(v => !v)} className="absolute right-3 top-1/2 -translate-y-1/2 text-[var(--muted)]">
                  {showPw ? <EyeOff size={15} /> : <Eye size={15} />}
                </button>
              </div>
            </div>
            <div className="space-y-1.5">
              <label className="field-label">New password</label>
              <input
                className="input-field"
                type="password"
                required
                minLength={8}
                value={pwForm.password}
                onChange={e => setPwForm({ ...pwForm, password: e.target.value })}
              />
            </div>
            <div className="space-y-1.5">
              <label className="field-label">Confirm new password</label>
              <input
                className="input-field"
                type="password"
                required
                value={pwForm.confirm}
                onChange={e => setPwForm({ ...pwForm, confirm: e.target.value })}
              />
            </div>
            {pwError && <p className="text-sm text-red-600">{pwError}</p>}
            <button type="submit" disabled={busy === 'pw'} className="primary-button">
              {busy === 'pw' ? 'Saving…' : 'Change password'}
            </button>
          </form>
        </section>
      )}

      {/* 2FA */}
      {!isOIDC && (
        <section className="panel p-6">
          <div className="mb-4 flex items-center gap-3">
            <div className="brand-badge"><ShieldCheck size={18} /></div>
            <div>
              <span className="eyebrow">Two-factor authentication</span>
              <h3 className="text-xl font-black tracking-tight">
                {me.totp_enabled ? 'Enabled' : 'Not enabled'}
              </h3>
            </div>
          </div>

          {totpSetup && (
            <div className="mb-4 space-y-3 rounded-2xl border border-[var(--border)] bg-[var(--surface-soft)] p-4">
              <p className="text-sm text-[var(--muted)]">Scan this code in your authenticator app, then enter the 6-digit code to confirm.</p>
              {showQR && (
                <div className="flex justify-center">
                  <img
                    src={`https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(totpSetup.otpauth_url)}`}
                    alt="QR Code"
                    className="rounded-xl"
                  />
                </div>
              )}
              <p className="break-all rounded-xl border border-[var(--border)] bg-[var(--panel-strong)] px-3 py-2 font-mono text-xs">{totpSetup.secret}</p>
              <div className="flex gap-2">
                <input
                  className="input-field"
                  placeholder="123456"
                  value={totpCode}
                  onChange={e => setTotpCode(e.target.value)}
                  inputMode="numeric"
                  maxLength={6}
                />
                <button type="button" onClick={handleEnable2FA} disabled={busy === '2fa'} className="primary-button whitespace-nowrap">
                  {busy === '2fa' ? 'Verifying…' : 'Enable 2FA'}
                </button>
              </div>
            </div>
          )}

          <div className="flex gap-2">
            {!me.totp_enabled && !totpSetup && (
              <button type="button" onClick={handleSetup2FA} disabled={busy === '2fa'} className="primary-button">
                {busy === '2fa' ? 'Setting up…' : 'Set up 2FA'}
              </button>
            )}
            {me.totp_enabled && (
              <button type="button" onClick={handleDisable2FA} disabled={busy === '2fa'} className="ghost-button ghost-button-danger">
                {busy === '2fa' ? 'Disabling…' : 'Disable 2FA'}
              </button>
            )}
          </div>
        </section>
      )}

      {/* Proxy credentials */}
      <section className="panel p-6 col-span-full">
        <div className="mb-4 flex items-center gap-3">
          <div className="brand-badge"><KeyRound size={18} /></div>
          <div>
            <span className="eyebrow">Proxy access</span>
            <h3 className="text-xl font-black tracking-tight">HTTP/SOCKS5 credentials</h3>
          </div>
        </div>
        <p className="mb-4 text-sm text-[var(--muted)]">
          Create a username and password to use the server's HTTP CONNECT proxy or SOCKS5 proxy from your browser or applications.
        </p>

        {createdCred && (
          <div className="success-panel mb-4">
            <p className="mb-2 text-sm font-semibold">Credential created — save the password now, it won't be shown again.</p>
            <p className="font-mono text-sm"><span className="text-[var(--muted)]">Username:</span> {createdCred.username}</p>
            <p className="font-mono text-sm"><span className="text-[var(--muted)]">Password:</span> {createdCred.password}</p>
          </div>
        )}

        <div className="mb-4 space-y-2">
          {creds.map(c => (
            <div key={c.id} className="flex items-center gap-3 rounded-2xl border border-[var(--border)] bg-[var(--panel-strong)] p-3">
              <div className="flex-1">
                <p className="font-mono text-sm font-semibold">{c.username}</p>
                <p className="text-xs text-[var(--muted)]">{c.name} · created {new Date(c.created_at).toLocaleDateString()}</p>
              </div>
              <button type="button" onClick={() => handleDeleteCred(c.id)} className="ghost-button ghost-button-danger text-xs">Delete</button>
            </div>
          ))}
        </div>

        <button type="button" onClick={handleCreateCred} disabled={busy === 'cred'} className="primary-button">
          <KeyRound size={15} />
          <span>{busy === 'cred' ? 'Creating…' : 'Create credential'}</span>
        </button>
      </section>

      {turnEnabled && (
        <section className="panel p-6 col-span-full">
          <div className="mb-4 flex items-center gap-3">
            <div className="brand-badge"><RadioTower size={18} /></div>
            <div>
              <span className="eyebrow">TURN access</span>
              <h3 className="text-xl font-black tracking-tight">Hosted relay credentials</h3>
            </div>
          </div>
          <p className="mb-4 text-sm text-[var(--muted)]">
            Generate per-user TURN credentials for hosted relay listeners. These are useful for WireGuard-over-TURN and for NAT traversal workflows that need a stable relay path.
          </p>

          {createdTurnCred && (
            <div className="success-panel mb-4">
              <p className="mb-2 text-sm font-semibold">TURN credential created — save the password now, it won't be shown again.</p>
              <p className="font-mono text-sm"><span className="text-[var(--muted)]">Username:</span> {createdTurnCred.username}</p>
              <p className="font-mono text-sm"><span className="text-[var(--muted)]">Password:</span> {createdTurnCred.password}</p>
              {Array.isArray(createdTurnCred.profiles) && createdTurnCred.profiles.map((profile) => (
                <p key={profile.url} className="break-all font-mono text-xs"><span className="text-[var(--muted)]">{profile.label}:</span> {profile.url}</p>
              ))}
            </div>
          )}

          <div className="mb-4 space-y-2">
            {turnCreds.map((cred) => (
              <div key={cred.id} className="rounded-2xl border border-[var(--border)] bg-[var(--panel-strong)] p-3">
                <div className="flex items-center justify-between gap-3">
                  <div className="flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <p className="font-mono text-sm font-semibold">{cred.username}</p>
                      {cred.connected ? (
                        <span className="status-chip">connected</span>
                      ) : (
                        <span className="status-chip status-chip-muted">idle</span>
                      )}
                    </div>
                    <p className="text-xs text-[var(--muted)]">{cred.name} · port {cred.port}</p>
                    {Array.isArray(cred.profiles) && cred.profiles.length > 0 && (
                      <div className="mt-2 space-y-1">
                        {cred.profiles.map((profile) => (
                          <p key={profile.url} className="break-all font-mono text-xs"><span className="text-[var(--muted)]">{profile.label}:</span> {profile.url}</p>
                        ))}
                      </div>
                    )}
                  </div>
                  <button type="button" onClick={() => handleDeleteTurnCred(cred.id)} className="ghost-button ghost-button-danger text-xs">Delete</button>
                </div>
              </div>
            ))}
          </div>

          {turnSelfService ? (
            <div className="space-y-3 rounded-2xl border border-[var(--border)] bg-[var(--surface-soft)] p-4">
              <div className="grid gap-3 md:grid-cols-2">
                <div className="space-y-1.5">
                  <label className="field-label">Credential name</label>
                  <input className="input-field" value={turnForm.name} onChange={(event) => setTurnForm({ ...turnForm, name: event.target.value })} />
                </div>
                <div className="space-y-1.5">
                  <label className="field-label">Optional WireGuard public key</label>
                  <input className="input-field font-mono text-sm" placeholder="leave empty to require embedded key in username" value={turnForm.wireguard_public_key} onChange={(event) => setTurnForm({ ...turnForm, wireguard_public_key: event.target.value })} />
                </div>
              </div>
              <button type="button" onClick={handleCreateTurnCred} disabled={busy === 'turn'} className="primary-button">
                <RadioTower size={15} />
                <span>{busy === 'turn' ? 'Creating…' : 'Create TURN credential'}</span>
              </button>
            </div>
          ) : (
            <p className="text-sm text-[var(--muted)]">TURN self-service is disabled by the administrator.</p>
          )}
        </section>
      )}
    </div>
  );
}
