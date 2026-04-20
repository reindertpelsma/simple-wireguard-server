import { useEffect, useState } from 'react';
import { FileText, KeyRound, Network, Power, Save, ShieldCheck } from 'lucide-react';
import { api } from '../lib/api';

export default function SettingsTab() {
  const [config, setConfig] = useState({});
  const [yamlInfo, setYamlInfo] = useState({ enabled: false, custom: '', effective: '', generated: '' });
  const [customYaml, setCustomYaml] = useState('');
  const [customEnabled, setCustomEnabled] = useState(false);
  const [me, setMe] = useState(null);
  const [totpSetup, setTotpSetup] = useState(null);
  const [totpCode, setTotpCode] = useState('');
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState('');

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    setLoading(true);
    try {
      const currentConfig = await api.getAdminConfig();
      setConfig(currentConfig);
      const currentYaml = await api.getYAMLConfig();
      setYamlInfo(currentYaml);
      setCustomYaml(currentYaml.custom || currentYaml.effective || currentYaml.generated || '');
      setCustomEnabled(!!currentYaml.enabled);
      setMe(await api.getMe());
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleUpdate = async (event) => {
    event.preventDefault();
    try {
      await api.updateGlobalConfig(config);
      alert('Config updated. Some daemon changes may still need a restart.');
      fetchData();
    } catch (err) {
      alert(err.message);
    }
  };

  const handleSaveYaml = async () => {
    setBusy('yaml');
    try {
      await api.saveYAMLConfig({ enabled: customEnabled, custom: customYaml });
      alert('YAML configuration saved.');
      await fetchData();
    } catch (err) {
      alert(err.message);
    } finally {
      setBusy('');
    }
  };

  const handleRestart = async () => {
    if (!confirm('Restart the managed uwgsocks/uwgkm daemon now? Existing daemon-side sessions may reconnect.')) return;
    setBusy('restart');
    try {
      await api.restartDaemon();
      alert('Daemon restarted and peers re-synced.');
    } catch (err) {
      alert(err.message);
    } finally {
      setBusy('');
    }
  };

  const handleSetup2FA = async () => {
    setBusy('2fa');
    try {
      const result = await api.setupTOTP();
      setTotpSetup(result);
      setTotpCode('');
    } catch (err) {
      alert(err.message);
    } finally {
      setBusy('');
    }
  };

  const handleEnable2FA = async () => {
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

  const directiveKeys = ['enable_client_ipv6', 'client_allowed_ips', 'client_config_tcp', 'client_config_turn_url', 'client_config_skipverifytls', 'client_config_url'];
  const editableConfigEntries = Object.entries(config).filter(([key]) => !['custom_yaml', 'custom_yaml_enabled', ...directiveKeys].includes(key));

  if (loading) {
    return <div className="state-shell py-24 text-[var(--muted)]">Loading settings…</div>;
  }

  return (
    <div className="grid gap-6 xl:grid-cols-[1.2fr_0.8fr]">
      <section className="panel p-6">
        <div className="mb-6 flex items-center gap-3">
          <div className="brand-badge">
            <Save size={18} />
          </div>
          <div>
            <span className="eyebrow">Operator Settings</span>
            <h3 className="text-2xl font-black tracking-tight">Global configuration</h3>
          </div>
        </div>

        <form onSubmit={handleUpdate} className="grid gap-4 md:grid-cols-2">
          {editableConfigEntries.map(([key, value]) => (
            <div key={key} className="space-y-2">
              <label className="field-label">{key.replace(/_/g, ' ')}</label>
              <input
                type="text"
                className="input-field"
                value={value}
                onChange={(event) => setConfig({ ...config, [key]: event.target.value })}
              />
            </div>
          ))}

          <div className="md:col-span-2">
            <div className="flex flex-wrap gap-3">
              <button type="submit" className="primary-button">
                <Save size={16} />
                <span>Save settings</span>
              </button>
              <button type="button" onClick={handleRestart} disabled={busy === 'restart'} className="secondary-button">
                <Power size={16} />
                <span>{busy === 'restart' ? 'Restarting…' : 'Restart daemon'}</span>
              </button>
            </div>
          </div>
        </form>

        <div className="mt-6 rounded-3xl border border-[var(--border)] bg-[var(--surface-soft)] p-5">
          <div className="mb-4 flex items-center gap-3">
            <div className="brand-badge">
              <ShieldCheck size={18} />
            </div>
            <div>
              <span className="eyebrow">Account Security</span>
              <h4 className="text-xl font-black tracking-tight">Two-factor authentication</h4>
            </div>
          </div>
          <p className="mb-4 text-sm text-[var(--muted)]">
            Status for {me?.username || 'your account'}: {me?.totp_enabled ? '2FA enabled' : '2FA not enabled'}.
          </p>
          {totpSetup && (
            <div className="mb-4 space-y-3">
              <div className="info-tile">
                <span className="stat-label">Authenticator secret</span>
                <strong className="break-all font-mono text-sm">{totpSetup.secret}</strong>
                <code className="mt-2 block break-all text-xs">{totpSetup.otpauth_url}</code>
              </div>
              <div className="grid gap-3 sm:grid-cols-[1fr_auto]">
                <input className="input-field" inputMode="numeric" placeholder="Enter 6-digit code" value={totpCode} onChange={(event) => setTotpCode(event.target.value)} />
                <button type="button" onClick={handleEnable2FA} disabled={busy === '2fa'} className="primary-button justify-center">Enable 2FA</button>
              </div>
            </div>
          )}
          <div className="flex flex-wrap gap-3">
            {!me?.totp_enabled && (
              <button type="button" onClick={handleSetup2FA} disabled={busy === '2fa'} className="secondary-button">
                <KeyRound size={16} />
                <span>{totpSetup ? 'Regenerate secret' : 'Set up 2FA'}</span>
              </button>
            )}
            {me?.totp_enabled && (
              <button type="button" onClick={handleDisable2FA} disabled={busy === '2fa'} className="ghost-button ghost-button-danger">
                Disable 2FA
              </button>
            )}
          </div>
        </div>
      </section>

      <div className="grid gap-6">
      <section className="panel p-6">
        <div className="mb-6 flex items-center gap-3">
          <div className="brand-badge">
            <Network size={18} />
          </div>
          <div>
            <span className="eyebrow">Client Config Directives</span>
            <h3 className="text-2xl font-black tracking-tight">Downloaded config options</h3>
          </div>
        </div>
        <p className="mb-4 text-sm text-[var(--muted)]">
          These settings are embedded as <code className="font-mono">#!</code> directives in downloaded WireGuard configs and are parsed by uwgsocks clients.
        </p>
        <form onSubmit={handleUpdate} className="grid gap-4 md:grid-cols-2">
          <div className="space-y-2 md:col-span-2">
            <label className="field-label">Push routes (AllowedIPs)</label>
            <input
              type="text"
              className="input-field font-mono text-sm"
              placeholder="0.0.0.0/0, ::/0"
              value={config.client_allowed_ips || ''}
              onChange={(e) => setConfig({ ...config, client_allowed_ips: e.target.value })}
            />
            <p className="text-xs text-[var(--muted)]">Controls what traffic clients route through the server. Default: <code className="font-mono">0.0.0.0/0, ::/0</code> (all traffic).</p>
          </div>
          <div className="space-y-2 md:col-span-2">
            <label className="field-label">IPv6 client addresses</label>
            <select
              className="input-field"
              value={config.enable_client_ipv6 || 'false'}
              onChange={(e) => setConfig({ ...config, enable_client_ipv6: e.target.value })}
            >
              <option value="true">Enabled — allocate IPv6 addresses and include ::/0 in AllowedIPs</option>
              <option value="false">Disabled — IPv4 only</option>
            </select>
          </div>
          <div className="space-y-2">
            <label className="field-label">#!TCP directive</label>
            <select
              className="input-field"
              value={config.client_config_tcp || ''}
              onChange={(e) => setConfig({ ...config, client_config_tcp: e.target.value })}
            >
              <option value="">Not set (use UDP / server default)</option>
              <option value="supported">supported — prefer TCP, fall back to UDP</option>
              <option value="required">required — TCP only</option>
            </select>
          </div>
          <div className="space-y-2">
            <label className="field-label">#!SkipVerifyTLS directive</label>
            <select
              className="input-field"
              value={config.client_config_skipverifytls || ''}
              onChange={(e) => setConfig({ ...config, client_config_skipverifytls: e.target.value })}
            >
              <option value="">Not set</option>
              <option value="yes">yes — skip TLS certificate verification</option>
            </select>
          </div>
          <div className="space-y-2">
            <label className="field-label">#!TURN= URL</label>
            <input
              type="text"
              className="input-field"
              placeholder="turn+tls://user:pass@turn.example.com:443"
              value={config.client_config_turn_url || ''}
              onChange={(e) => setConfig({ ...config, client_config_turn_url: e.target.value })}
            />
          </div>
          <div className="space-y-2">
            <label className="field-label">#!URL= (WebSocket/HTTP transport URL)</label>
            <input
              type="text"
              className="input-field"
              placeholder="https://vpn.example.com/wireguard"
              value={config.client_config_url || ''}
              onChange={(e) => setConfig({ ...config, client_config_url: e.target.value })}
            />
          </div>
          <div className="md:col-span-2">
            <button type="submit" className="primary-button">
              <Save size={16} />
              <span>Save</span>
            </button>
          </div>
        </form>
      </section>

      <section className="panel p-6">
        <div className="mb-6 flex items-center gap-3">
          <div className="brand-badge">
            <FileText size={18} />
          </div>
          <div>
            <span className="eyebrow">Canonical Output</span>
            <h3 className="text-2xl font-black tracking-tight">Daemon YAML override</h3>
          </div>
        </div>
        <div className="space-y-4">
          <label className="flex items-center gap-3 rounded-2xl border border-[var(--border)] bg-[var(--surface-soft)] px-4 py-3 text-sm font-medium">
            <input type="checkbox" checked={customEnabled} onChange={(event) => setCustomEnabled(event.target.checked)} />
            <span>Use this custom YAML instead of the generated canonical config</span>
          </label>
          <textarea
            className="input-field min-h-[360px] resize-y font-mono text-sm leading-6"
            value={customYaml}
            spellCheck="false"
            onChange={(event) => setCustomYaml(event.target.value)}
          />
          <div className="flex flex-wrap gap-3">
            <button type="button" onClick={handleSaveYaml} disabled={busy === 'yaml'} className="primary-button">
              <FileText size={16} />
              <span>{busy === 'yaml' ? 'Saving…' : 'Save YAML'}</span>
            </button>
            <button type="button" onClick={() => setCustomYaml(yamlInfo.generated || yamlInfo.effective || '')} className="secondary-button">
              Reset to generated
            </button>
          </div>
          <div>
            <span className="field-label mb-2">Currently effective YAML</span>
            <pre className="config-block max-h-[320px]">{yamlInfo.effective || yamlInfo.generated}</pre>
          </div>
        </div>
      </section>
      </div>
    </div>
  );
}
