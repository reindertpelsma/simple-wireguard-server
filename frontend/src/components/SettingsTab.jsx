import { useEffect, useState } from 'react';
import { FileText, Network, Power, Save } from 'lucide-react';
import { api } from '../lib/api';

export default function SettingsTab() {
  const [config, setConfig] = useState({});
  const [yamlInfo, setYamlInfo] = useState({ enabled: false, custom: '', effective: '', generated: '' });
  const [customYaml, setCustomYaml] = useState('');
  const [customEnabled, setCustomEnabled] = useState(false);
  const [services, setServices] = useState([]);
  const [serviceForm, setServiceForm] = useState({
    name: '',
    host: '',
    target_url: '',
    auth_mode: 'login',
    bypass_cidrs: '',
    cors_protection: true,
    allowed_origins: '',
    insecure_skip_verify: false,
    ca_pem: '',
    client_cert_pem: '',
  });
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
      setServices(await api.getExposedServices());
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

  const handleCreateService = async (event) => {
    event.preventDefault();
    setBusy('service');
    try {
      await api.createExposedService(serviceForm);
      setServices(await api.getExposedServices());
      setServiceForm({ ...serviceForm, name: '', host: '', target_url: '' });
    } catch (err) {
      alert(err.message);
    } finally {
      setBusy('');
    }
  };

  const handleDeleteService = async (id) => {
    if (!confirm('Delete this exposed service?')) return;
    setBusy('service');
    try {
      await api.deleteExposedService(id);
      setServices(await api.getExposedServices());
    } catch (err) {
      alert(err.message);
    } finally {
      setBusy('');
    }
  };

  const directiveKeys = ['enable_client_ipv6', 'client_allowed_ips', 'client_config_tcp', 'client_config_turn_url', 'client_config_skipverifytls', 'client_config_url', 'peer_sync_mode', 'peer_sync_port'];
  const accessKeys = ['trusted_proxy_cidrs', 'web_base_url', 'http_proxy_access_enabled', 'socket_proxy_enabled', 'socket_proxy_http_port', 'exposed_services_enabled', 'service_auth_cookie_seconds'];
  const turnKeys = ['turn_hosting_enabled', 'turn_hosting_realm', 'turn_hosting_relay_ip', 'turn_allow_user_credentials', 'turn_max_user_credentials', 'turn_user_port_start', 'turn_user_port_end'];
  const explicitKeys = ['yaml_host_forward_redirect_ip'];
  const editableConfigEntries = Object.entries(config).filter(([key]) => !['custom_yaml', 'custom_yaml_enabled', ...directiveKeys, ...accessKeys, ...turnKeys, ...explicitKeys].includes(key));

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

          <div className="space-y-2">
            <label className="field-label">Host forward redirect IP</label>
            <input
              type="text"
              className="input-field font-mono text-sm"
              placeholder="127.0.0.1 — leave empty to disable"
              value={config.yaml_host_forward_redirect_ip || ''}
              onChange={(e) => setConfig({ ...config, yaml_host_forward_redirect_ip: e.target.value })}
            />
            <p className="text-xs text-[var(--muted)]">IP to redirect host-forward traffic to. Leave empty to disable host forwarding entirely.</p>
          </div>

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
              <Network size={18} />
            </div>
            <div>
              <span className="eyebrow">Reverse Proxy Access</span>
              <h4 className="text-xl font-black tracking-tight">Web and proxy entrypoints</h4>
            </div>
          </div>
          <form onSubmit={handleUpdate} className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2 md:col-span-2">
              <label className="field-label">Base URL</label>
              <input className="input-field" placeholder="https://wireguard.example.com" value={config.web_base_url || ''} onChange={(event) => setConfig({ ...config, web_base_url: event.target.value })} />
            </div>
            <div className="space-y-2 md:col-span-2">
              <label className="field-label">Trusted proxy CIDRs</label>
              <textarea className="input-field min-h-24 font-mono text-sm" placeholder="127.0.0.1/32, ::1/128, 10.0.0.0/8" value={config.trusted_proxy_cidrs || ''} onChange={(event) => setConfig({ ...config, trusted_proxy_cidrs: event.target.value })} />
            </div>
            <div className="space-y-2">
              <label className="field-label">HTTPS proxy access</label>
              <select className="input-field" value={config.http_proxy_access_enabled || 'false'} onChange={(event) => setConfig({ ...config, http_proxy_access_enabled: event.target.value })}>
                <option value="false">Disabled</option>
                <option value="true">Enabled at /proxy</option>
              </select>
            </div>
            <div className="space-y-2">
              <label className="field-label">WireGuard /socket tunnel</label>
              <select className="input-field" value={config.socket_proxy_enabled || 'false'} onChange={(event) => setConfig({ ...config, socket_proxy_enabled: event.target.value })}>
                <option value="false">Disabled</option>
                <option value="true">Enabled</option>
              </select>
            </div>
            <div className="space-y-2">
              <label className="field-label">Loopback /socket port</label>
              <input className="input-field" value={config.socket_proxy_http_port || ''} onChange={(event) => setConfig({ ...config, socket_proxy_http_port: event.target.value })} />
            </div>
            <div className="space-y-2">
              <label className="field-label">Exposed services</label>
              <select className="input-field" value={config.exposed_services_enabled || 'true'} onChange={(event) => setConfig({ ...config, exposed_services_enabled: event.target.value })}>
                <option value="true">Enabled</option>
                <option value="false">Disabled</option>
              </select>
            </div>
            <div className="md:col-span-2">
              <button type="submit" className="primary-button"><Save size={16} /><span>Save access settings</span></button>
            </div>
          </form>

        </div>

        <div className="mt-6 rounded-3xl border border-[var(--border)] bg-[var(--surface-soft)] p-5">
          <div className="mb-4 flex items-center gap-3">
            <div className="brand-badge">
              <Network size={18} />
            </div>
            <div>
              <span className="eyebrow">TURN Hosting</span>
              <h4 className="text-xl font-black tracking-tight">Managed relay daemon</h4>
            </div>
          </div>
          <form onSubmit={handleUpdate} className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <label className="field-label">TURN hosting</label>
              <select className="input-field" value={config.turn_hosting_enabled || 'false'} onChange={(event) => setConfig({ ...config, turn_hosting_enabled: event.target.value })}>
                <option value="false">Disabled</option>
                <option value="true">Enabled</option>
              </select>
            </div>
            <div className="space-y-2">
              <label className="field-label">User self-service</label>
              <select className="input-field" value={config.turn_allow_user_credentials || 'false'} onChange={(event) => setConfig({ ...config, turn_allow_user_credentials: event.target.value })}>
                <option value="false">Disabled</option>
                <option value="true">Users can create TURN credentials</option>
              </select>
            </div>
            <div className="space-y-2">
              <label className="field-label">TURN realm</label>
              <input className="input-field" value={config.turn_hosting_realm || ''} onChange={(event) => setConfig({ ...config, turn_hosting_realm: event.target.value })} />
            </div>
            <div className="space-y-2">
              <label className="field-label">Relay IP</label>
              <input className="input-field" placeholder="public relay IP" value={config.turn_hosting_relay_ip || ''} onChange={(event) => setConfig({ ...config, turn_hosting_relay_ip: event.target.value })} />
            </div>
            <div className="space-y-2">
              <label className="field-label">Max credentials per user</label>
              <input className="input-field" value={config.turn_max_user_credentials || ''} onChange={(event) => setConfig({ ...config, turn_max_user_credentials: event.target.value })} />
            </div>
            <div className="space-y-2">
              <label className="field-label">User port range</label>
              <div className="grid grid-cols-2 gap-2">
                <input className="input-field" placeholder="start" value={config.turn_user_port_start || ''} onChange={(event) => setConfig({ ...config, turn_user_port_start: event.target.value })} />
                <input className="input-field" placeholder="end" value={config.turn_user_port_end || ''} onChange={(event) => setConfig({ ...config, turn_user_port_end: event.target.value })} />
              </div>
            </div>
            <div className="md:col-span-2">
              <button type="submit" className="primary-button"><Save size={16} /><span>Save TURN settings</span></button>
            </div>
          </form>
        </div>
      </section>

      <div className="grid gap-6">
      <section className="panel p-6">
        <div className="mb-6 flex items-center gap-3">
          <div className="brand-badge">
            <Network size={18} />
          </div>
          <div>
            <span className="eyebrow">Private Web Apps</span>
            <h3 className="text-2xl font-black tracking-tight">Exposed services</h3>
          </div>
        </div>
        <form onSubmit={handleCreateService} className="grid gap-4 md:grid-cols-2">
          <input className="input-field" placeholder="service name" value={serviceForm.name} onChange={(event) => setServiceForm({ ...serviceForm, name: event.target.value })} />
          <input className="input-field" placeholder="service.wireguard.example.com" value={serviceForm.host} onChange={(event) => setServiceForm({ ...serviceForm, host: event.target.value })} />
          <input className="input-field md:col-span-2" placeholder="http://100.64.0.10:8080" value={serviceForm.target_url} onChange={(event) => setServiceForm({ ...serviceForm, target_url: event.target.value })} />
          <select className="input-field" value={serviceForm.auth_mode} onChange={(event) => setServiceForm({ ...serviceForm, auth_mode: event.target.value })}>
            <option value="login">Must be logged in</option>
            <option value="open">Open to the internet</option>
          </select>
          <label className="flex items-center gap-2 text-sm font-medium"><input type="checkbox" checked={serviceForm.cors_protection} onChange={(event) => setServiceForm({ ...serviceForm, cors_protection: event.target.checked })} /> CORS protection</label>
          <textarea className="input-field md:col-span-2" placeholder="Bypass CIDRs" value={serviceForm.bypass_cidrs} onChange={(event) => setServiceForm({ ...serviceForm, bypass_cidrs: event.target.value })} />
          <input className="input-field md:col-span-2" placeholder="Allowed origins for CORS bypass" value={serviceForm.allowed_origins} onChange={(event) => setServiceForm({ ...serviceForm, allowed_origins: event.target.value })} />
          <label className="flex items-center gap-2 text-sm font-medium"><input type="checkbox" checked={serviceForm.insecure_skip_verify} onChange={(event) => setServiceForm({ ...serviceForm, insecure_skip_verify: event.target.checked })} /> Skip backend TLS verification</label>
          <textarea className="input-field md:col-span-2 font-mono text-sm" placeholder="Backend CA PEM" value={serviceForm.ca_pem} onChange={(event) => setServiceForm({ ...serviceForm, ca_pem: event.target.value })} />
          <textarea className="input-field md:col-span-2 font-mono text-sm" placeholder="Client certificate and key PEM" value={serviceForm.client_cert_pem} onChange={(event) => setServiceForm({ ...serviceForm, client_cert_pem: event.target.value })} />
          <button type="submit" disabled={busy === 'service'} className="primary-button md:col-span-2"><span>Add service</span></button>
        </form>
        <div className="mt-5 grid gap-2">
          {services.map((service) => (
            <div key={service.id} className="rounded-lg border border-[var(--border)] p-3 text-sm">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <p className="font-bold">{service.host}</p>
                  <p className="text-[var(--muted)]">{service.target_url} · {service.auth_mode}</p>
                </div>
                <button type="button" onClick={() => handleDeleteService(service.id)} className="ghost-button ghost-button-danger">Delete</button>
              </div>
            </div>
          ))}
        </div>
      </section>

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
          <div className="space-y-2 md:col-span-2">
            <label className="field-label">Peer syncing / P2P discovery</label>
            <select
              className="input-field"
              value={config.peer_sync_mode || 'disabled'}
              onChange={(e) => setConfig({ ...config, peer_sync_mode: e.target.value })}
            >
              <option value="disabled">Disabled</option>
              <option value="opt_in">Only clients that opt in</option>
              <option value="enabled">Enabled for all clients</option>
            </select>
            <p className="text-xs text-[var(--muted)]">Runs a tunnel-only peer sync controller and adds `#!Control=` to downloaded configs for selected uwgsocks clients. It enables P2P discovery and multi-server peer syncing. Standard WireGuard clients safely ignore the directive.</p>
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
              placeholder="https://user:pass@turn.example.com:443/turn"
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
