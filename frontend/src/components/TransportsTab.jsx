import { useEffect, useState } from 'react';
import { ChevronDown, ChevronUp, Edit3, Plus, Radio, Trash2 } from 'lucide-react';
import { api } from '../lib/api';

const BASE_OPTIONS = ['udp', 'tcp', 'tls', 'dtls', 'http', 'https', 'quic', 'quic-ws', 'turn', 'url'];
const PROXY_TYPES = ['', 'socks5', 'http'];

const EMPTY_FORM = {
  name: '',
  base: 'udp',
  listen: false,
  listen_port: '',
  listen_addrs: '',
  url: '',
  ws_path: '',
  connect_host: '',
  host_header: '',
  turn_server: '',
  turn_username: '',
  turn_password: '',
  turn_realm: '',
  turn_protocol: 'udp',
  turn_no_create_permission: false,
  turn_include_wg_public_key: false,
  turn_permissions: '',
  tls_cert_file: '',
  tls_key_file: '',
  tls_ca_file: '',
  tls_verify_peer: false,
  tls_server_sni: '',
  proxy_type: '',
  proxy_server: '',
  proxy_username: '',
  proxy_password: '',
};

const INPUT =
  'w-full rounded border border-gray-300 bg-white px-2 py-1 text-gray-900 placeholder-gray-400 dark:border-gray-600 dark:bg-gray-700 dark:text-gray-100 dark:placeholder-gray-500';
const SELECT = INPUT;
const LABEL = 'flex flex-col gap-1 text-sm text-gray-700 dark:text-gray-300';

function needsTLS(base) {
  return ['tls', 'dtls', 'https', 'quic', 'quic-ws', 'url'].includes(base);
}

function needsTurn(base) {
  return base === 'turn';
}

function turnUsesTLS(base, protocol) {
  return base === 'turn' && ['tls', 'dtls'].includes(protocol);
}

function needsWebSocket(base) {
  return ['http', 'https', 'quic', 'quic-ws', 'url'].includes(base);
}

function connectionBadge(transport) {
  if (transport.connected) {
    return { label: 'connected', className: 'rounded-full bg-green-100 px-2 py-0.5 text-xs font-medium text-green-700 dark:bg-green-900 dark:text-green-300' };
  }
  return { label: 'idle', className: 'rounded-full bg-gray-100 px-2 py-0.5 text-xs font-medium text-gray-700 dark:bg-gray-700 dark:text-gray-300' };
}

export default function TransportsTab() {
  const [transports, setTransports] = useState([]);
  const [showForm, setShowForm] = useState(false);
  const [editId, setEditId] = useState(null);
  const [form, setForm] = useState(EMPTY_FORM);
  const [expanded, setExpanded] = useState({});
  const [error, setError] = useState('');

  async function fetchTransports() {
    try {
      const data = await api.getTransports();
      return data || [];
    } catch (err) {
      console.error(err);
      return [];
    }
  }

  useEffect(() => {
    let cancelled = false;

    async function loadTransports() {
      const data = await fetchTransports();
      if (!cancelled) {
        setTransports(data);
      }
    }

    loadTransports();
    return () => {
      cancelled = true;
    };
  }, []);

  const set = (key, value) => setForm((f) => ({ ...f, [key]: value }));

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    const payload = {
      ...form,
      listen_port: form.listen_port ? parseInt(form.listen_port, 10) : 0,
    };
    try {
      if (editId != null) {
        await api.updateTransport(editId, payload);
      } else {
        await api.createTransport(payload);
      }
      setTransports(await fetchTransports());
      setForm(EMPTY_FORM);
      setShowForm(false);
      setEditId(null);
    } catch (err) {
      setError(err.message);
    }
  };

  const handleEdit = (t) => {
    setForm({
      name: t.name ?? '',
      base: t.base ?? 'udp',
      listen: t.listen ?? false,
      listen_port: t.listen_port ? String(t.listen_port) : '',
      listen_addrs: t.listen_addrs ?? '',
      url: t.url ?? '',
      ws_path: t.ws_path ?? '',
      connect_host: t.connect_host ?? '',
      host_header: t.host_header ?? '',
      turn_server: t.turn_server ?? '',
      turn_username: t.turn_username ?? '',
      turn_password: t.turn_password ?? '',
      turn_realm: t.turn_realm ?? '',
      turn_protocol: t.turn_protocol ?? 'udp',
      turn_no_create_permission: t.turn_no_create_permission ?? false,
      turn_include_wg_public_key: t.turn_include_wg_public_key ?? false,
      turn_permissions: t.turn_permissions ?? '',
      tls_cert_file: t.tls_cert_file ?? '',
      tls_key_file: t.tls_key_file ?? '',
      tls_ca_file: t.tls_ca_file ?? '',
      tls_verify_peer: t.tls_verify_peer ?? false,
      tls_server_sni: t.tls_server_sni ?? '',
      proxy_type: t.proxy_type ?? '',
      proxy_server: t.proxy_server ?? '',
      proxy_username: t.proxy_username ?? '',
      proxy_password: t.proxy_password ?? '',
    });
    setEditId(t.id);
    setShowForm(true);
  };

  const handleDelete = async (id) => {
    if (!confirm('Delete this transport?')) return;
    try {
      await api.deleteTransport(id);
      setTransports(await fetchTransports());
    } catch (err) {
      alert(err.message);
    }
  };

  const toggleExpand = (id) => setExpanded((e) => ({ ...e, [id]: !e[id] }));

  return (
    <div className="space-y-6">
      <div className="rounded-lg border border-blue-200 bg-blue-50 px-4 py-3 text-sm text-blue-800 dark:border-blue-800 dark:bg-blue-950 dark:text-blue-200">
        Transport add/remove/update is applied live without a daemon restart. However, <strong>listener port changes</strong> (enabling or changing a listen port) only take effect after restarting the daemon from the Settings tab.
      </div>
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Radio className="h-5 w-5 text-blue-500" />
          <h2 className="text-lg font-semibold text-gray-900 dark:text-gray-100">Transports</h2>
        </div>
        <button
          onClick={() => { setForm(EMPTY_FORM); setEditId(null); setShowForm((s) => !s); setError(''); }}
          className="flex items-center gap-1 rounded-md bg-blue-600 px-3 py-1.5 text-sm text-white hover:bg-blue-700"
        >
          <Plus className="h-4 w-4" />
          Add Transport
        </button>
      </div>

      {/* Add / Edit form */}
      {showForm && (
        <form
          onSubmit={handleSubmit}
          className="rounded-lg border border-gray-200 bg-white p-5 shadow-sm dark:border-gray-700 dark:bg-gray-800 space-y-4"
        >
          <h3 className="font-semibold text-gray-800 dark:text-gray-100">
            {editId != null ? 'Edit Transport' : 'New Transport'}
          </h3>

          {/* Name + Base + Listen */}
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <label className={`sm:col-span-1 ${LABEL}`}>
              Name *
              <input className={INPUT} required value={form.name} onChange={(e) => set('name', e.target.value)} placeholder="e.g. ws-server" />
            </label>
            <label className={LABEL}>
              Base Protocol *
              <select className={SELECT} value={form.base} onChange={(e) => set('base', e.target.value)}>
                {BASE_OPTIONS.map((b) => <option key={b} value={b}>{b}</option>)}
              </select>
            </label>
            <label className="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300 pt-5">
              <input type="checkbox" checked={form.listen} onChange={(e) => set('listen', e.target.checked)} className="h-4 w-4" />
              Enable Listener
            </label>
          </div>

          {/* Listen port + addresses (when listener enabled) */}
          {form.listen && (
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <label className={LABEL}>
                Listen Port
                <input
                  className={INPUT}
                  type="number"
                  min="1"
                  max="65535"
                  value={form.listen_port}
                  onChange={(e) => set('listen_port', e.target.value)}
                  placeholder="51820 (0 = use WireGuard port)"
                />
              </label>
              <label className={LABEL}>
                Listen Addresses
                <input
                  className={INPUT}
                  value={form.listen_addrs}
                  onChange={(e) => set('listen_addrs', e.target.value)}
                  placeholder="0.0.0.0, :: (comma-separated, empty = all)"
                />
              </label>
            </div>
          )}

          {/* URL for base=url */}
          {form.base === 'url' && (
            <label className={LABEL}>
              URL *
              <input className={INPUT} value={form.url} onChange={(e) => set('url', e.target.value)} placeholder="https://vpn.example.com/wg" />
            </label>
          )}

          {needsTurn(form.base) && (
            <details className="rounded border border-gray-200 p-3 dark:border-gray-600" open>
              <summary className="cursor-pointer text-sm font-medium text-gray-600 hover:text-gray-800 dark:text-gray-400 dark:hover:text-gray-200">
                TURN Settings
              </summary>
              <div className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-2">
                <label className={LABEL}>
                  TURN Server *
                  <input className={INPUT} value={form.turn_server} onChange={(e) => set('turn_server', e.target.value)} placeholder="turn.example.com:3478" />
                </label>
                <label className={LABEL}>
                  TURN Protocol
                  <select className={SELECT} value={form.turn_protocol} onChange={(e) => set('turn_protocol', e.target.value)}>
                    {['udp', 'tcp', 'tls', 'dtls'].map((protocol) => <option key={protocol} value={protocol}>{protocol}</option>)}
                  </select>
                </label>
                <label className={LABEL}>
                  Username
                  <input className={INPUT} value={form.turn_username} onChange={(e) => set('turn_username', e.target.value)} placeholder="optional" />
                </label>
                <label className={LABEL}>
                  Password
                  <input type="password" className={INPUT} value={form.turn_password} onChange={(e) => set('turn_password', e.target.value)} placeholder="optional" />
                </label>
                <label className={LABEL}>
                  Realm
                  <input className={INPUT} value={form.turn_realm} onChange={(e) => set('turn_realm', e.target.value)} placeholder="optional" />
                </label>
                <label className={LABEL}>
                  Permissions
                  <input className={INPUT} value={form.turn_permissions} onChange={(e) => set('turn_permissions', e.target.value)} placeholder="ip:port, ip:port" />
                </label>
                <label className="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300">
                  <input type="checkbox" checked={form.turn_no_create_permission} onChange={(e) => set('turn_no_create_permission', e.target.checked)} className="h-4 w-4" />
                  Skip CREATE_PERMISSION
                </label>
                <label className="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300">
                  <input type="checkbox" checked={form.turn_include_wg_public_key} onChange={(e) => set('turn_include_wg_public_key', e.target.checked)} className="h-4 w-4" />
                  Include WireGuard public key in TURN username
                </label>
              </div>
            </details>
          )}

          {/* WebSocket options */}
          {needsWebSocket(form.base) && (
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
              <label className={LABEL}>
                WS Path
                <input className={INPUT} value={form.ws_path} onChange={(e) => set('ws_path', e.target.value)} placeholder="/" />
              </label>
              <label className={LABEL}>
                Connect Host
                <input className={INPUT} value={form.connect_host} onChange={(e) => set('connect_host', e.target.value)} placeholder="(outer DNS/TCP host)" />
              </label>
              <label className={LABEL}>
                Host Header
                <input className={INPUT} value={form.host_header} onChange={(e) => set('host_header', e.target.value)} placeholder="(inner HTTP host)" />
              </label>
            </div>
          )}

          {/* TLS settings */}
          {(needsTLS(form.base) || turnUsesTLS(form.base, form.turn_protocol)) && (
            <details className="rounded border border-gray-200 p-3 dark:border-gray-600">
              <summary className="cursor-pointer text-sm font-medium text-gray-600 hover:text-gray-800 dark:text-gray-400 dark:hover:text-gray-200">
                TLS Settings
              </summary>
              <div className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-2">
                <label className={LABEL}>Cert File <input className={INPUT} value={form.tls_cert_file} onChange={(e) => set('tls_cert_file', e.target.value)} placeholder="/path/to/cert.pem" /></label>
                <label className={LABEL}>Key File  <input className={INPUT} value={form.tls_key_file}  onChange={(e) => set('tls_key_file', e.target.value)}  placeholder="/path/to/key.pem" /></label>
                <label className={LABEL}>CA File   <input className={INPUT} value={form.tls_ca_file}   onChange={(e) => set('tls_ca_file', e.target.value)}   placeholder="/path/to/ca.pem" /></label>
                <label className={LABEL}>Server SNI <input className={INPUT} value={form.tls_server_sni} onChange={(e) => set('tls_server_sni', e.target.value)} placeholder="(override SNI)" /></label>
                <label className="sm:col-span-2 flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300">
                  <input type="checkbox" checked={form.tls_verify_peer} onChange={(e) => set('tls_verify_peer', e.target.checked)} className="h-4 w-4" />
                  Verify Peer Certificate
                </label>
              </div>
            </details>
          )}

          {/* Proxy settings */}
          <details className="rounded border border-gray-200 p-3 dark:border-gray-600">
            <summary className="cursor-pointer text-sm font-medium text-gray-600 hover:text-gray-800 dark:text-gray-400 dark:hover:text-gray-200">
              Proxy Settings
            </summary>
            <div className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-2">
              <label className={LABEL}>
                Proxy Type
                <select className={SELECT} value={form.proxy_type} onChange={(e) => set('proxy_type', e.target.value)}>
                  {PROXY_TYPES.map((p) => <option key={p} value={p}>{p || 'none'}</option>)}
                </select>
              </label>
              {form.proxy_type && (
                <>
                  <label className={LABEL}>Proxy Server <input className={INPUT} value={form.proxy_server} onChange={(e) => set('proxy_server', e.target.value)} placeholder="host:port" /></label>
                  <label className={LABEL}>Username <input className={INPUT} value={form.proxy_username} onChange={(e) => set('proxy_username', e.target.value)} /></label>
                  <label className={LABEL}>Password <input type="password" className={INPUT} value={form.proxy_password} onChange={(e) => set('proxy_password', e.target.value)} /></label>
                </>
              )}
            </div>
          </details>

          {error && <p className="text-sm text-red-600 dark:text-red-400">{error}</p>}

          <div className="flex gap-2">
            <button type="submit" className="rounded-md bg-blue-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-blue-700">
              {editId != null ? 'Save Changes' : 'Create Transport'}
            </button>
            <button
              type="button"
              onClick={() => { setShowForm(false); setEditId(null); setError(''); }}
              className="rounded-md border border-gray-300 bg-white px-4 py-1.5 text-sm font-medium text-gray-700 hover:bg-gray-50 dark:border-gray-600 dark:bg-gray-700 dark:text-gray-200 dark:hover:bg-gray-600"
            >
              Cancel
            </button>
          </div>
        </form>
      )}

      {/* Transport list */}
      {transports.length === 0 ? (
        <p className="text-sm text-gray-500 dark:text-gray-400">No transports configured. Add one above.</p>
      ) : (
        <div className="space-y-2">
          {transports.map((t) => (
            <div key={t.id} className="rounded-lg border border-gray-200 bg-white dark:border-gray-700 dark:bg-gray-800">
              <div className="flex items-center justify-between px-4 py-3">
                <div className="flex flex-wrap items-center gap-2">
                  <button onClick={() => toggleExpand(t.id)} className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300">
                    {expanded[t.id] ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                  </button>
                  <span className="font-mono text-sm font-medium text-gray-900 dark:text-gray-100">{t.name}</span>
                  <span className="rounded-full bg-blue-100 px-2 py-0.5 text-xs font-medium text-blue-700 dark:bg-blue-900 dark:text-blue-300">{t.base}</span>
                  {t.base === 'turn' && t.turn_protocol && (
                    <span className="rounded-full bg-indigo-100 px-2 py-0.5 text-xs font-medium text-indigo-700 dark:bg-indigo-900 dark:text-indigo-300">
                      turn/{t.turn_protocol}
                    </span>
                  )}
                  {t.listen && (
                    <span className="rounded-full bg-green-100 px-2 py-0.5 text-xs font-medium text-green-700 dark:bg-green-900 dark:text-green-300">
                      listener{t.listen_port ? ` :${t.listen_port}` : ''}
                    </span>
                  )}
                  {(t.base === 'turn' || t.connected || t.active_sessions > 0) && (
                    <span className={connectionBadge(t).className}>
                      {connectionBadge(t).label}
                    </span>
                  )}
                  {typeof t.active_sessions === 'number' && t.active_sessions > 0 && (
                    <span className="rounded-full bg-slate-100 px-2 py-0.5 text-xs font-medium text-slate-700 dark:bg-slate-700 dark:text-slate-200">
                      {t.active_sessions} sessions
                    </span>
                  )}
                  {t.proxy_type && t.proxy_type !== 'none' && (
                    <span className="rounded-full bg-yellow-100 px-2 py-0.5 text-xs font-medium text-yellow-700 dark:bg-yellow-900 dark:text-yellow-300">
                      via {t.proxy_type}
                    </span>
                  )}
                </div>
                <div className="flex shrink-0 gap-1">
                  <button onClick={() => handleEdit(t)} className="rounded p-1 text-gray-400 hover:bg-gray-100 hover:text-blue-600 dark:hover:bg-gray-700 dark:hover:text-blue-400">
                    <Edit3 className="h-4 w-4" />
                  </button>
                  <button onClick={() => handleDelete(t.id)} className="rounded p-1 text-gray-400 hover:bg-gray-100 hover:text-red-600 dark:hover:bg-gray-700 dark:hover:text-red-400">
                    <Trash2 className="h-4 w-4" />
                  </button>
                </div>
              </div>

              {expanded[t.id] && (
                <dl className="grid grid-cols-2 gap-x-4 gap-y-1 border-t border-gray-100 px-4 py-3 text-xs dark:border-gray-700 sm:grid-cols-3">
                  {t.listen_addrs && <><dt className="text-gray-500 dark:text-gray-400">Addresses</dt><dd className="text-gray-800 dark:text-gray-200 col-span-2">{t.listen_addrs}</dd></>}
                  {t.url && <><dt className="text-gray-500 dark:text-gray-400">URL</dt><dd className="text-gray-800 dark:text-gray-200 col-span-2">{t.url}</dd></>}
                  {t.ws_path && <><dt className="text-gray-500 dark:text-gray-400">Path</dt><dd className="text-gray-800 dark:text-gray-200">{t.ws_path}</dd></>}
                  {t.connect_host && <><dt className="text-gray-500 dark:text-gray-400">Connect Host</dt><dd className="text-gray-800 dark:text-gray-200">{t.connect_host}</dd></>}
                  {t.host_header && <><dt className="text-gray-500 dark:text-gray-400">Host Header</dt><dd className="text-gray-800 dark:text-gray-200">{t.host_header}</dd></>}
                  {t.turn_server && <><dt className="text-gray-500 dark:text-gray-400">TURN Server</dt><dd className="text-gray-800 dark:text-gray-200 col-span-2">{t.turn_server}</dd></>}
                  {t.turn_protocol && t.base === 'turn' && <><dt className="text-gray-500 dark:text-gray-400">TURN Protocol</dt><dd className="text-gray-800 dark:text-gray-200">{t.turn_protocol}</dd></>}
                  {t.turn_realm && <><dt className="text-gray-500 dark:text-gray-400">TURN Realm</dt><dd className="text-gray-800 dark:text-gray-200">{t.turn_realm}</dd></>}
                  {t.turn_permissions && <><dt className="text-gray-500 dark:text-gray-400">TURN Permissions</dt><dd className="text-gray-800 dark:text-gray-200 col-span-2">{t.turn_permissions}</dd></>}
                  {t.turn_no_create_permission && <><dt className="text-gray-500 dark:text-gray-400">TURN Mode</dt><dd className="text-gray-800 dark:text-gray-200">no create_permission</dd></>}
                  {t.turn_include_wg_public_key && <><dt className="text-gray-500 dark:text-gray-400">TURN Username</dt><dd className="text-gray-800 dark:text-gray-200">includes WireGuard public key</dd></>}
                  {t.tls_cert_file && <><dt className="text-gray-500 dark:text-gray-400">Cert</dt><dd className="text-gray-800 dark:text-gray-200 col-span-2">{t.tls_cert_file}</dd></>}
                  {t.tls_ca_file && <><dt className="text-gray-500 dark:text-gray-400">CA</dt><dd className="text-gray-800 dark:text-gray-200 col-span-2">{t.tls_ca_file}</dd></>}
                  {t.tls_verify_peer && <><dt className="text-gray-500 dark:text-gray-400">TLS</dt><dd className="text-gray-800 dark:text-gray-200">verify peer</dd></>}
                  {t.proxy_server && <><dt className="text-gray-500 dark:text-gray-400">Proxy</dt><dd className="text-gray-800 dark:text-gray-200">{t.proxy_type} {t.proxy_server}</dd></>}
                  {t.connected && <><dt className="text-gray-500 dark:text-gray-400">Connected</dt><dd className="text-gray-800 dark:text-gray-200">yes</dd></>}
                  {t.carrier_protocol && <><dt className="text-gray-500 dark:text-gray-400">Carrier</dt><dd className="text-gray-800 dark:text-gray-200">{t.carrier_protocol}</dd></>}
                  {t.carrier_local_addr && <><dt className="text-gray-500 dark:text-gray-400">Local Addr</dt><dd className="text-gray-800 dark:text-gray-200 col-span-2">{t.carrier_local_addr}</dd></>}
                  {t.carrier_remote_addr && <><dt className="text-gray-500 dark:text-gray-400">Remote Addr</dt><dd className="text-gray-800 dark:text-gray-200 col-span-2">{t.carrier_remote_addr}</dd></>}
                  {t.relay_addr && <><dt className="text-gray-500 dark:text-gray-400">Relay Addr</dt><dd className="text-gray-800 dark:text-gray-200 col-span-2">{t.relay_addr}</dd></>}
                  {typeof t.active_sessions === 'number' && <><dt className="text-gray-500 dark:text-gray-400">Active Sessions</dt><dd className="text-gray-800 dark:text-gray-200">{t.active_sessions}</dd></>}
                </dl>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
