import { useEffect, useState } from 'react';
import { ChevronDown, ChevronUp, Edit3, Plus, Radio, Trash2 } from 'lucide-react';
import { api } from '../lib/api';

const BASE_OPTIONS = ['udp', 'tcp', 'tls', 'dtls', 'http', 'https', 'quic', 'quic-ws', 'url'];
const PROXY_TYPES = ['', 'none', 'socks5', 'http', 'turn'];

const EMPTY_FORM = {
  name: '',
  base: 'tcp',
  listen: false,
  url: '',
  ws_path: '',
  connect_host: '',
  host_header: '',
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

function needsTLS(base) {
  return ['tls', 'dtls', 'https', 'quic', 'quic-ws', 'url'].includes(base);
}

function needsWebSocket(base) {
  return ['http', 'https', 'quic', 'quic-ws', 'url'].includes(base);
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
      setTransports(data || []);
    } catch (err) {
      console.error(err);
    }
  }

  useEffect(() => {
    fetchTransports();
  }, []);

  const handleField = (key, value) => setForm((f) => ({ ...f, [key]: value }));

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    try {
      const payload = { ...form };
      if (editId != null) {
        await api.updateTransport(editId, payload);
      } else {
        await api.createTransport(payload);
      }
      setForm(EMPTY_FORM);
      setShowForm(false);
      setEditId(null);
      fetchTransports();
    } catch (err) {
      setError(err.message);
    }
  };

  const handleEdit = (t) => {
    setForm({
      name: t.name,
      base: t.base,
      listen: t.listen ?? false,
      url: t.url ?? '',
      ws_path: t.ws_path ?? '',
      connect_host: t.connect_host ?? '',
      host_header: t.host_header ?? '',
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
      fetchTransports();
    } catch (err) {
      alert(err.message);
    }
  };

  const toggleExpand = (id) => setExpanded((e) => ({ ...e, [id]: !e[id] }));

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Radio className="h-5 w-5 text-blue-500" />
          <h2 className="text-lg font-semibold">Transports</h2>
        </div>
        <button
          onClick={() => { setForm(EMPTY_FORM); setEditId(null); setShowForm((s) => !s); }}
          className="flex items-center gap-1 rounded-md bg-blue-600 px-3 py-1.5 text-sm text-white hover:bg-blue-700"
        >
          <Plus className="h-4 w-4" />
          Add Transport
        </button>
      </div>

      {showForm && (
        <form onSubmit={handleSubmit} className="rounded-lg border border-gray-200 bg-gray-50 p-4 dark:border-gray-700 dark:bg-gray-800 space-y-4">
          <h3 className="font-medium text-sm">{editId != null ? 'Edit Transport' : 'New Transport'}</h3>

          <div className="grid grid-cols-2 gap-3">
            <label className="col-span-2 flex flex-col gap-1 text-sm">
              Name
              <input
                className="rounded border border-gray-300 px-2 py-1 dark:border-gray-600 dark:bg-gray-700"
                required
                value={form.name}
                onChange={(e) => handleField('name', e.target.value)}
                placeholder="e.g. ws-server"
              />
            </label>

            <label className="flex flex-col gap-1 text-sm">
              Base Protocol
              <select
                className="rounded border border-gray-300 px-2 py-1 dark:border-gray-600 dark:bg-gray-700"
                value={form.base}
                onChange={(e) => handleField('base', e.target.value)}
              >
                {BASE_OPTIONS.map((b) => <option key={b} value={b}>{b}</option>)}
              </select>
            </label>

            <label className="flex items-center gap-2 text-sm mt-5">
              <input type="checkbox" checked={form.listen} onChange={(e) => handleField('listen', e.target.checked)} />
              Enable Listener
            </label>
          </div>

          {form.base === 'url' && (
            <label className="flex flex-col gap-1 text-sm">
              URL (e.g. https://example.com/wg)
              <input
                className="rounded border border-gray-300 px-2 py-1 dark:border-gray-600 dark:bg-gray-700"
                value={form.url}
                onChange={(e) => handleField('url', e.target.value)}
                placeholder="https://vpn.example.com/wg"
              />
            </label>
          )}

          {needsWebSocket(form.base) && (
            <div className="grid grid-cols-3 gap-3">
              <label className="flex flex-col gap-1 text-sm">
                WS Path
                <input className="rounded border border-gray-300 px-2 py-1 dark:border-gray-600 dark:bg-gray-700" value={form.ws_path} onChange={(e) => handleField('ws_path', e.target.value)} placeholder="/" />
              </label>
              <label className="flex flex-col gap-1 text-sm">
                Connect Host
                <input className="rounded border border-gray-300 px-2 py-1 dark:border-gray-600 dark:bg-gray-700" value={form.connect_host} onChange={(e) => handleField('connect_host', e.target.value)} placeholder="(domain fronting outer)" />
              </label>
              <label className="flex flex-col gap-1 text-sm">
                Host Header
                <input className="rounded border border-gray-300 px-2 py-1 dark:border-gray-600 dark:bg-gray-700" value={form.host_header} onChange={(e) => handleField('host_header', e.target.value)} placeholder="(domain fronting inner)" />
              </label>
            </div>
          )}

          {needsTLS(form.base) && (
            <details className="text-sm">
              <summary className="cursor-pointer text-gray-500 hover:text-gray-700 dark:text-gray-400">TLS Settings</summary>
              <div className="mt-2 grid grid-cols-2 gap-3">
                <label className="flex flex-col gap-1">
                  Cert File
                  <input className="rounded border border-gray-300 px-2 py-1 dark:border-gray-600 dark:bg-gray-700" value={form.tls_cert_file} onChange={(e) => handleField('tls_cert_file', e.target.value)} placeholder="/path/to/cert.pem" />
                </label>
                <label className="flex flex-col gap-1">
                  Key File
                  <input className="rounded border border-gray-300 px-2 py-1 dark:border-gray-600 dark:bg-gray-700" value={form.tls_key_file} onChange={(e) => handleField('tls_key_file', e.target.value)} placeholder="/path/to/key.pem" />
                </label>
                <label className="flex flex-col gap-1">
                  CA File
                  <input className="rounded border border-gray-300 px-2 py-1 dark:border-gray-600 dark:bg-gray-700" value={form.tls_ca_file} onChange={(e) => handleField('tls_ca_file', e.target.value)} placeholder="/path/to/ca.pem" />
                </label>
                <label className="flex flex-col gap-1">
                  Server SNI
                  <input className="rounded border border-gray-300 px-2 py-1 dark:border-gray-600 dark:bg-gray-700" value={form.tls_server_sni} onChange={(e) => handleField('tls_server_sni', e.target.value)} placeholder="(override SNI)" />
                </label>
                <label className="col-span-2 flex items-center gap-2">
                  <input type="checkbox" checked={form.tls_verify_peer} onChange={(e) => handleField('tls_verify_peer', e.target.checked)} />
                  Verify Peer Certificate
                </label>
              </div>
            </details>
          )}

          <details className="text-sm">
            <summary className="cursor-pointer text-gray-500 hover:text-gray-700 dark:text-gray-400">Proxy Settings</summary>
            <div className="mt-2 grid grid-cols-2 gap-3">
              <label className="flex flex-col gap-1">
                Proxy Type
                <select className="rounded border border-gray-300 px-2 py-1 dark:border-gray-600 dark:bg-gray-700" value={form.proxy_type} onChange={(e) => handleField('proxy_type', e.target.value)}>
                  {PROXY_TYPES.map((p) => <option key={p} value={p}>{p || 'none'}</option>)}
                </select>
              </label>
              {form.proxy_type && form.proxy_type !== 'none' && (
                <>
                  <label className="flex flex-col gap-1">
                    Proxy Server
                    <input className="rounded border border-gray-300 px-2 py-1 dark:border-gray-600 dark:bg-gray-700" value={form.proxy_server} onChange={(e) => handleField('proxy_server', e.target.value)} placeholder="host:port" />
                  </label>
                  <label className="flex flex-col gap-1">
                    Username
                    <input className="rounded border border-gray-300 px-2 py-1 dark:border-gray-600 dark:bg-gray-700" value={form.proxy_username} onChange={(e) => handleField('proxy_username', e.target.value)} />
                  </label>
                  <label className="flex flex-col gap-1">
                    Password
                    <input type="password" className="rounded border border-gray-300 px-2 py-1 dark:border-gray-600 dark:bg-gray-700" value={form.proxy_password} onChange={(e) => handleField('proxy_password', e.target.value)} />
                  </label>
                </>
              )}
            </div>
          </details>

          {error && <p className="text-red-500 text-sm">{error}</p>}

          <div className="flex gap-2">
            <button type="submit" className="rounded-md bg-blue-600 px-3 py-1.5 text-sm text-white hover:bg-blue-700">
              {editId != null ? 'Save Changes' : 'Create Transport'}
            </button>
            <button type="button" onClick={() => { setShowForm(false); setEditId(null); }} className="rounded-md border border-gray-300 px-3 py-1.5 text-sm hover:bg-gray-100 dark:border-gray-600 dark:hover:bg-gray-700">
              Cancel
            </button>
          </div>
        </form>
      )}

      {transports.length === 0 ? (
        <p className="text-sm text-gray-500 dark:text-gray-400">No transports configured. Add one above.</p>
      ) : (
        <div className="space-y-2">
          {transports.map((t) => (
            <div key={t.id} className="rounded-lg border border-gray-200 dark:border-gray-700">
              <div className="flex items-center justify-between px-4 py-3">
                <div className="flex items-center gap-3">
                  <button onClick={() => toggleExpand(t.id)} className="text-gray-400 hover:text-gray-600">
                    {expanded[t.id] ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                  </button>
                  <span className="font-mono text-sm font-medium">{t.name}</span>
                  <span className="rounded-full bg-blue-100 px-2 py-0.5 text-xs text-blue-700 dark:bg-blue-900 dark:text-blue-300">{t.base}</span>
                  {t.listen && <span className="rounded-full bg-green-100 px-2 py-0.5 text-xs text-green-700 dark:bg-green-900 dark:text-green-300">listener</span>}
                  {t.proxy_type && t.proxy_type !== 'none' && (
                    <span className="rounded-full bg-yellow-100 px-2 py-0.5 text-xs text-yellow-700 dark:bg-yellow-900 dark:text-yellow-300">via {t.proxy_type}</span>
                  )}
                </div>
                <div className="flex gap-2">
                  <button onClick={() => handleEdit(t)} className="p-1 text-gray-400 hover:text-blue-500">
                    <Edit3 className="h-4 w-4" />
                  </button>
                  <button onClick={() => handleDelete(t.id)} className="p-1 text-gray-400 hover:text-red-500">
                    <Trash2 className="h-4 w-4" />
                  </button>
                </div>
              </div>

              {expanded[t.id] && (
                <div className="border-t border-gray-100 px-4 py-3 text-xs text-gray-500 dark:border-gray-700 dark:text-gray-400 space-y-1">
                  {t.url && <div><span className="font-medium">URL:</span> {t.url}</div>}
                  {t.ws_path && <div><span className="font-medium">Path:</span> {t.ws_path}</div>}
                  {t.connect_host && <div><span className="font-medium">Connect Host:</span> {t.connect_host}</div>}
                  {t.host_header && <div><span className="font-medium">Host Header:</span> {t.host_header}</div>}
                  {t.tls_cert_file && <div><span className="font-medium">Cert:</span> {t.tls_cert_file}</div>}
                  {t.tls_verify_peer && <div><span className="font-medium">TLS:</span> verify peer</div>}
                  {t.proxy_server && <div><span className="font-medium">Proxy:</span> {t.proxy_type} {t.proxy_server}</div>}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
