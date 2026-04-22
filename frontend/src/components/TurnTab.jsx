import { useCallback, useEffect, useState } from 'react';
import { ChevronDown, ChevronUp, Edit3, Plus, RadioTower, Trash2 } from 'lucide-react';
import { api } from '../lib/api';

const EMPTY_FORM = {
  name: '',
  type: 'udp',
  listen: '',
  external_endpoint: '',
  path: '',
  advertise_http3: false,
  cert_file: '',
  key_file: '',
  ca_file: '',
  verify_peer: false,
  enabled: true,
};

const INPUT =
  'w-full rounded border border-[var(--border)] bg-[var(--input)] px-2 py-1 text-[var(--text)] placeholder:text-[var(--muted)]';
const LABEL = 'flex flex-col gap-1 text-sm text-[var(--text)]';
const CHECKBOX_LABEL = 'flex items-center gap-2 pt-6 text-sm text-[var(--text)]';

export default function TurnTab({ isAdmin = false, sudoActive = false, onRequireSudo = () => {} }) {
  const [listeners, setListeners] = useState([]);
  const [status, setStatus] = useState({ sessions: [], listeners: [] });
  const [credentials, setCredentials] = useState([]);
  const [createdCredential, setCreatedCredential] = useState(null);
  const [turnForm, setTurnForm] = useState({ name: 'TURN relay', wireguard_public_key: '' });
  const [publicConfig, setPublicConfig] = useState({});
  const [showForm, setShowForm] = useState(false);
  const [editId, setEditId] = useState(null);
  const [form, setForm] = useState(EMPTY_FORM);
  const [expanded, setExpanded] = useState({});
  const [error, setError] = useState('');

  const set = (key, value) => setForm((current) => ({ ...current, [key]: value }));

  const loadData = useCallback(async () => {
    const [listenerData, statusData, cfg, credentialData] = await Promise.all([
      isAdmin ? api.getTURNListeners() : api.getVisibleTURNListeners(),
      isAdmin ? api.getTURNStatus() : Promise.resolve({ sessions: [], listeners: [] }),
      api.getPublicConfig(),
      isAdmin ? api.getAdminTURNCredentials() : api.getMyTURNCredentials().catch(() => []),
    ]);
    return {
      listeners: listenerData || [],
      status: statusData || { sessions: [], listeners: [] },
      publicConfig: cfg || {},
      credentials: credentialData || [],
    };
  }, [isAdmin]);

  function applyData(next) {
    setListeners(next.listeners);
    setStatus(next.status);
    setPublicConfig(next.publicConfig || {});
    setCredentials(next.credentials || []);
  }

  useEffect(() => {
    let cancelled = false;
    async function run() {
      try {
        const next = await loadData();
        if (!cancelled) {
          applyData(next);
          setError('');
        }
      } catch (err) {
        if (!cancelled) {
          setError(err.message || 'Failed to load TURN data');
        }
      }
    }
    run();
    return () => {
      cancelled = true;
    };
  }, [loadData]);

  const handleSubmit = async (event) => {
    event.preventDefault();
    if (!sudoActive) return onRequireSudo();
    setError('');
    try {
      if (editId != null) {
        await api.updateTURNListener(editId, form);
      } else {
        await api.createTURNListener(form);
      }
      setForm(EMPTY_FORM);
      setShowForm(false);
      setEditId(null);
      applyData(await loadData());
    } catch (err) {
      setError(err.message);
    }
  };

  const handleEdit = (listener) => {
    setForm({
      name: listener.name ?? '',
      type: listener.type ?? 'udp',
      listen: listener.listen ?? '',
      external_endpoint: listener.external_endpoint ?? '',
      path: listener.path ?? '',
      advertise_http3: listener.advertise_http3 ?? false,
      cert_file: listener.cert_file ?? '',
      key_file: listener.key_file ?? '',
      ca_file: listener.ca_file ?? '',
      verify_peer: listener.verify_peer ?? false,
      enabled: listener.enabled ?? true,
    });
    setEditId(listener.id);
    setShowForm(true);
  };

  const handleDelete = async (id) => {
    if (!sudoActive) return onRequireSudo();
    if (!confirm('Delete this TURN listener?')) return;
    try {
      await api.deleteTURNListener(id);
      applyData(await loadData());
      setError('');
    } catch (err) {
      setError(err.message || 'Failed to delete TURN listener');
    }
  };

  const handleCreateCredential = async () => {
    if (!sudoActive) return onRequireSudo();
    setError('');
    try {
      const created = await api.createMyTURNCredential(turnForm);
      setCreatedCredential(created);
      applyData(await loadData());
    } catch (err) {
      setError(err.message);
    }
  };

  const handleDeleteCredential = async (id) => {
    if (!sudoActive) return onRequireSudo();
    if (!confirm('Delete this TURN credential?')) return;
    try {
      await api.deleteMyTURNCredential(id);
      applyData(await loadData());
      setError('');
    } catch (err) {
      setError(err.message);
    }
  };

  const activeCount = Array.isArray(status.sessions) ? status.sessions.length : 0;
  const turnSelfService = publicConfig.turn_allow_user_credentials === 'true';
  const canCreateOwnCredential = isAdmin || turnSelfService;

  return (
    <div className="space-y-6">
      <div className="rounded-3xl border border-[var(--border)] bg-[var(--surface-soft)] px-4 py-3 text-sm text-[var(--text)]">
        Hosted TURN listeners are managed as a separate daemon. Listener changes restart that TURN process; user TURN credentials sync live where possible.
      </div>
      {error ? <div className="error-banner">{error}</div> : null}

      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <RadioTower className="h-5 w-5 text-[var(--accent)]" />
          <div>
            <h2 className="text-lg font-semibold text-[var(--text)]">TURN Hosting</h2>
            <p className="text-sm text-[var(--muted)]">{activeCount} active TURN session{activeCount === 1 ? '' : 's'}</p>
          </div>
        </div>
        {isAdmin ? (
          <button
            onClick={() => { setForm(EMPTY_FORM); setEditId(null); setShowForm((s) => !s); setError(''); }}
            className="primary-button"
          >
            <Plus className="h-4 w-4" />
            Add Listener
          </button>
        ) : null}
      </div>

      {showForm && isAdmin && (
        <form onSubmit={handleSubmit} className="space-y-4 rounded-3xl border border-[var(--border)] bg-[var(--panel-strong)] p-5 shadow-sm">
          <h3 className="font-semibold text-[var(--text)]">{editId != null ? 'Edit TURN Listener' : 'New TURN Listener'}</h3>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <label className={LABEL}>
              Name
              <input className={INPUT} required value={form.name} onChange={(event) => set('name', event.target.value)} placeholder="turn-edge" />
            </label>
            <label className={LABEL}>
              Type
              <select className={INPUT} value={form.type} onChange={(event) => set('type', event.target.value)}>
                {['udp', 'tcp', 'tls', 'dtls', 'http', 'https', 'quic'].map((type) => <option key={type} value={type}>{type}</option>)}
              </select>
            </label>
            <label className={CHECKBOX_LABEL}>
              <input type="checkbox" checked={form.enabled} onChange={(event) => set('enabled', event.target.checked)} className="h-4 w-4" />
              Enabled
            </label>
          </div>

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <label className={LABEL}>
              Listen
              <input className={INPUT} required value={form.listen} onChange={(event) => set('listen', event.target.value)} placeholder="0.0.0.0:3478" />
            </label>
            <label className={LABEL}>
              Public Endpoint / URL
              <input className={INPUT} value={form.external_endpoint} onChange={(event) => set('external_endpoint', event.target.value)} placeholder="https://turn.example.com/turn or turn.example.com:3478" />
            </label>
          </div>

          {['http', 'https', 'quic'].includes(form.type) && (
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <label className={LABEL}>
                Path
                <input className={INPUT} value={form.path} onChange={(event) => set('path', event.target.value)} placeholder="/turn" />
              </label>
              <label className={CHECKBOX_LABEL}>
                <input type="checkbox" checked={form.advertise_http3} onChange={(event) => set('advertise_http3', event.target.checked)} className="h-4 w-4" />
                Advertise HTTP/3 on HTTPS responses
              </label>
            </div>
          )}

          {['tls', 'dtls', 'https', 'quic'].includes(form.type) && (
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <label className={LABEL}>
                Cert File
                <input className={INPUT} value={form.cert_file} onChange={(event) => set('cert_file', event.target.value)} placeholder="optional" />
              </label>
              <label className={LABEL}>
                Key File
                <input className={INPUT} value={form.key_file} onChange={(event) => set('key_file', event.target.value)} placeholder="optional" />
              </label>
              <label className={LABEL}>
                CA File
                <input className={INPUT} value={form.ca_file} onChange={(event) => set('ca_file', event.target.value)} placeholder="optional" />
              </label>
              <label className={CHECKBOX_LABEL}>
                <input type="checkbox" checked={form.verify_peer} onChange={(event) => set('verify_peer', event.target.checked)} className="h-4 w-4" />
                Verify Peer
              </label>
            </div>
          )}

          {error && <p className="text-sm text-[var(--danger)]">{error}</p>}
          <div className="flex gap-2">
            <button type="submit" className="primary-button">
              {editId != null ? 'Save Changes' : 'Create Listener'}
            </button>
            <button type="button" onClick={() => { setShowForm(false); setEditId(null); setError(''); }} className="ghost-button">
              Cancel
            </button>
          </div>
        </form>
      )}

      <div className="space-y-2">
        {listeners.length === 0 ? (
          <p className="text-sm text-[var(--muted)]">No TURN listeners configured.</p>
        ) : listeners.map((listener) => (
          <div key={listener.id} className="rounded-3xl border border-[var(--border)] bg-[var(--panel-strong)]">
            <div className="flex items-center justify-between px-4 py-3">
              <div className="flex flex-wrap items-center gap-2">
                <button onClick={() => setExpanded((current) => ({ ...current, [listener.id]: !current[listener.id] }))} className="ghost-button">
                  {expanded[listener.id] ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                </button>
                <span className="font-mono text-sm font-medium text-[var(--text)]">{listener.name}</span>
                <span className="status-chip">{listener.type}</span>
                {listener.enabled ? (
                  <span className="status-chip">enabled</span>
                ) : (
                  <span className="status-chip status-chip-muted">disabled</span>
                )}
                {listener.bound_addr && <span className="status-chip status-chip-muted">bound {listener.bound_addr}</span>}
              </div>
              {isAdmin ? (
                <div className="flex gap-1">
                  <button onClick={() => handleEdit(listener)} className="ghost-button">
                    <Edit3 className="h-4 w-4" />
                  </button>
                  <button onClick={() => handleDelete(listener.id)} className="ghost-button ghost-button-danger">
                    <Trash2 className="h-4 w-4" />
                  </button>
                </div>
              ) : null}
            </div>

            {expanded[listener.id] && (
              <dl className="grid grid-cols-2 gap-x-4 gap-y-1 border-t border-[var(--border)] px-4 py-3 text-xs sm:grid-cols-3">
                <dt className="text-[var(--muted)]">Listen</dt><dd className="col-span-2 text-[var(--text)]">{listener.listen}</dd>
                {listener.external_endpoint && <><dt className="text-[var(--muted)]">Public endpoint</dt><dd className="col-span-2 text-[var(--text)]">{listener.external_endpoint}</dd></>}
                {listener.path && <><dt className="text-[var(--muted)]">Path</dt><dd className="text-[var(--text)]">{listener.path}</dd></>}
                {listener.advertise_http3 && <><dt className="text-[var(--muted)]">HTTP/3</dt><dd className="text-[var(--text)]">advertised</dd></>}
                {listener.cert_file && <><dt className="text-[var(--muted)]">Cert</dt><dd className="col-span-2 text-[var(--text)]">{listener.cert_file}</dd></>}
                {listener.ca_file && <><dt className="text-[var(--muted)]">CA</dt><dd className="col-span-2 text-[var(--text)]">{listener.ca_file}</dd></>}
              </dl>
            )}
          </div>
        ))}
      </div>

      <section className="panel p-6">
        <div className="mb-4 flex items-center gap-3">
          <div className="brand-badge"><RadioTower size={18} /></div>
          <div>
            <span className="eyebrow">TURN Credentials</span>
            <h3 className="text-xl font-black tracking-tight">{isAdmin ? 'All TURN credentials' : 'Your TURN credentials'}</h3>
          </div>
        </div>
        {createdCredential ? (
          <div className="success-panel mb-4">
            <p className="mb-2 text-sm font-semibold">TURN credential created — save the password now, it won’t be shown again.</p>
            <p className="font-mono text-sm"><span className="text-[var(--muted)]">Username:</span> {createdCredential.username}</p>
            <p className="font-mono text-sm"><span className="text-[var(--muted)]">Password:</span> {createdCredential.password}</p>
          </div>
        ) : null}
        <div className="space-y-3">
          {credentials.length === 0 ? (
            <p className="text-sm text-[var(--muted)]">No TURN credentials available.</p>
          ) : credentials.map((cred) => (
            <div key={cred.id} className="card p-4">
              <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                <div className="space-y-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-sm font-semibold">{cred.username}</span>
                    {cred.connected ? <span className="status-chip">connected</span> : <span className="status-chip status-chip-muted">idle</span>}
                  </div>
                  {isAdmin && cred.owner_username ? <p className="text-xs text-[var(--muted)]">Owner: {cred.owner_username}</p> : null}
                  <p className="text-xs text-[var(--muted)]">{cred.name} · port {cred.port}</p>
                  {Array.isArray(cred.profiles) ? cred.profiles.map((profile) => (
                    <p key={profile.url} className="break-all font-mono text-xs"><span className="text-[var(--muted)]">{profile.label}:</span> {profile.url}</p>
                  )) : null}
                </div>
                {!isAdmin ? (
                  <button type="button" onClick={() => handleDeleteCredential(cred.id)} className="ghost-button ghost-button-danger">Delete</button>
                ) : null}
              </div>
            </div>
          ))}
        </div>
        {canCreateOwnCredential ? (
          <div className="mt-4 rounded-2xl border border-[var(--border)] bg-[var(--surface-soft)] p-4">
            <div className="space-y-3">
              <div>
                <h4 className="text-base font-semibold text-[var(--text)]">Create your TURN credential</h4>
                <p className="text-sm text-[var(--muted)]">This creates a credential for the currently signed-in account.</p>
              </div>
              <div className="grid gap-3 md:grid-cols-2">
                <div className="space-y-1.5">
                  <label className="field-label">Credential name</label>
                  <input className="input-field" value={turnForm.name} onChange={(event) => setTurnForm({ ...turnForm, name: event.target.value })} />
                </div>
                <div className="space-y-1.5">
                  <label className="field-label">Optional WireGuard public key</label>
                  <input className="input-field font-mono text-sm" value={turnForm.wireguard_public_key} onChange={(event) => setTurnForm({ ...turnForm, wireguard_public_key: event.target.value })} />
                </div>
              </div>
              <button type="button" onClick={handleCreateCredential} className="primary-button">
                <Plus size={16} />
                <span>Create TURN credential</span>
              </button>
            </div>
          </div>
        ) : (
          <div className="mt-4 rounded-2xl border border-[var(--border)] bg-[var(--surface-soft)] p-4">
            <p className="text-sm text-[var(--muted)]">TURN self-service is disabled by the administrator.</p>
          </div>
        )}
      </section>
    </div>
  );
}
