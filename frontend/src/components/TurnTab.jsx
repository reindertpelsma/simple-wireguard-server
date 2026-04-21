import { useEffect, useState } from 'react';
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
  'w-full rounded border border-gray-300 bg-white px-2 py-1 text-gray-900 placeholder-gray-400 dark:border-gray-600 dark:bg-gray-700 dark:text-gray-100 dark:placeholder-gray-500';

export default function TurnTab() {
  const [listeners, setListeners] = useState([]);
  const [status, setStatus] = useState({ sessions: [], listeners: [] });
  const [showForm, setShowForm] = useState(false);
  const [editId, setEditId] = useState(null);
  const [form, setForm] = useState(EMPTY_FORM);
  const [expanded, setExpanded] = useState({});
  const [error, setError] = useState('');

  const set = (key, value) => setForm((current) => ({ ...current, [key]: value }));

  async function loadData() {
    const [listenerData, statusData] = await Promise.all([api.getTURNListeners(), api.getTURNStatus()]);
    return {
      listeners: listenerData || [],
      status: statusData || { sessions: [], listeners: [] },
    };
  }

  function applyData(next) {
    setListeners(next.listeners);
    setStatus(next.status);
  }

  useEffect(() => {
    let cancelled = false;
    async function run() {
      try {
        const next = await loadData();
        if (!cancelled) {
          applyData(next);
        }
      } catch (err) {
        console.error(err);
      }
    }
    run();
    return () => {
      cancelled = true;
    };
  }, []);

  const handleSubmit = async (event) => {
    event.preventDefault();
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
    if (!confirm('Delete this TURN listener?')) return;
    await api.deleteTURNListener(id);
    applyData(await loadData());
  };

  const activeCount = Array.isArray(status.sessions) ? status.sessions.length : 0;

  return (
    <div className="space-y-6">
      <div className="rounded-lg border border-blue-200 bg-blue-50 px-4 py-3 text-sm text-blue-800 dark:border-blue-800 dark:bg-blue-950 dark:text-blue-200">
        Hosted TURN listeners are managed as a separate daemon. Listener changes restart that TURN process; user TURN credentials sync live where possible.
      </div>

      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <RadioTower className="h-5 w-5 text-blue-500" />
          <div>
            <h2 className="text-lg font-semibold text-gray-900 dark:text-gray-100">TURN Hosting</h2>
            <p className="text-sm text-gray-500 dark:text-gray-400">{activeCount} active TURN session{activeCount === 1 ? '' : 's'}</p>
          </div>
        </div>
        <button
          onClick={() => { setForm(EMPTY_FORM); setEditId(null); setShowForm((s) => !s); setError(''); }}
          className="flex items-center gap-1 rounded-md bg-blue-600 px-3 py-1.5 text-sm text-white hover:bg-blue-700"
        >
          <Plus className="h-4 w-4" />
          Add Listener
        </button>
      </div>

      {showForm && (
        <form onSubmit={handleSubmit} className="space-y-4 rounded-lg border border-gray-200 bg-white p-5 shadow-sm dark:border-gray-700 dark:bg-gray-800">
          <h3 className="font-semibold text-gray-800 dark:text-gray-100">{editId != null ? 'Edit TURN Listener' : 'New TURN Listener'}</h3>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <label className="flex flex-col gap-1 text-sm text-gray-700 dark:text-gray-300">
              Name
              <input className={INPUT} required value={form.name} onChange={(event) => set('name', event.target.value)} placeholder="turn-edge" />
            </label>
            <label className="flex flex-col gap-1 text-sm text-gray-700 dark:text-gray-300">
              Type
              <select className={INPUT} value={form.type} onChange={(event) => set('type', event.target.value)}>
                {['udp', 'tcp', 'tls', 'dtls', 'http', 'https', 'quic'].map((type) => <option key={type} value={type}>{type}</option>)}
              </select>
            </label>
            <label className="flex items-center gap-2 pt-6 text-sm text-gray-700 dark:text-gray-300">
              <input type="checkbox" checked={form.enabled} onChange={(event) => set('enabled', event.target.checked)} className="h-4 w-4" />
              Enabled
            </label>
          </div>

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <label className="flex flex-col gap-1 text-sm text-gray-700 dark:text-gray-300">
              Listen
              <input className={INPUT} required value={form.listen} onChange={(event) => set('listen', event.target.value)} placeholder="0.0.0.0:3478" />
            </label>
            <label className="flex flex-col gap-1 text-sm text-gray-700 dark:text-gray-300">
              Public Endpoint / URL
              <input className={INPUT} value={form.external_endpoint} onChange={(event) => set('external_endpoint', event.target.value)} placeholder="https://turn.example.com/turn or turn.example.com:3478" />
            </label>
          </div>

          {['http', 'https', 'quic'].includes(form.type) && (
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <label className="flex flex-col gap-1 text-sm text-gray-700 dark:text-gray-300">
                Path
                <input className={INPUT} value={form.path} onChange={(event) => set('path', event.target.value)} placeholder="/turn" />
              </label>
              <label className="flex items-center gap-2 pt-6 text-sm text-gray-700 dark:text-gray-300">
                <input type="checkbox" checked={form.advertise_http3} onChange={(event) => set('advertise_http3', event.target.checked)} className="h-4 w-4" />
                Advertise HTTP/3 on HTTPS responses
              </label>
            </div>
          )}

          {['tls', 'dtls', 'https', 'quic'].includes(form.type) && (
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <label className="flex flex-col gap-1 text-sm text-gray-700 dark:text-gray-300">
                Cert File
                <input className={INPUT} value={form.cert_file} onChange={(event) => set('cert_file', event.target.value)} placeholder="optional" />
              </label>
              <label className="flex flex-col gap-1 text-sm text-gray-700 dark:text-gray-300">
                Key File
                <input className={INPUT} value={form.key_file} onChange={(event) => set('key_file', event.target.value)} placeholder="optional" />
              </label>
              <label className="flex flex-col gap-1 text-sm text-gray-700 dark:text-gray-300">
                CA File
                <input className={INPUT} value={form.ca_file} onChange={(event) => set('ca_file', event.target.value)} placeholder="optional" />
              </label>
              <label className="flex items-center gap-2 pt-6 text-sm text-gray-700 dark:text-gray-300">
                <input type="checkbox" checked={form.verify_peer} onChange={(event) => set('verify_peer', event.target.checked)} className="h-4 w-4" />
                Verify Peer
              </label>
            </div>
          )}

          {error && <p className="text-sm text-red-600 dark:text-red-400">{error}</p>}
          <div className="flex gap-2">
            <button type="submit" className="rounded-md bg-blue-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-blue-700">
              {editId != null ? 'Save Changes' : 'Create Listener'}
            </button>
            <button type="button" onClick={() => { setShowForm(false); setEditId(null); setError(''); }} className="rounded-md border border-gray-300 bg-white px-4 py-1.5 text-sm font-medium text-gray-700 hover:bg-gray-50 dark:border-gray-600 dark:bg-gray-700 dark:text-gray-200 dark:hover:bg-gray-600">
              Cancel
            </button>
          </div>
        </form>
      )}

      <div className="space-y-2">
        {listeners.length === 0 ? (
          <p className="text-sm text-gray-500 dark:text-gray-400">No TURN listeners configured.</p>
        ) : listeners.map((listener) => (
          <div key={listener.id} className="rounded-lg border border-gray-200 bg-white dark:border-gray-700 dark:bg-gray-800">
            <div className="flex items-center justify-between px-4 py-3">
              <div className="flex flex-wrap items-center gap-2">
                <button onClick={() => setExpanded((current) => ({ ...current, [listener.id]: !current[listener.id] }))} className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300">
                  {expanded[listener.id] ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                </button>
                <span className="font-mono text-sm font-medium text-gray-900 dark:text-gray-100">{listener.name}</span>
                <span className="rounded-full bg-blue-100 px-2 py-0.5 text-xs font-medium text-blue-700 dark:bg-blue-900 dark:text-blue-300">{listener.type}</span>
                {listener.enabled ? (
                  <span className="rounded-full bg-green-100 px-2 py-0.5 text-xs font-medium text-green-700 dark:bg-green-900 dark:text-green-300">enabled</span>
                ) : (
                  <span className="rounded-full bg-gray-100 px-2 py-0.5 text-xs font-medium text-gray-700 dark:bg-gray-700 dark:text-gray-300">disabled</span>
                )}
                {listener.bound_addr && <span className="rounded-full bg-slate-100 px-2 py-0.5 text-xs font-medium text-slate-700 dark:bg-slate-700 dark:text-slate-200">bound {listener.bound_addr}</span>}
              </div>
              <div className="flex gap-1">
                <button onClick={() => handleEdit(listener)} className="rounded p-1 text-gray-400 hover:bg-gray-100 hover:text-blue-600 dark:hover:bg-gray-700 dark:hover:text-blue-400">
                  <Edit3 className="h-4 w-4" />
                </button>
                <button onClick={() => handleDelete(listener.id)} className="rounded p-1 text-gray-400 hover:bg-gray-100 hover:text-red-600 dark:hover:bg-gray-700 dark:hover:text-red-400">
                  <Trash2 className="h-4 w-4" />
                </button>
              </div>
            </div>

            {expanded[listener.id] && (
              <dl className="grid grid-cols-2 gap-x-4 gap-y-1 border-t border-gray-100 px-4 py-3 text-xs dark:border-gray-700 sm:grid-cols-3">
                <dt className="text-gray-500 dark:text-gray-400">Listen</dt><dd className="text-gray-800 dark:text-gray-200 col-span-2">{listener.listen}</dd>
                {listener.external_endpoint && <><dt className="text-gray-500 dark:text-gray-400">Public endpoint</dt><dd className="text-gray-800 dark:text-gray-200 col-span-2">{listener.external_endpoint}</dd></>}
                {listener.path && <><dt className="text-gray-500 dark:text-gray-400">Path</dt><dd className="text-gray-800 dark:text-gray-200">{listener.path}</dd></>}
                {listener.advertise_http3 && <><dt className="text-gray-500 dark:text-gray-400">HTTP/3</dt><dd className="text-gray-800 dark:text-gray-200">advertised</dd></>}
                {listener.cert_file && <><dt className="text-gray-500 dark:text-gray-400">Cert</dt><dd className="text-gray-800 dark:text-gray-200 col-span-2">{listener.cert_file}</dd></>}
                {listener.ca_file && <><dt className="text-gray-500 dark:text-gray-400">CA</dt><dd className="text-gray-800 dark:text-gray-200 col-span-2">{listener.ca_file}</dd></>}
              </dl>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
