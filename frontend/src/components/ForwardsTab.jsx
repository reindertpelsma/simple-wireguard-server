import { useEffect, useState } from 'react';
import { ArrowLeftRight, Plus, Trash2 } from 'lucide-react';
import { api } from '../lib/api';

const EMPTY_FORWARD = {
  name: '',
  reverse: false,
  proto: 'tcp',
  listen: '',
  target: '',
  proxy_protocol: '',
};

function ForwardForm({ initial, onSave, onCancel }) {
  const [form, setForm] = useState(initial ? { ...initial } : { ...EMPTY_FORWARD });

  const handleSubmit = (e) => {
    e.preventDefault();
    onSave(form);
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4 rounded-2xl border border-[var(--border)] bg-[var(--surface-soft)] p-4">
      <div className="grid gap-4 md:grid-cols-2">
        <div className="space-y-1.5">
          <label className="field-label">Name <span className="normal-case font-normal text-[var(--muted)]">(optional)</span></label>
          <input className="input-field" placeholder="My forward" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} />
        </div>
        <div className="space-y-1.5">
          <label className="field-label">Direction</label>
          <select className="select-field" value={form.reverse ? 'reverse' : 'forward'} onChange={e => setForm({ ...form, reverse: e.target.value === 'reverse' })}>
            <option value="forward">Forward — host-side listener → WireGuard target</option>
            <option value="reverse">Reverse — WireGuard-side listener → host target</option>
          </select>
        </div>
        <div className="space-y-1.5">
          <label className="field-label">Protocol</label>
          <select className="select-field" value={form.proto} onChange={e => setForm({ ...form, proto: e.target.value })}>
            <option value="tcp">TCP</option>
            <option value="udp">UDP</option>
          </select>
        </div>
        <div className="space-y-1.5">
          <label className="field-label">
            {form.reverse ? 'WireGuard listen address' : 'Host listen address'}
          </label>
          <input
            className="input-field font-mono text-sm"
            required
            placeholder={form.reverse ? '100.64.0.99:8443' : '127.0.0.1:15432'}
            value={form.listen}
            onChange={e => setForm({ ...form, listen: e.target.value })}
          />
        </div>
        <div className="space-y-1.5">
          <label className="field-label">
            {form.reverse ? 'Host target address' : 'WireGuard target address'}
          </label>
          <input
            className="input-field font-mono text-sm"
            required
            placeholder={form.reverse ? '127.0.0.1:443' : '10.10.0.20:5432'}
            value={form.target}
            onChange={e => setForm({ ...form, target: e.target.value })}
          />
        </div>
        <div className="space-y-1.5">
          <label className="field-label">
            PROXY protocol <span className="normal-case font-normal text-[var(--muted)]">(optional)</span>
          </label>
          <select className="select-field" value={form.proxy_protocol} onChange={e => setForm({ ...form, proxy_protocol: e.target.value })}>
            <option value="">None</option>
            <option value="v1">v1</option>
            <option value="v2">v2</option>
          </select>
        </div>
      </div>
      <div className="rounded-2xl border border-[var(--border)] bg-[var(--surface)] p-3 text-xs text-[var(--muted)] space-y-1">
        {form.reverse
          ? <>
              <p><strong>Reverse forward:</strong> binds to a WireGuard-routed IP so peers can reach your host service.</p>
              <p>Listen on a tunnel IP like <code>100.64.0.99:8443</code>, forward to a host address like <code>127.0.0.1:443</code>.</p>
            </>
          : <>
              <p><strong>Forward:</strong> binds on the host so local apps can reach a peer over WireGuard.</p>
              <p>Listen on <code>127.0.0.1:15432</code>, forward to a WireGuard-routed address like <code>10.10.0.20:5432</code>.</p>
            </>
        }
      </div>
      <div className="flex justify-end gap-2">
        {onCancel && <button type="button" onClick={onCancel} className="ghost-button">Cancel</button>}
        <button type="submit" className="primary-button">
          <Plus size={15} />
          <span>{initial ? 'Save changes' : 'Add forward'}</span>
        </button>
      </div>
    </form>
  );
}

export default function ForwardsTab() {
  const [forwards, setForwards] = useState([]);
  const [showForm, setShowForm] = useState(false);
  const [editingId, setEditingId] = useState(null);

  async function fetchForwards() {
    try {
      setForwards(await api.getForwards());
    } catch (err) {
      console.error(err);
    }
  }

  useEffect(() => { fetchForwards(); }, []);

  const handleCreate = async (data) => {
    try {
      await api.createForward(data);
      setShowForm(false);
      await fetchForwards();
    } catch (err) {
      alert(err.message);
    }
  };

  const handleUpdate = async (data) => {
    try {
      await api.updateForward(data.id, data);
      setEditingId(null);
      await fetchForwards();
    } catch (err) {
      alert(err.message);
    }
  };

  const handleDelete = async (id) => {
    if (!confirm('Delete this forward? The daemon will restart.')) return;
    try {
      await api.deleteForward(id);
      await fetchForwards();
    } catch (err) {
      alert(err.message);
    }
  };

  const localForwards = forwards.filter(f => !f.reverse);
  const reverseForwards = forwards.filter(f => f.reverse);

  const ForwardRow = ({ fwd }) => (
    editingId === fwd.id
      ? <ForwardForm initial={fwd} onSave={handleUpdate} onCancel={() => setEditingId(null)} />
      : (
        <div className="flex items-center gap-3 rounded-2xl border border-[var(--border)] bg-[var(--surface)] p-4">
          <div className="flex-1 grid gap-0.5">
            <div className="flex items-center gap-2">
              {fwd.name && <span className="font-semibold">{fwd.name}</span>}
              <span className="rounded-full bg-[var(--surface-soft)] px-2 py-0.5 font-mono text-xs uppercase">{fwd.proto}</span>
              {fwd.proxy_protocol && <span className="rounded-full bg-amber-100 text-amber-800 dark:bg-amber-900 dark:text-amber-200 px-2 py-0.5 text-xs">PROXY {fwd.proxy_protocol}</span>}
            </div>
            <div className="flex items-center gap-2 font-mono text-sm text-[var(--muted)]">
              <span>{fwd.listen}</span>
              <ArrowLeftRight size={13} />
              <span>{fwd.target}</span>
            </div>
          </div>
          <div className="flex gap-1">
            <button type="button" onClick={() => setEditingId(fwd.id)} className="ghost-button text-xs">Edit</button>
            <button type="button" onClick={() => handleDelete(fwd.id)} className="ghost-button ghost-button-danger">
              <Trash2 size={14} />
            </button>
          </div>
        </div>
      )
  );

  return (
    <div className="space-y-6">
      <div className="rounded-3xl border border-[var(--border)] bg-[var(--surface-soft)] px-4 py-3 text-sm text-[var(--muted)]">
        Forward changes require a <strong>daemon restart</strong> to take effect. The daemon restarts automatically when a forward is added, changed, or removed.
      </div>

      {localForwards.length > 0 && (
        <section className="space-y-2">
          <h3 className="text-lg font-bold tracking-tight">Local Forwards <span className="text-sm font-normal text-[var(--muted)]">— host-side listener → WireGuard target</span></h3>
          {localForwards.map(f => <ForwardRow key={f.id} fwd={f} />)}
        </section>
      )}

      {reverseForwards.length > 0 && (
        <section className="space-y-2">
          <h3 className="text-lg font-bold tracking-tight">Reverse Forwards <span className="text-sm font-normal text-[var(--muted)]">— WireGuard-side listener → host target</span></h3>
          {reverseForwards.map(f => <ForwardRow key={f.id} fwd={f} />)}
        </section>
      )}

      {forwards.length === 0 && !showForm && (
        <div className="state-shell py-12 text-[var(--muted)]">No forwards configured</div>
      )}

      {showForm && (
        <ForwardForm onSave={handleCreate} onCancel={() => setShowForm(false)} />
      )}

      {!showForm && (
        <button type="button" onClick={() => setShowForm(true)} className="primary-button">
          <Plus size={16} /><span>Add forward</span>
        </button>
      )}
    </div>
  );
}
