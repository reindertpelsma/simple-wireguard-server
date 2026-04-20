import { useEffect, useState } from 'react';
import { Plus, ShieldAlert, Trash2 } from 'lucide-react';
import { api } from '../lib/api';

export default function ACLsTab() {
  const [acls, setACLs] = useState([]);
  const [defaults, setDefaults] = useState({
    inbound: 'allow',
    outbound: 'allow',
    relay: 'deny',
  });
  const [newACL, setNewACL] = useState({
    list_name: 'relay',
    action: 'allow',
    src: '',
    dst: '',
    proto: '',
    dport: '',
    priority: 0,
  });

  async function fetchACLs() {
    try {
      const data = await api.getACLs();
      setACLs(data);
      const config = await api.getAdminConfig();
      setDefaults({
        inbound: config.acl_inbound_default || 'allow',
        outbound: config.acl_outbound_default || 'allow',
        relay: config.acl_relay_default || 'deny',
      });
    } catch (err) {
      console.error(err);
    }
  }

  useEffect(() => {
    let cancelled = false;

    async function loadACLs() {
      try {
        const data = await api.getACLs();
        const config = await api.getAdminConfig();
        if (!cancelled) {
          setACLs(data);
          setDefaults({
            inbound: config.acl_inbound_default || 'allow',
            outbound: config.acl_outbound_default || 'allow',
            relay: config.acl_relay_default || 'deny',
          });
        }
      } catch (err) {
        console.error(err);
      }
    }

    loadACLs();
    return () => {
      cancelled = true;
    };
  }, []);

  const handleCreate = async (event) => {
    event.preventDefault();
    try {
      await api.createACL({ ...newACL, priority: Number.parseInt(newACL.priority, 10) || 0 });
      setNewACL({ list_name: 'relay', action: 'allow', src: '', dst: '', proto: '', dport: '', priority: 0 });
      fetchACLs();
    } catch (err) {
      alert(err.message);
    }
  };

  const handleDelete = async (id) => {
    if (!confirm('Delete rule?')) return;
    try {
      await api.deleteACL(id);
      fetchACLs();
    } catch (err) {
      alert(err.message);
    }
  };

  const saveDefaults = async () => {
    try {
      await api.updateGlobalConfig({
        acl_inbound_default: defaults.inbound,
        acl_outbound_default: defaults.outbound,
        acl_relay_default: defaults.relay,
      });
      alert('ACL defaults updated.');
    } catch (err) {
      alert(err.message);
    }
  };

  return (
    <div className="space-y-6">
      <div className="rounded-3xl border border-[var(--border)] bg-[var(--surface-soft)] px-4 py-3 text-sm text-[var(--muted)]">
        ACL changes take effect immediately — rules are pushed live to the running daemon without a restart.
      </div>
      <section className="panel p-6">
        <div className="mb-6 flex items-center gap-3">
          <div className="brand-badge">
            <ShieldAlert size={18} />
          </div>
          <div>
            <span className="eyebrow">ACL Defaults</span>
            <h3 className="text-2xl font-black tracking-tight">Server-side traffic direction</h3>
          </div>
        </div>

        <div className="mb-5 grid gap-3 lg:grid-cols-3">
          <div className="stat-tile">
            <span className="stat-label">Inbound</span>
            <strong>From WireGuard into the server/host when a peer initiates a connection.</strong>
          </div>
          <div className="stat-tile">
            <span className="stat-label">Outbound</span>
            <strong>From the server side into WireGuard when a peer receives or reaches outward.</strong>
          </div>
          <div className="stat-tile">
            <span className="stat-label">Relay</span>
            <strong>Peer-to-peer forwarding between WireGuard peers through this server.</strong>
          </div>
        </div>

        <div className="grid gap-4 md:grid-cols-3">
          {[
            ['inbound', 'Inbound default'],
            ['outbound', 'Outbound default'],
            ['relay', 'Relay default'],
          ].map(([key, label]) => (
            <div key={key} className="space-y-2">
              <label className="field-label">{label}</label>
              <select
                className="select-field"
                value={defaults[key]}
                onChange={(event) => setDefaults((current) => ({ ...current, [key]: event.target.value }))}
              >
                <option value="allow">Allow</option>
                <option value="deny">Deny</option>
              </select>
            </div>
          ))}
        </div>

        <div className="mt-4">
          <button type="button" onClick={saveDefaults} className="primary-button">
            <span>Save defaults</span>
          </button>
        </div>
      </section>

      <section className="panel p-6">
        <div className="mb-6 flex items-center gap-3">
          <div className="brand-badge">
            <ShieldAlert size={18} />
          </div>
          <div>
            <span className="eyebrow">Firewall Policy</span>
            <h3 className="text-2xl font-black tracking-tight">Create a rule</h3>
          </div>
        </div>

        <form onSubmit={handleCreate} className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <div className="space-y-2">
            <label className="field-label">List</label>
            <select className="select-field" value={newACL.list_name} onChange={(event) => setNewACL({ ...newACL, list_name: event.target.value })}>
              <option value="relay">Relay: peer to peer</option>
              <option value="inbound">Inbound: from WireGuard</option>
              <option value="outbound">Outbound: to WireGuard</option>
            </select>
          </div>
          <div className="space-y-2">
            <label className="field-label">Action</label>
            <select className="select-field" value={newACL.action} onChange={(event) => setNewACL({ ...newACL, action: event.target.value })}>
              <option value="allow">Allow</option>
              <option value="deny">Deny</option>
            </select>
          </div>
          <div className="space-y-2">
            <label className="field-label">Source</label>
            <input className="input-field" placeholder="10.0.0.0/24" value={newACL.src} onChange={(event) => setNewACL({ ...newACL, src: event.target.value })} />
          </div>
          <div className="space-y-2">
            <label className="field-label">Destination</label>
            <input className="input-field" placeholder="0.0.0.0/0" value={newACL.dst} onChange={(event) => setNewACL({ ...newACL, dst: event.target.value })} />
          </div>
          <div className="space-y-2">
            <label className="field-label">Protocol</label>
            <input className="input-field" placeholder="tcp" value={newACL.proto} onChange={(event) => setNewACL({ ...newACL, proto: event.target.value })} />
          </div>
          <div className="space-y-2">
            <label className="field-label">Port</label>
            <input className="input-field" placeholder="80-443" value={newACL.dport} onChange={(event) => setNewACL({ ...newACL, dport: event.target.value })} />
          </div>
          <div className="space-y-2">
            <label className="field-label">Priority</label>
            <input className="input-field" type="number" value={newACL.priority} onChange={(event) => setNewACL({ ...newACL, priority: event.target.value })} />
          </div>
          <div className="flex items-end">
            <button type="submit" className="primary-button w-full justify-center">
              <Plus size={16} />
              <span>Add rule</span>
            </button>
          </div>
        </form>
      </section>

      <section className="table-shell">
        <table>
          <thead>
            <tr>
              <th>List</th>
              <th>Action</th>
              <th>Source</th>
              <th>Destination</th>
              <th>Proto</th>
              <th>Port</th>
              <th>Priority</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {acls.map((acl) => (
              <tr key={acl.id}>
                <td className="font-mono text-sm">{acl.list_name}</td>
                <td>
                  <span className={`status-chip ${acl.action === 'deny' ? 'status-chip-danger' : ''}`}>
                    {acl.action.toUpperCase()}
                  </span>
                </td>
                <td className="font-mono text-xs">{acl.src || '*'}</td>
                <td className="font-mono text-xs">{acl.dst || '*'}</td>
                <td className="font-mono text-xs uppercase">{acl.proto || '*'}</td>
                <td className="font-mono text-xs">{acl.dport || '*'}</td>
                <td>{acl.priority}</td>
                <td className="text-right">
                  <button type="button" onClick={() => handleDelete(acl.id)} className="ghost-button ghost-button-danger">
                    <Trash2 size={16} />
                    <span>Delete</span>
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}
