import { useEffect, useState } from 'react';
import { Plus, ShieldAlert, Trash2 } from 'lucide-react';
import { api } from '../lib/api';

export default function ACLsTab() {
  const [acls, setACLs] = useState([]);
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
    } catch (err) {
      console.error(err);
    }
  }

  useEffect(() => {
    let cancelled = false;

    async function loadACLs() {
      try {
        const data = await api.getACLs();
        if (!cancelled) {
          setACLs(data);
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

  return (
    <div className="space-y-6">
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
              <option value="relay">Relay</option>
              <option value="inbound">Inbound</option>
              <option value="outbound">Outbound</option>
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
