import { useState, useEffect } from 'react';
import { api } from '../lib/api';
import { ShieldAlert, Plus, Trash2 } from 'lucide-react';

export default function ACLsTab() {
  const [acls, setACLs] = useState([]);
  const [newACL, setNewACL] = useState({ list_name: 'relay', action: 'allow', src: '', dst: '', proto: '', dport: '', priority: 0 });

  useEffect(() => { fetchACLs(); }, []);

  const fetchACLs = async () => {
    try {
      const data = await api.getACLs();
      setACLs(data);
    } catch (err) { console.error(err); }
  };

  const handleCreate = async (e) => {
    e.preventDefault();
    try {
      await api.createACL({...newACL, priority: parseInt(newACL.priority)});
      setNewACL({ list_name: 'relay', action: 'allow', src: '', dst: '', proto: '', dport: '', priority: 0 });
      fetchACLs();
    } catch (err) { alert(err.message); }
  };

  const handleDelete = async (id) => {
    if (!confirm('Delete rule?')) return;
    try {
      await api.deleteACL(id);
      fetchACLs();
    } catch (err) { alert(err.message); }
  };

  return (
    <div className="space-y-8">
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
        <h3 className="text-xl font-bold mb-4 flex items-center gap-2">
          <ShieldAlert size={20} className="text-purple-500" /> New Firewall Rule
        </h3>
        <form onSubmit={handleCreate} className="grid grid-cols-1 md:grid-cols-4 lg:grid-cols-8 gap-4 items-end">
          <div className="col-span-1">
            <label className="block text-xs text-gray-400 mb-1">List</label>
            <select className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 outline-none" 
                    value={newACL.list_name} onChange={e => setNewACL({...newACL, list_name: e.target.value})}>
              <option value="relay">Relay</option>
              <option value="inbound">Inbound</option>
              <option value="outbound">Outbound</option>
            </select>
          </div>
          <div className="col-span-1">
            <label className="block text-xs text-gray-400 mb-1">Action</label>
            <select className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 outline-none"
                    value={newACL.action} onChange={e => setNewACL({...newACL, action: e.target.value})}>
              <option value="allow">Allow</option>
              <option value="deny">Deny</option>
            </select>
          </div>
          <div className="col-span-1">
            <label className="block text-xs text-gray-400 mb-1">Source</label>
            <input type="text" placeholder="10.0.0.0/24" className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 outline-none text-sm"
                   value={newACL.src} onChange={e => setNewACL({...newACL, src: e.target.value})} />
          </div>
          <div className="col-span-1">
            <label className="block text-xs text-gray-400 mb-1">Destination</label>
            <input type="text" placeholder="0.0.0.0/0" className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 outline-none text-sm"
                   value={newACL.dst} onChange={e => setNewACL({...newACL, dst: e.target.value})} />
          </div>
          <div className="col-span-1">
            <label className="block text-xs text-gray-400 mb-1">Proto</label>
            <input type="text" placeholder="tcp" className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 outline-none text-sm"
                   value={newACL.proto} onChange={e => setNewACL({...newACL, proto: e.target.value})} />
          </div>
          <div className="col-span-1">
            <label className="block text-xs text-gray-400 mb-1">Port</label>
            <input type="text" placeholder="80,443" className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 outline-none text-sm"
                   value={newACL.dport} onChange={e => setNewACL({...newACL, dport: e.target.value})} />
          </div>
          <div className="col-span-1">
            <label className="block text-xs text-gray-400 mb-1">Prio</label>
            <input type="number" className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 outline-none text-sm"
                   value={newACL.priority} onChange={e => setNewACL({...newACL, priority: e.target.value})} />
          </div>
          <button type="submit" className="bg-purple-600 hover:bg-purple-700 px-4 py-2 rounded font-bold h-[38px] flex items-center justify-center">
            <Plus size={18}/>
          </button>
        </form>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <table className="w-full text-left">
          <thead>
            <tr className="bg-gray-800 text-gray-400 text-xs uppercase tracking-wider">
              <th className="px-6 py-3">List</th>
              <th className="px-6 py-3">Action</th>
              <th className="px-6 py-3">Source</th>
              <th className="px-6 py-3">Destination</th>
              <th className="px-6 py-3">Proto</th>
              <th className="px-6 py-3">Port</th>
              <th className="px-6 py-3">Prio</th>
              <th className="px-6 py-3"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800 text-sm">
            {acls.map(a => (
              <tr key={a.id} className="hover:bg-white/5 transition">
                <td className="px-6 py-4 capitalize font-mono text-purple-400">{a.list_name}</td>
                <td className="px-6 py-4">
                  <span className={`px-2 py-1 rounded text-xs font-bold ${a.action === 'allow' ? 'bg-green-500/10 text-green-500' : 'bg-red-500/10 text-red-500'}`}>
                    {a.action.toUpperCase()}
                  </span>
                </td>
                <td className="px-6 py-4 font-mono text-xs">{a.src || '*'}</td>
                <td className="px-6 py-4 font-mono text-xs">{a.dst || '*'}</td>
                <td className="px-6 py-4 font-mono text-xs uppercase">{a.proto || '*'}</td>
                <td className="px-6 py-4 font-mono text-xs">{a.dport || '*'}</td>
                <td className="px-6 py-4">{a.priority}</td>
                <td className="px-6 py-4">
                  <button onClick={() => handleDelete(a.id)} className="text-gray-500 hover:text-red-500 transition"><Trash2 size={16}/></button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
