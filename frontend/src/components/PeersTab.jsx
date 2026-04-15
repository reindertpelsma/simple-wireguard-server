import { useState, useEffect } from 'react';
import { api } from '../lib/api';
import { Smartphone, QrCode, Trash2, Activity, Power, PowerOff, Edit3, Loader2, User, Globe, Lock } from 'lucide-react';

export default function PeersTab({ isAdmin, onSelectPeer }) {
  const [peers, setPeers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [pinging, setPinging] = useState(null);
  const [editingPeer, setEditingPeer] = useState(null);

  useEffect(() => { fetchPeers(); }, []);

  const fetchPeers = async () => {
    setLoading(true);
    try {
      const data = await api.getPeers();
      setPeers(data || []);
    } catch (err) { console.error(err); }
    finally { setLoading(false); }
  };

  const handleUpdate = async (id, data) => {
    try {
      await api.updatePeer(id, data);
      setEditingPeer(null);
      fetchPeers();
    } catch (err) { alert(err.message); }
  };

  const handleToggle = async (peer) => {
    try {
      await api.updatePeer(peer.id, { enabled: !peer.enabled });
      fetchPeers();
    } catch (err) { alert(err.message); }
  };

  const handlePing = async (id) => {
    setPinging(id);
    try {
      const res = await api.pingPeer(id);
      alert(`Ping Result: ${res.received}/${res.transmitted} received. Avg RTT: ${res.round_trip_ms?.[0]?.toFixed(2) || 'N/A'}ms`);
    } catch (err) { alert(`Ping failed: ${err.message}`); }
    finally { setPinging(null); }
  };

  const handleDelete = async (id) => {
    if (!confirm('Delete device?')) return;
    try {
      await api.deletePeer(id);
      fetchPeers();
    } catch (err) { alert(err.message); }
  };

  const formatBytes = (bytes) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const groups = peers.reduce((acc, peer) => {
    const user = peer.username || 'Unknown';
    if (!acc[user]) acc[user] = [];
    acc[user].push(peer);
    return acc;
  }, {});

  if (loading) return <div className="flex justify-center py-20"><Loader2 className="animate-spin text-purple-500" size={40}/></div>;

  return (
    <div className="space-y-10 pb-20">
      {Object.entries(groups).map(([user, userPeers]) => (
        <div key={user} className="space-y-4">
          <div className="flex items-center gap-4 px-2">
            <User size={16} className="text-gray-500" />
            <h3 className="text-sm font-bold text-gray-400 uppercase tracking-widest">
              {user}
            </h3>
            <div className="h-px bg-gray-800 flex-1"></div>
          </div>
          <div className="grid grid-cols-1 gap-4">
            {userPeers.map(peer => (
              <div key={peer.id} className={`bg-gray-900 border ${peer.enabled ? 'border-gray-800' : 'border-red-900/30 opacity-60'} rounded-xl p-5 hover:border-purple-500/40 transition group relative overflow-hidden`}>
                <div className="flex flex-wrap justify-between items-start gap-4 relative z-10">
                  <div className="flex items-start gap-4">
                    <div className={`p-3 rounded-lg ${peer.enabled ? 'bg-purple-500/10 text-purple-500 shadow-lg shadow-purple-500/5' : 'bg-gray-800 text-gray-500'}`}>
                      <Smartphone size={24} />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <h4 className="font-bold text-lg">{peer.name}</h4>
                        {!peer.enabled && <span className="text-[10px] bg-red-500/20 text-red-500 px-1.5 py-0.5 rounded font-bold uppercase">Offline</span>}
                        {peer.is_manual_key && <Lock size={12} className="text-amber-500" title="Manual Key" />}
                      </div>
                      <p className="text-sm font-mono text-purple-400 font-medium">{peer.assigned_ips}</p>
                      <div className="flex flex-wrap gap-x-6 gap-y-1 mt-2 text-[11px] text-gray-500 font-medium">
                        <span className="flex items-center gap-1"><Activity size={12}/> {peer.has_handshake ? `Handshake: ${new Date(peer.last_handshake_time).toLocaleTimeString()}` : 'No Handshake'}</span>
                        <span className="flex items-center gap-1"><Globe size={12}/> {formatBytes(peer.transmit_bytes + peer.receive_bytes)}</span>
                        {peer.expires_at && (
                          <span className={`flex items-center gap-1 ${new Date(peer.expires_at) < new Date() ? 'text-red-500' : 'text-amber-500'}`}>
                            Expires: {new Date(peer.expires_at).toLocaleDateString()}
                          </span>
                        )}
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-1 bg-gray-950/50 p-1 rounded-xl border border-gray-800/50">
                    <button onClick={() => handlePing(peer.id)} disabled={pinging === peer.id} className="p-2 hover:bg-gray-800 rounded-lg text-gray-400 transition" title="Ping">
                      {pinging === peer.id ? <Loader2 size={18} className="animate-spin text-purple-500"/> : <Activity size={18} />}
                    </button>
                    <button onClick={() => setEditingPeer(peer)} className="p-2 hover:bg-gray-800 rounded-lg text-gray-400 transition" title="Edit">
                      <Edit3 size={18} />
                    </button>
                    <button onClick={() => handleToggle(peer)} className={`p-2 hover:bg-gray-800 rounded-lg transition ${peer.enabled ? 'text-green-500' : 'text-red-500'}`} title={peer.enabled ? 'Disable' : 'Enable'}>
                      {peer.enabled ? <Power size={18}/> : <PowerOff size={18}/>}
                    </button>
                    <div className="w-px h-4 bg-gray-800 mx-1"></div>
                    
                    {/* View Logic: can view if !is_e2e OR if we have the local nonce */}
                    {(() => {
                      const hasLocalNonce = !!localStorage.getItem(`nonce_${peer.public_key}`);
                      const canView = !peer.is_e2e || hasLocalNonce;
                      
                      return (
                        <button 
                          onClick={() => canView ? onSelectPeer(peer) : null} 
                          disabled={!canView}
                          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-bold transition ${
                            canView 
                              ? 'bg-purple-600/10 text-purple-400 hover:bg-purple-600 hover:text-white' 
                              : 'bg-gray-800/50 text-gray-600 cursor-not-allowed opacity-50'
                          }`}
                          title={!canView ? (peer.is_e2e ? 'Decryption key (nonce) missing from this browser' : 'Encryption locked') : ''}
                        >
                          <QrCode size={16} /> Config
                        </button>
                      );
                    })()}

                    <button onClick={() => handleDelete(peer.id)} className="p-2 hover:bg-red-500/20 text-gray-500 hover:text-red-500 rounded-lg transition">
                      <Trash2 size={18} />
                    </button>
                  </div>
                </div>

                {/* Protected Data Section */}
                {(isAdmin || peer.public_key || peer.endpoint_ip || peer.static_endpoint) && (
                  <div className="mt-4 pt-4 border-t border-gray-800/50 grid grid-cols-1 md:grid-cols-2 gap-4 text-[10px]">
                    {peer.public_key && (
                      <div>
                        <span className="text-gray-600 block mb-1 uppercase font-black tracking-tighter">Public Key</span>
                        <code className="bg-black/40 px-2 py-1.5 rounded-lg text-gray-400 block truncate border border-gray-800/50">{peer.public_key}</code>
                      </div>
                    )}
                    {(peer.endpoint_ip || peer.static_endpoint) && (
                      <div>
                        <span className="text-gray-600 block mb-1 uppercase font-black tracking-tighter">Endpoint / IP Privacy</span>
                        <code className="bg-black/40 px-2 py-1.5 rounded-lg text-gray-400 block truncate border border-gray-800/50">
                          {peer.static_endpoint ? `Static: ${peer.static_endpoint}` : (peer.endpoint_ip ? `Remote: ${peer.endpoint_ip}` : 'No Endpoint')}
                        </code>
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      ))}

      {/* Edit Modal */}
      {editingPeer && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50">
          <div className="bg-gray-900 border border-gray-800 rounded-2xl w-full max-w-md p-8">
            <h2 className="text-2xl font-bold mb-6">Edit Peer Settings</h2>
            <div className="space-y-4">
              <div>
                <label className="block text-xs text-gray-500 mb-1 uppercase font-bold">Name</label>
                <input type="text" className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 outline-none" 
                       defaultValue={editingPeer.name} onBlur={e => handleUpdate(editingPeer.id, { name: e.target.value })} />
              </div>
              {isAdmin && (
                <div>
                  <label className="block text-xs text-gray-500 mb-1 uppercase font-bold">Assigned IPs / Subnets</label>
                  <input type="text" className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 outline-none font-mono" 
                         defaultValue={editingPeer.assigned_ips} onBlur={e => handleUpdate(editingPeer.id, { assigned_ips: e.target.value })} />
                </div>
              )}
              <div>
                <label className="block text-xs text-gray-500 mb-1 uppercase font-bold">Static Endpoint (host:port)</label>
                <input type="text" className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 outline-none" 
                       defaultValue={editingPeer.static_endpoint} onBlur={e => handleUpdate(editingPeer.id, { static_endpoint: e.target.value })} />
              </div>
              <div>
                <label className="block text-xs text-gray-500 mb-1 uppercase font-bold">Keepalive (Seconds)</label>
                <input type="number" className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 outline-none" 
                       defaultValue={editingPeer.keepalive} onBlur={e => handleUpdate(editingPeer.id, { keepalive: parseInt(e.target.value) })} />
              </div>
              <div>
                <label className="block text-xs text-gray-500 mb-1 uppercase font-bold">Expiration Date</label>
                <input type="datetime-local" className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 outline-none text-white" 
                       defaultValue={editingPeer.expires_at ? new Date(editingPeer.expires_at).toISOString().slice(0, 16) : ''} 
                       onBlur={e => handleUpdate(editingPeer.id, { expires_at: e.target.value ? new Date(e.target.value).toISOString() : null })} />
              </div>
            </div>
            <button onClick={() => setEditingPeer(null)} className="w-full mt-8 bg-gray-800 hover:bg-gray-700 py-3 rounded-lg font-bold transition">Close</button>
          </div>
        </div>
      )}
    </div>
  );
}
