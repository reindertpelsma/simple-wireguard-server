import { useState, useEffect } from 'react';
import { api } from '../lib/api';
import { Plus, LogOut, Loader2, Users, ShieldAlert, Smartphone, Settings } from 'lucide-react';
import AddPeerModal from './AddPeerModal';
import ConfigModal from './ConfigModal';
import PeersTab from './PeersTab';
import UsersTab from './UsersTab';
import ACLsTab from './ACLsTab';
import SettingsTab from './SettingsTab';

export default function Dashboard({ onLogout }) {
  const [activeTab, setActiveTab] = useState('peers');
  const [isAdmin, setIsAdmin] = useState(false);
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [selectedPeer, setSelectedPeer] = useState(null);

  useEffect(() => {
    // Check if admin from token/state
    const checkAdmin = async () => {
      try {
        const users = await api.getUsers(); // Will fail if not admin
        setIsAdmin(true);
      } catch (err) {
        setIsAdmin(false);
      }
    };
    checkAdmin();
  }, []);

  return (
    <div className="min-h-screen bg-gray-950 text-white flex flex-col">
      {/* Header */}
      <header className="border-b border-gray-800 bg-gray-900/50 backdrop-blur-md sticky top-0 z-30">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-8">
            <h1 className="text-xl font-black bg-gradient-to-r from-purple-400 to-purple-600 bg-clip-text text-transparent uppercase tracking-tighter">
              WireGuard / SD-WAN
            </h1>
            <nav className="flex gap-1">
              <button 
                onClick={() => setActiveTab('peers')}
                className={`px-4 py-2 rounded-lg text-sm font-bold transition flex items-center gap-2 ${activeTab === 'peers' ? 'bg-purple-600 text-white' : 'text-gray-400 hover:bg-gray-800'}`}
              >
                <Smartphone size={16}/> Peers
              </button>
              {isAdmin && (
                <>
                  <button 
                    onClick={() => setActiveTab('acls')}
                    className={`px-4 py-2 rounded-lg text-sm font-bold transition flex items-center gap-2 ${activeTab === 'acls' ? 'bg-purple-600 text-white' : 'text-gray-400 hover:bg-gray-800'}`}
                  >
                    <ShieldAlert size={16}/> ACLs
                  </button>
                  <button 
                    onClick={() => setActiveTab('users')}
                    className={`px-4 py-2 rounded-lg text-sm font-bold transition flex items-center gap-2 ${activeTab === 'users' ? 'bg-purple-600 text-white' : 'text-gray-400 hover:bg-gray-800'}`}
                  >
                    <Users size={16}/> Users
                  </button>
                  <button 
                    onClick={() => setActiveTab('settings')}
                    className={`px-4 py-2 rounded-lg text-sm font-bold transition flex items-center gap-2 ${activeTab === 'settings' ? 'bg-purple-600 text-white' : 'text-gray-400 hover:bg-gray-800'}`}
                  >
                    <Settings size={16}/> Settings
                  </button>
                </>
              )}
            </nav>
          </div>
          <div className="flex items-center gap-4">
            <button
              onClick={() => setIsAddModalOpen(true)}
              className="hidden md:flex items-center gap-2 bg-purple-600 hover:bg-purple-700 px-4 py-2 rounded-lg font-bold text-sm transition"
            >
              <Plus size={18} /> New Device
            </button>
            <button
              onClick={onLogout}
              className="p-2 text-gray-400 hover:text-white hover:bg-gray-800 rounded-lg transition"
            >
              <LogOut size={20} />
            </button>
          </div>
        </div>
      </header>

      {/* Content */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-6">
        {activeTab === 'peers' && <PeersTab isAdmin={isAdmin} onSelectPeer={setSelectedPeer} />}
        {activeTab === 'acls' && <ACLsTab />}
        {activeTab === 'users' && <UsersTab />}
        {activeTab === 'settings' && <SettingsTab />}
      </main>

      {/* Floating Add Button for Mobile */}
      <button
        onClick={() => setIsAddModalOpen(true)}
        className="md:hidden fixed bottom-6 right-6 w-14 h-14 bg-purple-600 rounded-full shadow-xl flex items-center justify-center text-white z-40"
      >
        <Plus size={24}/>
      </button>

      {isAddModalOpen && (
        <AddPeerModal
          onClose={() => setIsAddModalOpen(false)}
          onSuccess={async (peer) => {
            setIsAddModalOpen(false);
            window.location.reload(); 
          }}
        />
      )}

      {selectedPeer && (
        <ConfigModal
          peer={selectedPeer}
          onClose={() => setSelectedPeer(null)}
        />
      )}
    </div>
  );
}
