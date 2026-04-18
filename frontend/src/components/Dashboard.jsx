import { useEffect, useState } from 'react';
import { LogOut, Plus, Radio, Settings, ShieldAlert, Smartphone, Users } from 'lucide-react';
import { api } from '../lib/api';
import AddPeerModal from './AddPeerModal';
import ConfigModal from './ConfigModal';
import PeersTab from './PeersTab';
import UsersTab from './UsersTab';
import ACLsTab from './ACLsTab';
import SettingsTab from './SettingsTab';
import TransportsTab from './TransportsTab';
import ThemeToggle from './ThemeToggle';

const tabs = [
  { id: 'peers', label: 'Peers', icon: Smartphone, adminOnly: false },
  { id: 'acls', label: 'ACLs', icon: ShieldAlert, adminOnly: true },
  { id: 'transports', label: 'Transports', icon: Radio, adminOnly: true },
  { id: 'users', label: 'Users', icon: Users, adminOnly: true },
  { id: 'settings', label: 'Settings', icon: Settings, adminOnly: true },
];

export default function Dashboard({ theme, onToggleTheme, onLogout }) {
  const [activeTab, setActiveTab] = useState('peers');
  const [isAdmin, setIsAdmin] = useState(false);
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [selectedPeer, setSelectedPeer] = useState(null);

  useEffect(() => {
    async function checkAdmin() {
      try {
        await api.getUsers();
        setIsAdmin(true);
      } catch {
        setIsAdmin(false);
      }
    }

    checkAdmin();
  }, []);

  const visibleTabs = tabs.filter((tab) => isAdmin || !tab.adminOnly);

  const handleLogout = async () => {
    try {
      await api.logout();
    } catch {
      // The local session is cleared either way; logout should feel reliable.
    }
    onLogout();
  };

  return (
    <div className="app-shell">
      <header className="sticky top-0 z-30 border-b border-[var(--border)] bg-[var(--panel)]/95 backdrop-blur-xl">
        <div className="mx-auto flex max-w-7xl flex-col gap-4 px-4 py-4 sm:px-6 lg:px-8">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
            <div className="space-y-2">
              <span className="eyebrow">WireGuard VPN Control</span>
              <div className="flex flex-wrap items-center gap-3">
                <h1 className="text-2xl font-black tracking-tight sm:text-3xl">
                  Manage peers, policies, and bootstrap access from one console
                </h1>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <ThemeToggle theme={theme} onToggle={onToggleTheme} />
              <button
                type="button"
                onClick={() => setIsAddModalOpen(true)}
                className="primary-button"
              >
                <Plus size={18} />
                <span>New Device</span>
              </button>
              <button
                type="button"
                onClick={handleLogout}
                className="ghost-button"
                aria-label="Log out"
                title="Log out"
              >
                <LogOut size={18} />
              </button>
            </div>
          </div>

          <div className="tab-strip">
            {visibleTabs.map((tab) => {
              const TabIcon = tab.icon;

              return <button
                key={tab.id}
                type="button"
                onClick={() => setActiveTab(tab.id)}
                className={`tab-pill ${activeTab === tab.id ? 'tab-pill-active' : ''}`}
              >
                <TabIcon size={16} />
                <span>{tab.label}</span>
              </button>
            })}
          </div>
        </div>
      </header>

      <main className="mx-auto w-full max-w-7xl px-4 py-6 pb-24 sm:px-6 lg:px-8">
        {activeTab === 'peers' && <PeersTab isAdmin={isAdmin} onSelectPeer={setSelectedPeer} />}
        {activeTab === 'acls' && <ACLsTab />}
        {activeTab === 'transports' && <TransportsTab />}
        {activeTab === 'users' && <UsersTab />}
        {activeTab === 'settings' && <SettingsTab />}
      </main>

      <button
        type="button"
        onClick={() => setIsAddModalOpen(true)}
        className="floating-action lg:hidden"
        aria-label="Create device"
      >
        <Plus size={22} />
      </button>

      {isAddModalOpen && (
        <AddPeerModal
          onClose={() => setIsAddModalOpen(false)}
          onSuccess={() => {
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
