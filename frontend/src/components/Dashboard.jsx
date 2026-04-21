import { useEffect, useState } from 'react';
import { ArrowLeftRight, LogOut, Menu, Plus, Radio, RadioTower, Settings, ShieldAlert, Smartphone, User, Users, X } from 'lucide-react';
import { api } from '../lib/api';
import AddPeerModal from './AddPeerModal';
import ConfigModal from './ConfigModal';
import PeersTab from './PeersTab';
import UsersTab from './UsersTab';
import ACLsTab from './ACLsTab';
import SettingsTab from './SettingsTab';
import TransportsTab from './TransportsTab';
import TurnTab from './TurnTab';
import ForwardsTab from './ForwardsTab';
import ProfileTab from './ProfileTab';
import ThemeToggle from './ThemeToggle';

const tabs = [
  { id: 'peers',      label: 'Peers',      icon: Smartphone,    adminOnly: false },
  { id: 'profile',    label: 'Profile',    icon: User,          adminOnly: false },
  { id: 'acls',       label: 'ACLs',       icon: ShieldAlert,   adminOnly: true },
  { id: 'transports', label: 'Transports', icon: Radio,         adminOnly: true },
  { id: 'turn',       label: 'TURN',       icon: RadioTower,    adminOnly: true },
  { id: 'forwards',   label: 'Forwards',   icon: ArrowLeftRight, adminOnly: true },
  { id: 'users',      label: 'Users',      icon: Users,         adminOnly: true },
  { id: 'settings',   label: 'Settings',   icon: Settings,      adminOnly: true },
];

export default function Dashboard({ theme, onToggleTheme, onLogout }) {
  const [activeTab, setActiveTab] = useState('peers');
  const [isAdmin, setIsAdmin] = useState(false);
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [selectedPeer, setSelectedPeer] = useState(null);
  const [currentUsername, setCurrentUsername] = useState('');
  const [mobileNavOpen, setMobileNavOpen] = useState(false);

  useEffect(() => {
    async function checkAdmin() {
      try {
        await api.getUsers();
        setIsAdmin(true);
      } catch {
        setIsAdmin(false);
      }
    }

    async function fetchMe() {
      try {
        const me = await api.getMe();
        setCurrentUsername(me?.username || '');
      } catch {
        // ignore
      }
    }

    checkAdmin();
    fetchMe();
  }, []);

  const visibleTabs = tabs.filter((tab) => isAdmin || !tab.adminOnly);
  const activeTabMeta = visibleTabs.find((tab) => tab.id === activeTab) || visibleTabs[0];

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
                onClick={() => setMobileNavOpen((open) => !open)}
                className="ghost-button mobile-nav-toggle"
                aria-label="Toggle navigation"
              >
                {mobileNavOpen ? <X size={18} /> : <Menu size={18} />}
                <span>Menu</span>
              </button>
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

          <div className="mobile-nav-summary">
            <span className="text-sm font-semibold text-[var(--muted)]">Current section</span>
            <span className="status-chip status-chip-muted">{activeTabMeta?.label || activeTab}</span>
          </div>

          {mobileNavOpen && (
            <div className="mobile-nav-panel">
              {visibleTabs.map((tab) => {
                const TabIcon = tab.icon;

                return (
                  <button
                    key={tab.id}
                    type="button"
                    onClick={() => {
                      setActiveTab(tab.id);
                      setMobileNavOpen(false);
                    }}
                    className={`tab-pill ${activeTab === tab.id ? 'tab-pill-active' : ''}`}
                  >
                    <TabIcon size={16} />
                    <span>{tab.label}</span>
                  </button>
                );
              })}
            </div>
          )}

          <div className="tab-strip desktop-tab-strip">
            {visibleTabs.map((tab) => {
              const TabIcon = tab.icon;

              return (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => setActiveTab(tab.id)}
                  className={`tab-pill ${activeTab === tab.id ? 'tab-pill-active' : ''}`}
                >
                  <TabIcon size={16} />
                  <span>{tab.label}</span>
                </button>
              );
            })}
          </div>
        </div>
      </header>

      <main className="mx-auto w-full max-w-7xl px-4 py-6 pb-24 sm:px-6 lg:px-8">
        {activeTab === 'peers'      && <PeersTab isAdmin={isAdmin} currentUsername={currentUsername} onSelectPeer={setSelectedPeer} />}
        {activeTab === 'profile'    && <ProfileTab />}
        {activeTab === 'acls'       && <ACLsTab />}
        {activeTab === 'transports' && <TransportsTab />}
        {activeTab === 'turn'       && <TurnTab />}
        {activeTab === 'forwards'   && <ForwardsTab />}
        {activeTab === 'users'      && <UsersTab />}
        {activeTab === 'settings'   && <SettingsTab />}
      </main>

      <footer className="px-4 pb-10 text-center text-sm text-[var(--muted)] sm:px-6 lg:px-8">
        Powered by <a className="font-semibold text-[var(--accent)] underline-offset-4 hover:underline" href="https://github.com/reindertpelsma/simple-wireguard-server" target="_blank" rel="noreferrer">simple-wireguard-server</a>
      </footer>

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
