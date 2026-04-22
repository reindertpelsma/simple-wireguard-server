import { useCallback, useEffect, useState } from 'react';
import { Lock, LogOut, Menu, Plus, RadioTower, Settings, ShieldAlert, Smartphone, User, Users, X } from 'lucide-react';
import { api } from '../lib/api';
import AddPeerModal from './AddPeerModal';
import ConfigModal from './ConfigModal';
import PeersTab from './PeersTab';
import UsersTab from './UsersTab';
import ACLsTab from './ACLsTab';
import SettingsTab from './SettingsTab';
import TurnTab from './TurnTab';
import ProfileTab from './ProfileTab';
import ThemeToggle from './ThemeToggle';
import ServicesTab from './ServicesTab';
import SudoModal from './SudoModal';

const tabs = [
  { id: 'peers',      label: 'Peers',      icon: Smartphone,    adminOnly: false },
  { id: 'services',   label: 'Services',   icon: RadioTower,    adminOnly: false },
  { id: 'profile',    label: 'Profile',    icon: User,          adminOnly: false },
  { id: 'acls',       label: 'ACLs',       icon: ShieldAlert,   adminOnly: true },
  { id: 'turn',       label: 'TURN',       icon: RadioTower,    adminOnly: true },
  { id: 'users',      label: 'Users',      icon: Users,         adminOnly: false },
  { id: 'settings',   label: 'Settings',   icon: Settings,      adminOnly: true },
];

export default function Dashboard({ theme, onToggleTheme, onLogout }) {
  const [activeTab, setActiveTab] = useState('peers');
  const [me, setMe] = useState(null);
  const [publicConfig, setPublicConfig] = useState({});
  const [visibleServiceCount, setVisibleServiceCount] = useState(0);
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [selectedPeer, setSelectedPeer] = useState(null);
  const [currentUsername, setCurrentUsername] = useState('');
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [sudoModalOpen, setSudoModalOpen] = useState(false);

  const refreshContext = useCallback(async () => {
    try {
      const [meData, cfg] = await Promise.all([api.getMe(), api.getPublicConfig()]);
      setMe(meData || null);
      setPublicConfig(cfg || {});
      setCurrentUsername(meData?.username || '');
      if ((cfg?.exposed_services_enabled === 'true') && !meData?.can_manage_settings) {
        try {
          const services = await api.getVisibleServices();
          setVisibleServiceCount(Array.isArray(services) ? services.length : 0);
        } catch {
          setVisibleServiceCount(0);
        }
      } else {
        setVisibleServiceCount(0);
      }
    } catch {
      setMe(null);
      setPublicConfig({});
      setCurrentUsername('');
      setVisibleServiceCount(0);
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    async function loadContext() {
      try {
        const [meData, cfg] = await Promise.all([api.getMe(), api.getPublicConfig()]);
        if (cancelled) {
          return;
        }
        setMe(meData || null);
        setPublicConfig(cfg || {});
        setCurrentUsername(meData?.username || '');
        if ((cfg?.exposed_services_enabled === 'true') && !meData?.can_manage_settings) {
          try {
            const services = await api.getVisibleServices();
            if (!cancelled) {
              setVisibleServiceCount(Array.isArray(services) ? services.length : 0);
            }
          } catch {
            if (!cancelled) {
              setVisibleServiceCount(0);
            }
          }
        } else {
          setVisibleServiceCount(0);
        }
      } catch {
        if (cancelled) {
          return;
        }
        setMe(null);
        setPublicConfig({});
        setCurrentUsername('');
        setVisibleServiceCount(0);
      }
    }
    loadContext();
    return () => {
      cancelled = true;
    };
  }, []);

  const isAdmin = !!me?.can_manage_settings;
  const canManageUsers = !!me?.can_manage_users;
  const sudoActive = !!me?.sudo_active;
  const turnEnabled = publicConfig.turn_hosting_enabled === 'true';
  const turnSelfService = publicConfig.turn_allow_user_credentials === 'true';
  const turnAvailable = turnEnabled && (isAdmin || turnSelfService);
  const servicesEnabled = publicConfig.exposed_services_enabled === 'true';
  const servicesAvailable = servicesEnabled && (isAdmin || visibleServiceCount > 0);

  const visibleTabs = tabs.filter((tab) => {
    if (tab.id === 'users') return canManageUsers;
    if (tab.id === 'acls' || tab.id === 'settings') return isAdmin;
    if (tab.id === 'turn') return turnAvailable;
    if (tab.id === 'services') return servicesAvailable;
    return !tab.adminOnly || isAdmin;
  });
  const activeTabMeta = visibleTabs.find((tab) => tab.id === activeTab) || visibleTabs[0];

  useEffect(() => {
    if (!visibleTabs.some((tab) => tab.id === activeTab) && visibleTabs[0]) {
      setActiveTab(visibleTabs[0].id);
    }
  }, [activeTab, visibleTabs]);

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
              <span className="eyebrow">Simple WireGuard Server</span>
              <div className="flex flex-wrap items-center gap-3">
                <h1 className="text-2xl font-black tracking-tight sm:text-3xl">
                  Manage WireGuard peers, services, and operator access
                </h1>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <ThemeToggle theme={theme} onToggle={onToggleTheme} />
              <button
                type="button"
                onClick={async () => {
                  if (sudoActive) {
                    try {
                      await api.lockSudo();
                    } finally {
                      refreshContext();
                    }
                    return;
                  }
                  setSudoModalOpen(true);
                }}
                className={`ghost-button ${sudoActive ? '' : 'ghost-button-danger'}`}
              >
                <Lock size={16} />
                <span>{sudoActive ? 'Changes unlocked' : 'Read-only mode'}</span>
              </button>
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
                onClick={() => sudoActive ? setIsAddModalOpen(true) : setSudoModalOpen(true)}
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
        {activeTab === 'peers'      && <PeersTab isAdmin={isAdmin} currentUsername={currentUsername} sudoActive={sudoActive} onRequireSudo={() => setSudoModalOpen(true)} onSelectPeer={(peer) => sudoActive ? setSelectedPeer(peer) : setSudoModalOpen(true)} />}
        {activeTab === 'services'   && <ServicesTab isAdmin={isAdmin} sudoActive={sudoActive} onRequireSudo={() => setSudoModalOpen(true)} />}
        {activeTab === 'profile'    && <ProfileTab me={me} sudoActive={sudoActive} onRequireSudo={() => setSudoModalOpen(true)} onRefreshMe={refreshContext} />}
        {activeTab === 'acls'       && <ACLsTab />}
        {activeTab === 'turn'       && <TurnTab isAdmin={isAdmin} sudoActive={sudoActive} onRequireSudo={() => setSudoModalOpen(true)} />}
        {activeTab === 'users'      && <UsersTab me={me} />}
        {activeTab === 'settings'   && <SettingsTab sudoActive={sudoActive} onRequireSudo={() => setSudoModalOpen(true)} onRefreshContext={refreshContext} />}
      </main>

      <footer className="px-4 pb-10 text-center text-sm text-[var(--muted)] sm:px-6 lg:px-8">
        Powered by <a className="font-semibold text-[var(--accent)] underline-offset-4 hover:underline" href="https://github.com/reindertpelsma/simple-wireguard-server" target="_blank" rel="noreferrer">simple-wireguard-server</a>
      </footer>

      {activeTab === 'peers' && (
        <button
          type="button"
          onClick={() => sudoActive ? setIsAddModalOpen(true) : setSudoModalOpen(true)}
          className="floating-action lg:hidden"
          aria-label="Create device"
        >
          <Plus size={22} />
        </button>
      )}

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

      <SudoModal
        open={sudoModalOpen}
        onClose={() => setSudoModalOpen(false)}
        onSuccess={refreshContext}
        requires2FA={!!me?.totp_enabled}
      />
    </div>
  );
}
