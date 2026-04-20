import { useEffect, useState } from 'react';
import { KeyRound, Network, Shield, ShieldCheck, ShieldOff, Trash2, UserPlus } from 'lucide-react';
import { api } from '../lib/api';

function UserPasswordForm({ user, onDone }) {
  const [pw, setPw] = useState('');
  const handleSave = async (e) => {
    e.preventDefault();
    if (pw.length < 8) { alert('Password must be at least 8 characters.'); return; }
    try {
      await api.updateUser(user.id, { password: pw });
      setPw('');
      onDone();
    } catch (err) {
      alert(err.message);
    }
  };
  return (
    <form onSubmit={handleSave} className="flex items-center gap-2 mt-1">
      <input
        className="input-field h-8 text-sm py-1 w-40"
        type="password"
        placeholder="New password"
        minLength={8}
        required
        value={pw}
        onChange={e => setPw(e.target.value)}
        autoFocus
      />
      <button type="submit" className="primary-button h-8 text-xs px-3 py-1">Save</button>
      <button type="button" onClick={onDone} className="ghost-button h-8 text-xs px-3 py-1">Cancel</button>
    </form>
  );
}

export default function UsersTab() {
  const [users, setUsers] = useState([]);
  const [groups, setGroups] = useState([]);
  const [newUser, setNewUser] = useState({ username: '', password: '', groups: '', primary_group: 'default' });
  const [newGroup, setNewGroup] = useState({ name: '', parent_groups: '', extra_cidrs: '', subnet: '' });
  const [passwordEditId, setPasswordEditId] = useState(null);

  async function fetchData() {
    try {
      const [userData, groupData] = await Promise.all([api.getUsers(), api.getTags()]);
      setUsers(userData);
      setGroups(groupData);
    } catch (err) {
      console.error(err);
    }
  }

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const [userData, groupData] = await Promise.all([api.getUsers(), api.getTags()]);
        if (!cancelled) {
          setUsers(userData);
          setGroups(groupData);
        }
      } catch (err) {
        console.error(err);
      }
    }
    load();
    return () => { cancelled = true; };
  }, []);

  const handleCreate = async (event) => {
    event.preventDefault();
    try {
      await api.createUser(newUser);
      setNewUser({ username: '', password: '', groups: '', primary_group: 'default' });
      fetchData();
    } catch (err) {
      alert(err.message);
    }
  };

  const handleUpdateUserGroups = async (user, groupsValue) => {
    try {
      await api.updateUser(user.id, { groups: groupsValue });
      fetchData();
    } catch (err) {
      alert(err.message);
    }
  };

  const handleUpdateUserPrimaryGroup = async (user, primaryGroup) => {
    try {
      await api.updateUser(user.id, { primary_group: primaryGroup });
      fetchData();
    } catch (err) {
      alert(err.message);
    }
  };

  const handleCreateGroup = async (event) => {
    event.preventDefault();
    try {
      // Send subnet="auto" to trigger auto-assignment when box is checked but empty,
      // or pass the explicit value the admin typed.
      const payload = { ...newGroup };
      if (payload.subnet === 'auto' || payload.subnet === '') {
        // Leave as-is — backend treats empty as non-primary-capable, "auto" as auto-assign
      }
      await api.createTag(payload);
      setNewGroup({ name: '', parent_groups: '', extra_cidrs: '', subnet: '' });
      fetchData();
    } catch (err) {
      alert(err.message);
    }
  };

  const handleUpdateGroup = async (group, patch) => {
    try {
      await api.updateTag(group.id, { ...group, ...patch });
      fetchData();
    } catch (err) {
      alert(err.message);
    }
  };

  const handleDeleteGroup = async (id) => {
    if (!confirm('Delete group? Existing assignments are left as-is.')) return;
    try {
      await api.deleteTag(id);
      fetchData();
    } catch (err) {
      alert(err.message);
    }
  };

  const handleDelete = async (id) => {
    if (!confirm('Delete user?')) return;
    try {
      await api.deleteUser(id);
      fetchData();
    } catch (err) {
      alert(err.message);
    }
  };

  const handleAdminResetTOTP = async (user) => {
    if (!confirm(`Remove 2FA from ${user.username}? They will be able to log in without a code.`)) return;
    try {
      await api.adminResetUserTOTP(user.id);
      fetchData();
    } catch (err) {
      alert(err.message);
    }
  };

  const primaryCapableGroups = groups.filter(g => g.subnet);

  return (
    <div className="space-y-6">
      <section className="panel p-6">
        <div className="mb-6 flex items-center gap-3">
          <div className="brand-badge">
            <UserPlus size={18} />
          </div>
          <div>
            <span className="eyebrow">Account Management</span>
            <h3 className="text-2xl font-black tracking-tight">Add a user</h3>
          </div>
        </div>

        <form onSubmit={handleCreate} className="grid gap-4 md:grid-cols-2 lg:grid-cols-[1fr_1fr_1fr_1fr_auto] md:items-end">
          <div className="space-y-2">
            <label className="field-label">Username</label>
            <input className="input-field" required value={newUser.username} onChange={(e) => setNewUser({ ...newUser, username: e.target.value })} />
          </div>
          <div className="space-y-2">
            <label className="field-label">Password</label>
            <input className="input-field" required type="password" value={newUser.password} onChange={(e) => setNewUser({ ...newUser, password: e.target.value })} />
          </div>
          <div className="space-y-2">
            <label className="field-label">Primary group</label>
            <select
              className="input-field"
              value={newUser.primary_group}
              onChange={(e) => setNewUser({ ...newUser, primary_group: e.target.value })}
            >
              <option value="default">default</option>
              {primaryCapableGroups.filter(g => g.name !== 'default').map(g => (
                <option key={g.id} value={g.name}>{g.name} ({g.subnet})</option>
              ))}
            </select>
          </div>
          <div className="space-y-2">
            <label className="field-label">Additional groups</label>
            <input className="input-field" placeholder="staff, lab" value={newUser.groups} onChange={(e) => setNewUser({ ...newUser, groups: e.target.value })} />
            <p className="text-xs text-[var(--muted)]">Add <code className="font-mono">admin</code> here to grant administrator access.</p>
          </div>
          <button type="submit" className="primary-button justify-center">
            <UserPlus size={16} />
            <span>Create</span>
          </button>
        </form>
      </section>

      <section className="panel p-6">
        <div className="mb-6 flex items-center gap-3">
          <div className="brand-badge">
            <Network size={18} />
          </div>
          <div>
            <span className="eyebrow">Policy Groups</span>
            <h3 className="text-2xl font-black tracking-tight">Groups and subnets</h3>
          </div>
        </div>
        <p className="mb-4 text-sm text-[var(--muted)]">
          A group with a subnet is <strong>primary-capable</strong> — users assigned to it as their primary group get IPs from that subnet.
          Leave subnet empty for role-only groups (e.g. <code>admin</code>). Use <code>auto</code> to auto-assign the next available block.
        </p>
        <form onSubmit={handleCreateGroup} className="grid gap-4 md:grid-cols-[1fr_1fr_1fr_2fr_auto] md:items-end">
          <div className="space-y-2">
            <label className="field-label">Name</label>
            <input className="input-field" required value={newGroup.name} onChange={(e) => setNewGroup({ ...newGroup, name: e.target.value })} />
          </div>
          <div className="space-y-2">
            <label className="field-label">Subnet <span className="normal-case font-normal text-[var(--muted)]">(or "auto")</span></label>
            <input className="input-field font-mono text-sm" placeholder="auto / 100.100.8.0/22 / empty" value={newGroup.subnet} onChange={(e) => setNewGroup({ ...newGroup, subnet: e.target.value })} />
          </div>
          <div className="space-y-2">
            <label className="field-label">Inherits</label>
            <input className="input-field" placeholder="staff, trusted" value={newGroup.parent_groups} onChange={(e) => setNewGroup({ ...newGroup, parent_groups: e.target.value })} />
          </div>
          <div className="space-y-2">
            <label className="field-label">Extra CIDRs</label>
            <input className="input-field font-mono text-sm" placeholder="100.64.50.0/24" value={newGroup.extra_cidrs} onChange={(e) => setNewGroup({ ...newGroup, extra_cidrs: e.target.value })} />
          </div>
          <button type="submit" className="primary-button justify-center">Add group</button>
        </form>
        <div className="mt-5 grid gap-2">
          {groups.map((group) => (
            <div key={group.id} className="grid gap-2 rounded-lg border border-[var(--border)] p-3 md:grid-cols-[1fr_1fr_1fr_2fr_auto]">
              <div className="flex items-center gap-2">
                <input
                  className="input-field"
                  value={group.name}
                  disabled={group.built_in}
                  onChange={(e) => handleUpdateGroup(group, { name: e.target.value })}
                />
                {group.built_in && <span className="text-xs text-[var(--muted)] whitespace-nowrap">built-in</span>}
              </div>
              <div className="flex items-center gap-1">
                {group.subnet ? (
                  <span className="font-mono text-xs px-2 py-1 rounded-lg bg-[var(--surface-soft)] text-[var(--text)] border border-[var(--border)] select-all">{group.subnet}</span>
                ) : (
                  <span className="text-xs text-[var(--muted)]">no subnet</span>
                )}
              </div>
              <input className="input-field" placeholder="Inherited groups" value={group.parent_groups || ''} onChange={(e) => handleUpdateGroup(group, { parent_groups: e.target.value })} />
              <input className="input-field font-mono text-sm" value={group.extra_cidrs || ''} onChange={(e) => handleUpdateGroup(group, { extra_cidrs: e.target.value })} />
              <button type="button" onClick={() => handleDeleteGroup(group.id)} disabled={group.built_in} className="ghost-button ghost-button-danger">Delete</button>
            </div>
          ))}
        </div>
      </section>

      <section className="table-shell">
        <table>
          <thead>
            <tr>
              <th>User</th>
              <th>Primary group</th>
              <th>Access</th>
              <th>Additional groups</th>
              <th>Created</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {users.map((user) => (
              <tr key={user.id}>
                <td className="font-semibold">{user.username}</td>
                <td>
                  <select
                    className="input-field text-sm py-1 h-8"
                    value={user.primary_group || 'default'}
                    onChange={(e) => {
                      setUsers(cur => cur.map(u => u.id === user.id ? { ...u, primary_group: e.target.value } : u));
                      handleUpdateUserPrimaryGroup(user, e.target.value);
                    }}
                  >
                    <option value="default">default</option>
                    {primaryCapableGroups.filter(g => g.name !== 'default').map(g => (
                      <option key={g.id} value={g.name}>{g.name}</option>
                    ))}
                  </select>
                </td>
                <td>
                  {user.is_admin ? (
                    <span className="status-chip">
                      <ShieldCheck size={13} />
                      Admin
                    </span>
                  ) : (
                    <span className="status-chip status-chip-muted">
                      <Shield size={13} />
                      User
                    </span>
                  )}
                </td>
                <td>
                  <input
                    className="input-field min-w-48"
                    value={user.groups || ''}
                    onChange={(e) => setUsers((cur) => cur.map((u) => u.id === user.id ? { ...u, groups: e.target.value } : u))}
                    onBlur={(e) => handleUpdateUserGroups(user, e.target.value)}
                  />
                </td>
                <td>{new Date(user.created_at).toLocaleString()}</td>
                <td className="text-right">
                  <div className="flex flex-col items-end gap-1">
                    <div className="flex gap-1">
                      {!user.oidc_login && (
                        <button
                          type="button"
                          onClick={() => setPasswordEditId(passwordEditId === user.id ? null : user.id)}
                          className="ghost-button text-xs"
                          title="Change password"
                        >
                          <KeyRound size={14} />
                        </button>
                      )}
                      {!user.oidc_login && user.totp_enabled && (
                        <button
                          type="button"
                          onClick={() => handleAdminResetTOTP(user)}
                          className="ghost-button text-xs"
                          title="Remove 2FA"
                        >
                          <ShieldOff size={14} />
                        </button>
                      )}
                      <button type="button" onClick={() => handleDelete(user.id)} className="ghost-button ghost-button-danger">
                        <Trash2 size={16} />
                        <span>Delete</span>
                      </button>
                    </div>
                    {passwordEditId === user.id && (
                      <UserPasswordForm user={user} onDone={() => setPasswordEditId(null)} />
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}
