import { useEffect, useState } from 'react';
import { Shield, ShieldCheck, Trash2, UserPlus } from 'lucide-react';
import { api } from '../lib/api';

export default function UsersTab() {
  const [users, setUsers] = useState([]);
  const [tags, setTags] = useState([]);
  const [newUser, setNewUser] = useState({ username: '', password: '', is_admin: false, tags: '' });
  const [newTag, setNewTag] = useState({ name: '', extra_cidrs: '' });

  async function fetchUsers() {
    try {
      const data = await api.getUsers();
      setUsers(data);
      setTags(await api.getTags());
    } catch (err) {
      console.error(err);
    }
  }

  useEffect(() => {
    let cancelled = false;

    async function loadUsers() {
      try {
        const data = await api.getUsers();
        const tagData = await api.getTags();
        if (!cancelled) {
          setUsers(data);
          setTags(tagData);
        }
      } catch (err) {
        console.error(err);
      }
    }

    loadUsers();
    return () => {
      cancelled = true;
    };
  }, []);

  const handleCreate = async (event) => {
    event.preventDefault();
    try {
      await api.createUser(newUser);
      setNewUser({ username: '', password: '', is_admin: false, tags: '' });
      fetchUsers();
    } catch (err) {
      alert(err.message);
    }
  };

  const handleUpdateUserTags = async (user, tagsValue) => {
    try {
      await api.updateUser(user.id, { tags: tagsValue });
      fetchUsers();
    } catch (err) {
      alert(err.message);
    }
  };

  const handleCreateTag = async (event) => {
    event.preventDefault();
    try {
      await api.createTag(newTag);
      setNewTag({ name: '', extra_cidrs: '' });
      fetchUsers();
    } catch (err) {
      alert(err.message);
    }
  };

  const handleUpdateTag = async (tag, patch) => {
    try {
      await api.updateTag(tag.id, { ...tag, ...patch });
      fetchUsers();
    } catch (err) {
      alert(err.message);
    }
  };

  const handleDeleteTag = async (id) => {
    if (!confirm('Delete tag? Existing text assignments are left as-is.')) return;
    try {
      await api.deleteTag(id);
      fetchUsers();
    } catch (err) {
      alert(err.message);
    }
  };

  const handleDelete = async (id) => {
    if (!confirm('Delete user?')) return;
    try {
      await api.deleteUser(id);
      fetchUsers();
    } catch (err) {
      alert(err.message);
    }
  };

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

        <form onSubmit={handleCreate} className="grid gap-4 md:grid-cols-[1fr_1fr_1fr_auto_auto] md:items-end">
          <div className="space-y-2">
            <label className="field-label">Username</label>
            <input className="input-field" required value={newUser.username} onChange={(event) => setNewUser({ ...newUser, username: event.target.value })} />
          </div>
          <div className="space-y-2">
            <label className="field-label">Password</label>
            <input className="input-field" required type="password" value={newUser.password} onChange={(event) => setNewUser({ ...newUser, password: event.target.value })} />
          </div>
          <div className="space-y-2">
            <label className="field-label">Tags</label>
            <input className="input-field" placeholder="admins, lab" value={newUser.tags} onChange={(event) => setNewUser({ ...newUser, tags: event.target.value })} />
          </div>
          <label className="flex items-center gap-3 rounded-2xl border border-[var(--border)] bg-[var(--surface-soft)] px-4 py-3 text-sm font-medium">
            <input type="checkbox" checked={newUser.is_admin} onChange={(event) => setNewUser({ ...newUser, is_admin: event.target.checked })} />
            <span>Admin</span>
          </label>
          <button type="submit" className="primary-button justify-center">
            <UserPlus size={16} />
            <span>Create</span>
          </button>
        </form>
      </section>

      <section className="panel p-6">
        <div className="mb-6 flex items-center gap-3">
          <div className="brand-badge">
            <Shield size={18} />
          </div>
          <div>
            <span className="eyebrow">Policy Tags</span>
            <h3 className="text-2xl font-black tracking-tight">Groups and extra CIDRs</h3>
          </div>
        </div>
        <form onSubmit={handleCreateTag} className="grid gap-4 md:grid-cols-[1fr_2fr_auto] md:items-end">
          <div className="space-y-2">
            <label className="field-label">Tag</label>
            <input className="input-field" required value={newTag.name} onChange={(event) => setNewTag({ ...newTag, name: event.target.value })} />
          </div>
          <div className="space-y-2">
            <label className="field-label">Extra CIDRs</label>
            <input className="input-field" placeholder="100.64.50.0/24" value={newTag.extra_cidrs} onChange={(event) => setNewTag({ ...newTag, extra_cidrs: event.target.value })} />
          </div>
          <button type="submit" className="primary-button justify-center">Add tag</button>
        </form>
        <div className="mt-5 grid gap-2">
          {tags.map((tag) => (
            <div key={tag.id} className="grid gap-2 rounded-lg border border-[var(--border)] p-3 md:grid-cols-[1fr_2fr_auto]">
              <input className="input-field" value={tag.name} onChange={(event) => handleUpdateTag(tag, { name: event.target.value })} />
              <input className="input-field font-mono text-sm" value={tag.extra_cidrs || ''} onChange={(event) => handleUpdateTag(tag, { extra_cidrs: event.target.value })} />
              <button type="button" onClick={() => handleDeleteTag(tag.id)} className="ghost-button ghost-button-danger">Delete</button>
            </div>
          ))}
        </div>
      </section>

      <section className="table-shell">
        <table>
          <thead>
            <tr>
              <th>User</th>
              <th>Role</th>
              <th>Tags</th>
              <th>Created</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {users.map((user) => (
              <tr key={user.id}>
                <td className="font-semibold">{user.username}</td>
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
                    value={user.tags || ''}
                    onChange={(event) => setUsers((current) => current.map((item) => item.id === user.id ? { ...item, tags: event.target.value } : item))}
                    onBlur={(event) => handleUpdateUserTags(user, event.target.value)}
                  />
                </td>
                <td>{new Date(user.created_at).toLocaleString()}</td>
                <td className="text-right">
                  <button type="button" onClick={() => handleDelete(user.id)} className="ghost-button ghost-button-danger">
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
