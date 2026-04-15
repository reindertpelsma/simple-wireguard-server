import { useState, useEffect } from 'react';
import { api } from '../lib/api';
import { UserPlus, Trash2, ShieldCheck, Shield } from 'lucide-react';

export default function UsersTab() {
  const [users, setUsers] = useState([]);
  const [newUser, setNewUser] = useState({ username: '', password: '', is_admin: false });

  useEffect(() => { fetchUsers(); }, []);

  const fetchUsers = async () => {
    try {
      const data = await api.getUsers();
      setUsers(data);
    } catch (err) { console.error(err); }
  };

  const handleCreate = async (e) => {
    e.preventDefault();
    try {
      await api.createUser(newUser);
      setNewUser({ username: '', password: '', is_admin: false });
      fetchUsers();
    } catch (err) { alert(err.message); }
  };

  const handleDelete = async (id) => {
    if (!confirm('Delete user?')) return;
    try {
      await api.deleteUser(id);
      fetchUsers();
    } catch (err) { alert(err.message); }
  };

  return (
    <div className="space-y-8">
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
        <h3 className="text-xl font-bold mb-4 flex items-center gap-2">
          <UserPlus size={20} className="text-purple-500" /> Add New User
        </h3>
        <form onSubmit={handleCreate} className="flex flex-wrap gap-4 items-end">
          <div>
            <label className="block text-xs text-gray-400 mb-1">Username</label>
            <input
              type="text"
              required
              className="bg-gray-800 border border-gray-700 rounded px-3 py-2 outline-none"
              value={newUser.username}
              onChange={e => setNewUser({...newUser, username: e.target.value})}
            />
          </div>
          <div>
            <label className="block text-xs text-gray-400 mb-1">Password</label>
            <input
              type="password"
              required
              className="bg-gray-800 border border-gray-700 rounded px-3 py-2 outline-none"
              value={newUser.password}
              onChange={e => setNewUser({...newUser, password: e.target.value})}
            />
          </div>
          <label className="flex items-center gap-2 bg-gray-800 border border-gray-700 rounded px-3 py-2 cursor-pointer">
            <input
              type="checkbox"
              checked={newUser.is_admin}
              onChange={e => setNewUser({...newUser, is_admin: e.target.checked})}
            />
            <span className="text-sm">Admin</span>
          </label>
          <button type="submit" className="bg-purple-600 hover:bg-purple-700 px-6 py-2 rounded font-bold">
            Create
          </button>
        </form>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <table className="w-full text-left">
          <thead>
            <tr className="bg-gray-800 text-gray-400 text-sm">
              <th className="px-6 py-3">User</th>
              <th className="px-6 py-3">Role</th>
              <th className="px-6 py-3">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800 text-sm">
            {users.map(u => (
              <tr key={u.id}>
                <td className="px-6 py-4 font-medium">{u.username}</td>
                <td className="px-6 py-4">
                  {u.is_admin ? (
                    <span className="flex items-center gap-1 text-purple-400 font-bold"><ShieldCheck size={14}/> Admin</span>
                  ) : (
                    <span className="flex items-center gap-1 text-gray-400"><Shield size={14}/> User</span>
                  )}
                </td>
                <td className="px-6 py-4">
                  <button onClick={() => handleDelete(u.id)} className="text-gray-500 hover:text-red-500"><Trash2 size={16}/></button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
