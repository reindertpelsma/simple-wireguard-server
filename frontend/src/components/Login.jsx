import { useState } from 'react';
import { api } from '../lib/api';
import { Shield, Loader2 } from 'lucide-react';

export default function Login({ onLogin }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      const { token } = await api.login(username, password);
      localStorage.setItem('token', token);
      onLogin();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-950 px-4">
      <div className="max-w-md w-full space-y-8 p-8 bg-gray-900 rounded-2xl border border-gray-800 shadow-xl">
        <div className="text-center">
          <div className="flex justify-center">
            <Shield className="h-12 w-12 text-purple-500" />
          </div>
          <h2 className="mt-6 text-3xl font-extrabold text-white">
            WireGuard Manager
          </h2>
          <p className="mt-2 text-sm text-gray-400">
            Sign in to manage your devices
          </p>
        </div>
        <form className="mt-8 space-y-6" onSubmit={handleSubmit} role="form">
          <div className="rounded-md shadow-sm space-y-4">
            <div>
              <label className="text-sm font-medium text-gray-300">Username</label>
              <input
                type="text"
                required
                className="appearance-none relative block w-full px-3 py-2 border border-gray-700 bg-gray-800 text-white rounded-lg focus:outline-none focus:ring-purple-500 focus:border-purple-500 sm:text-sm"
                placeholder="Admin"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
              />
            </div>
            <div>
              <label className="text-sm font-medium text-gray-300">Password</label>
              <input
                type="password"
                required
                className="appearance-none relative block w-full px-3 py-2 border border-gray-700 bg-gray-800 text-white rounded-lg focus:outline-none focus:ring-purple-500 focus:border-purple-500 sm:text-sm"
                placeholder="••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>
          </div>

          {error && (
            <div className="text-red-500 text-sm text-center">
              {error}
            </div>
          )}

          <div>
            <button
              type="submit"
              disabled={loading}
              className="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-lg text-white bg-purple-600 hover:bg-purple-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-purple-500 disabled:opacity-50"
            >
              {loading ? <Loader2 className="animate-spin h-5 w-5" /> : 'Sign in'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
