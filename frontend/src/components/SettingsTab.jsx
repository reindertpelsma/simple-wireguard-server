import { useState, useEffect } from 'react';
import { api, request } from '../lib/api';
import { Save, FileText, Activity } from 'lucide-react';

export default function SettingsTab() {
  const [config, setConfig] = useState({});
  const [yaml, setYaml] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    setLoading(true);
    try {
      const c = await api.getPublicConfig();
      setConfig(c);
      const y = await request('/api/admin/yaml');
      setYaml(y);
    } catch (err) { console.error(err); }
    finally { setLoading(false); }
  };

  const handleUpdate = async (e) => {
    e.preventDefault();
    try {
      await api.updateGlobalConfig(config);
      alert('Config updated! Restart might be required for some changes.');
      fetchData();
    } catch (err) { alert(err.message); }
  };

  if (loading) return <div className="text-center py-20 text-gray-500 font-bold animate-pulse uppercase tracking-widest">Loading Settings...</div>;

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
      <div className="space-y-6">
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
          <h3 className="text-xl font-bold mb-6 flex items-center gap-2">
            <Save size={20} className="text-purple-500" /> Global Settings
          </h3>
          <form onSubmit={handleUpdate} className="space-y-4">
            {Object.entries(config).map(([key, val]) => (
              <div key={key}>
                <label className="block text-xs text-gray-500 mb-1 uppercase font-bold tracking-wider">{key.replace(/_/g, ' ')}</label>
                <input
                  type="text"
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm outline-none focus:ring-1 focus:ring-purple-500"
                  value={val}
                  onChange={e => setConfig({...config, [key]: e.target.value})}
                />
              </div>
            ))}
            <button type="submit" className="w-full bg-purple-600 hover:bg-purple-700 py-3 rounded-lg font-bold shadow-lg shadow-purple-500/20 transition mt-4">
              Save Changes
            </button>
          </form>
        </div>
      </div>

      <div className="space-y-6">
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 h-full flex flex-col">
          <h3 className="text-xl font-bold mb-6 flex items-center gap-2">
            <FileText size={20} className="text-purple-500" /> Server YAML (Generated)
          </h3>
          <pre className="flex-1 bg-black/50 border border-gray-800 rounded-lg p-4 font-mono text-[11px] text-gray-400 overflow-auto max-h-[600px]">
            {yaml}
          </pre>
        </div>
      </div>
    </div>
  );
}
