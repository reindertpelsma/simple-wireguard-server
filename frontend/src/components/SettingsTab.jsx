import { useEffect, useState } from 'react';
import { FileText, Save } from 'lucide-react';
import { api, request } from '../lib/api';

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
      const currentConfig = await api.getAdminConfig();
      setConfig(currentConfig);
      const generatedYaml = await request('/api/admin/yaml');
      setYaml(generatedYaml);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleUpdate = async (event) => {
    event.preventDefault();
    try {
      await api.updateGlobalConfig(config);
      alert('Config updated. Some daemon changes may still need a restart.');
      fetchData();
    } catch (err) {
      alert(err.message);
    }
  };

  if (loading) {
    return <div className="state-shell py-24 text-[var(--muted)]">Loading settings…</div>;
  }

  return (
    <div className="grid gap-6 xl:grid-cols-[1.1fr_0.9fr]">
      <section className="panel p-6">
        <div className="mb-6 flex items-center gap-3">
          <div className="brand-badge">
            <Save size={18} />
          </div>
          <div>
            <span className="eyebrow">Operator Settings</span>
            <h3 className="text-2xl font-black tracking-tight">Global configuration</h3>
          </div>
        </div>

        <form onSubmit={handleUpdate} className="grid gap-4 md:grid-cols-2">
          {Object.entries(config).map(([key, value]) => (
            <div key={key} className="space-y-2">
              <label className="field-label">{key.replace(/_/g, ' ')}</label>
              <input
                type="text"
                className="input-field"
                value={value}
                onChange={(event) => setConfig({ ...config, [key]: event.target.value })}
              />
            </div>
          ))}

          <div className="md:col-span-2">
            <button type="submit" className="primary-button">
              <Save size={16} />
              <span>Save settings</span>
            </button>
          </div>
        </form>
      </section>

      <section className="panel p-6">
        <div className="mb-6 flex items-center gap-3">
          <div className="brand-badge">
            <FileText size={18} />
          </div>
          <div>
            <span className="eyebrow">Canonical Output</span>
            <h3 className="text-2xl font-black tracking-tight">Generated daemon YAML</h3>
          </div>
        </div>
        <pre className="config-block min-h-[540px]">{yaml}</pre>
      </section>
    </div>
  );
}
