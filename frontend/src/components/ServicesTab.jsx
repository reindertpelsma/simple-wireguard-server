import { ExternalLink, Globe, Plus, Trash2 } from 'lucide-react';
import { useEffect, useState } from 'react';
import { api } from '../lib/api';

const EMPTY_SERVICE_FORM = {
  name: '',
  host: '',
  target_url: '',
  auth_mode: 'login',
  bypass_cidrs: '',
  cors_protection: true,
  allowed_origins: '',
  insecure_skip_verify: false,
  ca_pem: '',
  client_cert_pem: '',
};

export default function ServicesTab({ isAdmin = false, sudoActive = false, onRequireSudo = () => {} }) {
  const [services, setServices] = useState([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const [serviceForm, setServiceForm] = useState(EMPTY_SERVICE_FORM);

  async function loadServices() {
    const data = isAdmin ? await api.getExposedServices() : await api.getVisibleServices();
    setServices(data || []);
  }

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const data = isAdmin ? await api.getExposedServices() : await api.getVisibleServices();
        if (!cancelled) {
          setServices(data || []);
          setError('');
        }
      } catch (err) {
        if (!cancelled) {
          setServices([]);
          setError(err.message || 'Failed to load services');
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    return () => { cancelled = true; };
  }, [isAdmin]);

  const handleCreateService = async (event) => {
    event.preventDefault();
    if (!sudoActive) return onRequireSudo();
    setBusy('service');
    try {
      await api.createExposedService(serviceForm);
      setServiceForm(EMPTY_SERVICE_FORM);
      await loadServices();
      setError('');
    } catch (err) {
      setError(err.message || 'Failed to create service');
    } finally {
      setBusy('');
    }
  };

  const handleDeleteService = async (id) => {
    if (!sudoActive) return onRequireSudo();
    if (!confirm('Delete this exposed service?')) return;
    setBusy('service');
    try {
      await api.deleteExposedService(id);
      await loadServices();
      setError('');
    } catch (err) {
      setError(err.message || 'Failed to delete service');
    } finally {
      setBusy('');
    }
  };

  if (loading) {
    return <div className="state-shell py-24 text-[var(--muted)]">Loading services…</div>;
  }

  return (
    <div className="space-y-6">
      <section className="panel p-6">
        <div className="mb-6 flex items-center gap-3">
          <div className="brand-badge"><Globe size={18} /></div>
          <div>
            <span className="eyebrow">Services</span>
            <h3 className="text-2xl font-black tracking-tight">Published services</h3>
          </div>
        </div>
        {error ? <div className="mb-4 error-banner">{error}</div> : null}
        {services.length === 0 ? (
          <div className="state-shell py-12 text-[var(--muted)]">No services available</div>
        ) : (
          <div className="grid gap-3">
            {services.map((service) => (
              <div key={service.id} className="card p-4">
                <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
                  <div className="space-y-1">
                    <h4 className="text-lg font-bold tracking-tight">{service.name}</h4>
                    <p className="font-mono text-sm text-[var(--muted)]">{service.host}</p>
                    <p className="font-mono text-xs text-[var(--muted)]">{service.url}</p>
                    {isAdmin && service.target_url ? (
                      <p className="text-xs text-[var(--muted)]">Target: <span className="font-mono">{service.target_url}</span></p>
                    ) : null}
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <a
                      href={service.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="primary-button justify-center"
                    >
                      <ExternalLink size={16} />
                      <span>Connect</span>
                    </a>
                    {isAdmin ? (
                      <button
                        type="button"
                        onClick={() => handleDeleteService(service.id)}
                        className="ghost-button ghost-button-danger"
                      >
                        <Trash2 size={16} />
                        <span>Delete</span>
                      </button>
                    ) : null}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      {isAdmin ? (
        <section className="panel p-6">
          <div className="mb-4 flex items-center gap-3">
            <div className="brand-badge"><Plus size={18} /></div>
            <div>
              <span className="eyebrow">Service Publishing</span>
              <h3 className="text-xl font-black tracking-tight">Expose a new service</h3>
            </div>
          </div>
          {!sudoActive ? (
            <div className="mb-4 error-banner">Service publishing is read-only until you unlock sensitive actions.</div>
          ) : null}
          <form onSubmit={handleCreateService} className="grid gap-4 md:grid-cols-2">
            <input className="input-field" placeholder="service name" value={serviceForm.name} onChange={(event) => setServiceForm({ ...serviceForm, name: event.target.value })} />
            <input className="input-field" placeholder="service.wireguard.example.com" value={serviceForm.host} onChange={(event) => setServiceForm({ ...serviceForm, host: event.target.value })} />
            <input className="input-field md:col-span-2" placeholder="http://100.64.0.10:8080" value={serviceForm.target_url} onChange={(event) => setServiceForm({ ...serviceForm, target_url: event.target.value })} />
            <select className="input-field" value={serviceForm.auth_mode} onChange={(event) => setServiceForm({ ...serviceForm, auth_mode: event.target.value })}>
              <option value="login">Require login</option>
              <option value="open">Open</option>
            </select>
            <label className="flex items-center gap-2 text-sm font-medium text-[var(--text)]"><input type="checkbox" checked={serviceForm.cors_protection} onChange={(event) => setServiceForm({ ...serviceForm, cors_protection: event.target.checked })} /> CORS protection</label>
            <textarea className="input-field md:col-span-2" placeholder="Bypass CIDRs" value={serviceForm.bypass_cidrs} onChange={(event) => setServiceForm({ ...serviceForm, bypass_cidrs: event.target.value })} />
            <input className="input-field md:col-span-2" placeholder="Allowed origins for CORS bypass" value={serviceForm.allowed_origins} onChange={(event) => setServiceForm({ ...serviceForm, allowed_origins: event.target.value })} />
            <label className="flex items-center gap-2 text-sm font-medium text-[var(--text)]"><input type="checkbox" checked={serviceForm.insecure_skip_verify} onChange={(event) => setServiceForm({ ...serviceForm, insecure_skip_verify: event.target.checked })} /> Skip backend TLS verification</label>
            <textarea className="input-field md:col-span-2 font-mono text-sm" placeholder="Backend CA PEM" value={serviceForm.ca_pem} onChange={(event) => setServiceForm({ ...serviceForm, ca_pem: event.target.value })} />
            <textarea className="input-field md:col-span-2 font-mono text-sm" placeholder="Client certificate and key PEM" value={serviceForm.client_cert_pem} onChange={(event) => setServiceForm({ ...serviceForm, client_cert_pem: event.target.value })} />
            <div className="md:col-span-2">
              <button type="submit" disabled={busy === 'service'} className="primary-button">
                <Plus size={16} />
                <span>{busy === 'service' ? 'Saving…' : 'Add service'}</span>
              </button>
            </div>
          </form>
        </section>
      ) : null}
    </div>
  );
}
