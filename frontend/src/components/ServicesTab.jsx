import { ExternalLink, Globe } from 'lucide-react';
import { useEffect, useState } from 'react';
import { api } from '../lib/api';

export default function ServicesTab({ isAdmin = false }) {
  const [services, setServices] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const data = isAdmin ? await api.getExposedServices() : await api.getVisibleServices();
        if (!cancelled) setServices(data || []);
      } catch (err) {
        if (!cancelled) {
          console.error(err);
          setServices([]);
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    return () => { cancelled = true; };
  }, [isAdmin]);

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
                    {isAdmin && service.target_url ? (
                      <p className="text-xs text-[var(--muted)]">Target: <span className="font-mono">{service.target_url}</span></p>
                    ) : null}
                  </div>
                  <a
                    href={service.url}
                    target="_blank"
                    rel="noreferrer"
                    className="primary-button justify-center"
                  >
                    <ExternalLink size={16} />
                    <span>Connect</span>
                  </a>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
