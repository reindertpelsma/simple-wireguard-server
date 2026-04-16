import { useEffect, useMemo, useState } from 'react';
import {
  Activity,
  Copy,
  Edit3,
  Globe,
  Link2,
  Loader2,
  Lock,
  Power,
  PowerOff,
  QrCode,
  Smartphone,
  Trash2,
  User,
  X,
} from 'lucide-react';
import { api } from '../lib/api';
import { formatBytes } from '../lib/config';
import TrafficSparkline from './TrafficSparkline';

function formatBps(value) {
  const bps = Number(value || 0);
  if (bps <= 0) return 'unlimited';
  const units = ['bps', 'Kbps', 'Mbps', 'Gbps'];
  let scaled = bps;
  let index = 0;
  while (scaled >= 1000 && index < units.length - 1) {
    scaled /= 1000;
    index += 1;
  }
  return `${scaled >= 10 || index === 0 ? scaled.toFixed(0) : scaled.toFixed(1)} ${units[index]}`;
}

function parseNumberField(value) {
  const text = String(value || '').trim();
  if (!text) return 0;
  return Number.parseInt(text, 10) || 0;
}

function ShareModal({ peer, onClose }) {
  const [oneUse, setOneUse] = useState(false);
  const [expiresAt, setExpiresAt] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [link, setLink] = useState('');
  const [copied, setCopied] = useState(false);

  const handleCreateLink = async () => {
    setLoading(true);
    setError('');

    try {
      const nonce = localStorage.getItem(`nonce_${peer.public_key}`);
      const result = await api.createShareLink(peer.id, {
        one_use: oneUse,
        expires_at: expiresAt ? new Date(expiresAt).toISOString() : null,
      });

      const base = `${window.location.origin}/config/${result.token}`;
      setLink(`${base}${peer.is_e2e && nonce ? `#${nonce}` : ''}`);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = async () => {
    await navigator.clipboard.writeText(link);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1800);
  };

  return (
    <div className="modal-backdrop">
      <div className="modal-panel">
        <div className="flex items-start justify-between gap-4 border-b border-[var(--border)] px-6 py-5">
          <div className="space-y-2">
            <span className="eyebrow">Shared Config Link</span>
            <h2 className="text-2xl font-black tracking-tight">{peer.name}</h2>
            <p className="text-sm text-[var(--muted)]">
              The token lives in the URL path. If this device uses browser-side encryption, the decrypting nonce stays in the `#fragment`.
            </p>
          </div>
          <button type="button" onClick={onClose} className="ghost-button" aria-label="Close">
            <X size={18} />
          </button>
        </div>

        <div className="space-y-5 px-6 py-6">
          <label className="flex items-center gap-3 rounded-2xl border border-[var(--border)] bg-[var(--surface-soft)] px-4 py-3 text-sm font-medium">
            <input type="checkbox" checked={oneUse} onChange={(event) => setOneUse(event.target.checked)} />
            <span>Allow this link to be used exactly once</span>
          </label>

          <div className="space-y-2">
            <label className="field-label">Expiration</label>
            <input
              type="datetime-local"
              className="input-field"
              value={expiresAt}
              onChange={(event) => setExpiresAt(event.target.value)}
            />
          </div>

          {error && <div className="error-banner">{error}</div>}

          {!link ? (
            <button type="button" onClick={handleCreateLink} disabled={loading} className="primary-button justify-center">
              {loading ? <Loader2 className="animate-spin" size={18} /> : <Link2 size={18} />}
              <span>{loading ? 'Creating link…' : 'Create share link'}</span>
            </button>
          ) : (
            <div className="space-y-4">
              <div className="info-tile">
                <strong>Share URL</strong>
                <code className="mt-2 block break-all text-xs">{link}</code>
              </div>
              <button type="button" onClick={handleCopy} className="secondary-button justify-center">
                <Copy size={16} />
                <span>{copied ? 'Copied' : 'Copy link'}</span>
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function EditPeerModal({ peer, isAdmin, onClose, onSave }) {
  const [form, setForm] = useState({
    name: peer.name,
    assigned_ips: peer.assigned_ips,
    static_endpoint: peer.static_endpoint || '',
    keepalive: peer.keepalive ? String(peer.keepalive) : '',
    expires_at: peer.expires_at ? new Date(peer.expires_at).toISOString().slice(0, 16) : '',
    traffic_upload_bps: peer.traffic_upload_bps ? String(peer.traffic_upload_bps) : '',
    traffic_download_bps: peer.traffic_download_bps ? String(peer.traffic_download_bps) : '',
    traffic_latency_ms: peer.traffic_latency_ms ? String(peer.traffic_latency_ms) : '',
  });

  const submit = async (event) => {
    event.preventDefault();
    await onSave(peer.id, {
      name: form.name,
      ...(isAdmin ? { assigned_ips: form.assigned_ips } : {}),
      static_endpoint: form.static_endpoint,
      keepalive: form.keepalive.trim() === '' ? 0 : Number.parseInt(form.keepalive, 10),
      expires_at: form.expires_at ? new Date(form.expires_at).toISOString() : null,
      ...(isAdmin ? {
        traffic_shaper: {
          upload_bps: parseNumberField(form.traffic_upload_bps),
          download_bps: parseNumberField(form.traffic_download_bps),
          latency_ms: parseNumberField(form.traffic_latency_ms),
        },
      } : {}),
    });
  };

  return (
    <div className="modal-backdrop">
      <div className="modal-panel">
        <div className="flex items-start justify-between gap-4 border-b border-[var(--border)] px-6 py-5">
          <div className="space-y-2">
            <span className="eyebrow">Edit Peer</span>
            <h2 className="text-2xl font-black tracking-tight">{peer.name}</h2>
          </div>
          <button type="button" onClick={onClose} className="ghost-button" aria-label="Close">
            <X size={18} />
          </button>
        </div>

        <form onSubmit={submit} className="space-y-5 px-6 py-6">
          <div className="space-y-2">
            <label className="field-label">Name</label>
            <input className="input-field" value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} />
          </div>

          {isAdmin && (
            <div className="space-y-2">
              <label className="field-label">Assigned IPs</label>
              <input className="input-field font-mono text-sm" value={form.assigned_ips} onChange={(event) => setForm({ ...form, assigned_ips: event.target.value })} />
            </div>
          )}

          <div className="grid gap-5 sm:grid-cols-2">
            <div className="space-y-2">
              <label className="field-label">Static Endpoint</label>
              <input className="input-field" value={form.static_endpoint} onChange={(event) => setForm({ ...form, static_endpoint: event.target.value })} />
            </div>
            <div className="space-y-2">
              <label className="field-label">Keepalive</label>
              <input className="input-field" type="number" min="0" placeholder="Blank disables it" value={form.keepalive} onChange={(event) => setForm({ ...form, keepalive: event.target.value })} />
            </div>
          </div>

          <div className="space-y-2">
            <label className="field-label">Expiration</label>
            <input className="input-field" type="datetime-local" value={form.expires_at} onChange={(event) => setForm({ ...form, expires_at: event.target.value })} />
          </div>

          {isAdmin && (
            <div className="space-y-3 rounded-3xl border border-[var(--border)] bg-[var(--surface-soft)] p-4">
              <div>
                <span className="eyebrow">Traffic Shaper</span>
                <p className="mt-2 text-sm text-[var(--muted)]">Set per-peer limits live through the daemon API. Leave a field blank or zero to disable that dimension.</p>
              </div>
              <div className="grid gap-5 sm:grid-cols-3">
                <div className="space-y-2">
                  <label className="field-label">Upload bps</label>
                  <input className="input-field" type="number" min="0" placeholder="0" value={form.traffic_upload_bps} onChange={(event) => setForm({ ...form, traffic_upload_bps: event.target.value })} />
                </div>
                <div className="space-y-2">
                  <label className="field-label">Download bps</label>
                  <input className="input-field" type="number" min="0" placeholder="0" value={form.traffic_download_bps} onChange={(event) => setForm({ ...form, traffic_download_bps: event.target.value })} />
                </div>
                <div className="space-y-2">
                  <label className="field-label">Latency ms</label>
                  <input className="input-field" type="number" min="0" placeholder="0" value={form.traffic_latency_ms} onChange={(event) => setForm({ ...form, traffic_latency_ms: event.target.value })} />
                </div>
              </div>
            </div>
          )}

          <div className="flex flex-col-reverse gap-3 border-t border-[var(--border)] pt-4 sm:flex-row sm:justify-end">
            <button type="button" onClick={onClose} className="ghost-button justify-center">Cancel</button>
            <button type="submit" className="primary-button justify-center">Save changes</button>
          </div>
        </form>
      </div>
    </div>
  );
}

export default function PeersTab({ isAdmin, onSelectPeer }) {
  const [peers, setPeers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [pinging, setPinging] = useState(null);
  const [editingPeer, setEditingPeer] = useState(null);
  const [sharingPeer, setSharingPeer] = useState(null);

  useEffect(() => {
    fetchPeers();
    const intervalId = window.setInterval(fetchPeers, 15000);
    return () => window.clearInterval(intervalId);
  }, []);

  const fetchPeers = async () => {
    try {
      const data = await api.getPeers();
      setPeers(data || []);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleUpdate = async (id, data) => {
    try {
      await api.updatePeer(id, data);
      setEditingPeer(null);
      await fetchPeers();
    } catch (err) {
      alert(err.message);
    }
  };

  const handleToggle = async (peer) => {
    try {
      await api.updatePeer(peer.id, { enabled: !peer.enabled });
      await fetchPeers();
    } catch (err) {
      alert(err.message);
    }
  };

  const handlePing = async (id) => {
    setPinging(id);
    try {
      const res = await api.pingPeer(id);
      alert(`Ping result: ${res.received}/${res.transmitted} replies, average RTT ${res.round_trip_ms?.[0]?.toFixed(2) || 'N/A'} ms`);
    } catch (err) {
      alert(`Ping failed: ${err.message}`);
    } finally {
      setPinging(null);
    }
  };

  const handleDelete = async (id) => {
    if (!confirm('Delete device?')) return;
    try {
      await api.deletePeer(id);
      await fetchPeers();
    } catch (err) {
      alert(err.message);
    }
  };

  const groups = useMemo(() => peers.reduce((accumulator, peer) => {
    const group = peer.username || 'Unknown';
    if (!accumulator[group]) accumulator[group] = [];
    accumulator[group].push(peer);
    return accumulator;
  }, {}), [peers]);

  if (loading) {
    return (
      <div className="state-shell py-24">
        <Loader2 className="animate-spin text-[var(--accent)]" size={36} />
        <p className="text-sm text-[var(--muted)]">Loading peers…</p>
      </div>
    );
  }

  return (
    <div className="space-y-10">
      {Object.entries(groups).map(([username, userPeers]) => (
        <section key={username} className="space-y-4">
          <div className="flex items-center gap-3 px-1">
            <div className="brand-badge">
              <User size={16} />
            </div>
            <div>
              <span className="eyebrow">Owner</span>
              <h3 className="text-lg font-black tracking-tight">{username}</h3>
            </div>
          </div>

          <div className="grid gap-4">
            {userPeers.map((peer) => {
              const hasNonce = !!localStorage.getItem(`nonce_${peer.public_key}`);
              const canRevealConfig = peer.has_private_key_material && (!peer.is_e2e || hasNonce);
              const canShareConfig = canRevealConfig;
              const hasShaper = (peer.traffic_upload_bps || 0) > 0 || (peer.traffic_download_bps || 0) > 0 || (peer.traffic_latency_ms || 0) > 0;

              return (
                <article key={peer.id} className={`peer-card ${peer.enabled ? '' : 'peer-card-disabled'}`}>
                  <div className="flex flex-col gap-6">
                    <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                      <div className="flex gap-4">
                        <div className="peer-icon">
                          <Smartphone size={24} />
                        </div>
                        <div className="space-y-3">
                          <div className="flex flex-wrap items-center gap-2">
                            <h4 className="text-xl font-black tracking-tight">{peer.name}</h4>
                            {!peer.enabled && <span className="status-chip status-chip-danger">Disabled</span>}
                            {peer.is_manual_key && <span className="status-chip status-chip-muted"><Lock size={12} /> Manual key</span>}
                            {peer.keepalive > 0 && <span className="status-chip">Keepalive {peer.keepalive}s</span>}
                            {hasShaper && <span className="status-chip">Shaped</span>}
                          </div>
                          <div className="space-y-1">
                            <p className="font-mono text-sm text-[var(--accent)]">{peer.assigned_ips}</p>
                            <div className="flex flex-wrap gap-4 text-sm text-[var(--muted)]">
                              <span className="inline-flex items-center gap-1"><Activity size={14} /> {peer.has_handshake ? `Last handshake ${new Date(peer.last_handshake_time).toLocaleTimeString()}` : 'No handshake yet'}</span>
                              <span className="inline-flex items-center gap-1"><Globe size={14} /> {formatBytes((peer.transmit_bytes || 0) + (peer.receive_bytes || 0))} total</span>
                              {peer.expires_at && (
                                <span className="inline-flex items-center gap-1">
                                  Expires {new Date(peer.expires_at).toLocaleString()}
                                </span>
                              )}
                            </div>
                          </div>
                        </div>
                      </div>

                      <div className="flex flex-wrap gap-2 lg:justify-end">
                        <button type="button" onClick={() => handlePing(peer.id)} disabled={pinging === peer.id} className="ghost-button">
                          {pinging === peer.id ? <Loader2 className="animate-spin" size={16} /> : <Activity size={16} />}
                          <span>Ping</span>
                        </button>
                        <button type="button" onClick={() => setEditingPeer(peer)} className="ghost-button">
                          <Edit3 size={16} />
                          <span>Edit</span>
                        </button>
                        <button type="button" onClick={() => handleToggle(peer)} className="ghost-button">
                          {peer.enabled ? <Power size={16} /> : <PowerOff size={16} />}
                          <span>{peer.enabled ? 'Disable' : 'Enable'}</span>
                        </button>
                        <button
                          type="button"
                          onClick={() => canShareConfig ? setSharingPeer(peer) : null}
                          className={`ghost-button ${canShareConfig ? '' : 'ghost-button-disabled'}`}
                          title={canShareConfig ? 'Share config' : 'This browser cannot unlock a shareable config for this peer'}
                        >
                          <Link2 size={16} />
                          <span>Share</span>
                        </button>
                        <button
                          type="button"
                          onClick={() => canRevealConfig ? onSelectPeer(peer) : null}
                          className={`primary-button ${canRevealConfig ? '' : 'primary-button-disabled'}`}
                          title={canRevealConfig ? 'Open config' : 'This browser cannot decrypt the stored config'}
                        >
                          <QrCode size={16} />
                          <span>Config</span>
                        </button>
                        <button type="button" onClick={() => handleDelete(peer.id)} className="ghost-button ghost-button-danger">
                          <Trash2 size={16} />
                          <span>Delete</span>
                        </button>
                      </div>
                    </div>

                    <div className="grid gap-4 xl:grid-cols-[1.2fr_0.8fr]">
                      <div className="traffic-panel">
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div>
                            <span className="eyebrow">Recent Traffic</span>
                            <h5 className="text-lg font-black tracking-tight">Short-term in-memory usage graph</h5>
                          </div>
                          <span className="text-sm text-[var(--muted)]">
                            {peer.traffic_history?.length || 0} samples
                          </span>
                        </div>
                        <TrafficSparkline history={peer.traffic_history || []} />
                        <div className="grid gap-3 sm:grid-cols-3">
                          <div className="stat-tile">
                            <span className="stat-label">Latest receive</span>
                            <strong>{formatBytes(peer.traffic_history?.at(-1)?.receive_delta || 0)}</strong>
                          </div>
                          <div className="stat-tile">
                            <span className="stat-label">Latest transmit</span>
                            <strong>{formatBytes(peer.traffic_history?.at(-1)?.transmit_delta || 0)}</strong>
                          </div>
                          <div className="stat-tile">
                            <span className="stat-label">Latest combined</span>
                            <strong>{formatBytes(peer.traffic_history?.at(-1)?.total_delta || 0)}</strong>
                          </div>
                        </div>
                      </div>

                      <div className="grid gap-3">
                        <div className="stat-tile">
                          <span className="stat-label">Traffic shaper</span>
                          <strong>
                            Up {formatBps(peer.traffic_upload_bps)} · Down {formatBps(peer.traffic_download_bps)}
                            {(peer.traffic_latency_ms || 0) > 0 ? ` · +${peer.traffic_latency_ms} ms` : ''}
                          </strong>
                        </div>
                        {(isAdmin || peer.public_key) && (
                          <div className="stat-tile">
                            <span className="stat-label">Public key</span>
                            <strong className="break-all font-mono text-sm">{peer.public_key || 'Hidden by policy'}</strong>
                          </div>
                        )}
                        {(peer.endpoint_ip || peer.static_endpoint) && (
                          <div className="stat-tile">
                            <span className="stat-label">Endpoint visibility</span>
                            <strong className="break-all font-mono text-sm">
                              {peer.static_endpoint ? `Static ${peer.static_endpoint}` : peer.endpoint_ip}
                            </strong>
                          </div>
                        )}
                        <div className="stat-tile">
                          <span className="stat-label">Config availability</span>
                          <strong>
                            {peer.has_private_key_material
                              ? (peer.is_e2e ? (hasNonce ? 'Unlocked in this browser' : 'Nonce missing in this browser') : 'Server-managed')
                              : 'Private key not retained'}
                          </strong>
                        </div>
                      </div>
                    </div>
                  </div>
                </article>
              );
            })}
          </div>
        </section>
      ))}

      {editingPeer && (
        <EditPeerModal
          peer={editingPeer}
          isAdmin={isAdmin}
          onClose={() => setEditingPeer(null)}
          onSave={handleUpdate}
        />
      )}

      {sharingPeer && (
        <ShareModal peer={sharingPeer} onClose={() => setSharingPeer(null)} />
      )}
    </div>
  );
}
