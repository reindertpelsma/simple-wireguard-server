import { useEffect, useMemo, useState } from 'react';
import {
  Activity,
  ChevronDown,
  ChevronUp,
  Copy,
  Edit3,
  Globe,
  Link2,
  Loader2,
  Lock,
  Power,
  PowerOff,
  QrCode,
  Search,
  Share2,
  Smartphone,
  Trash2,
  User,
  X,
} from 'lucide-react';
import { api } from '../lib/api';
import { formatBytes } from '../lib/config';
import TrafficSparkline from './TrafficSparkline';

// Values stored and sent to the daemon are bytes/sec; display as bits/sec (network convention).
function formatBps(bytesPerSec) {
  const bps = Number(bytesPerSec || 0) * 8;
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

const BANDWIDTH_UNITS = [
  { label: 'bps',  factor: 1 / 8 },
  { label: 'Kbps', factor: 1000 / 8 },
  { label: 'Mbps', factor: 1_000_000 / 8 },
  { label: 'Gbps', factor: 1_000_000_000 / 8 },
  { label: 'B/s',  factor: 1 },
  { label: 'KB/s', factor: 1_000 },
  { label: 'MB/s', factor: 1_000_000 },
  { label: 'GB/s', factor: 1_000_000_000 },
];

function bytesToDisplay(bytesPerSec) {
  if (!bytesPerSec || bytesPerSec <= 0) return { displayValue: '', unit: 'Mbps' };
  const bitsPerSec = bytesPerSec * 8;
  if (bitsPerSec >= 1_000_000_000) return { displayValue: String(+(bitsPerSec / 1_000_000_000).toPrecision(4)), unit: 'Gbps' };
  if (bitsPerSec >= 1_000_000) return { displayValue: String(+(bitsPerSec / 1_000_000).toPrecision(4)), unit: 'Mbps' };
  if (bitsPerSec >= 1_000) return { displayValue: String(+(bitsPerSec / 1_000).toPrecision(4)), unit: 'Kbps' };
  return { displayValue: String(bitsPerSec), unit: 'bps' };
}

function BandwidthInput({ initialValue, onChange }) {
  const init = bytesToDisplay(initialValue);
  const [displayValue, setDisplayValue] = useState(init.displayValue);
  const [unit, setUnit] = useState(init.unit);

  const emit = (val, u) => {
    const unitDef = BANDWIDTH_UNITS.find((x) => x.label === u);
    const bytes = parseFloat(val) * (unitDef?.factor ?? 1);
    onChange(isNaN(bytes) || bytes < 0 ? 0 : Math.round(bytes));
  };

  const handleValueChange = (e) => {
    setDisplayValue(e.target.value);
    emit(e.target.value, unit);
  };

  const handleUnitChange = (e) => {
    setUnit(e.target.value);
    emit(displayValue, e.target.value);
  };

  return (
    <div className="bandwidth-input">
      <input
        type="number"
        min="0"
        step="any"
        placeholder="0 = unlimited"
        className="input-field min-w-0"
        value={displayValue}
        onChange={handleValueChange}
      />
      <select className="input-field bandwidth-input-unit px-2" value={unit} onChange={handleUnitChange}>
        {BANDWIDTH_UNITS.map((u) => (
          <option key={u.label} value={u.label}>{u.label}</option>
        ))}
      </select>
    </div>
  );
}

function parseNumberField(value) {
  const text = String(value || '').trim();
  if (!text) return 0;
  return Number.parseInt(text, 10) || 0;
}

function formatTransportState(value) {
  switch (value) {
    case 'NotConnOriented':
      return 'NotConnOriented';
    case 'DialEndpoint':
      return 'DialEndpoint';
    case 'ConnEstablished':
      return 'ConnEstablished';
    default:
      return value || '';
  }
}

function transportStateChipClass(value) {
  switch (value) {
    case 'ConnEstablished':
      return 'status-chip';
    case 'DialEndpoint':
      return 'status-chip status-chip-muted';
    default:
      return 'status-chip status-chip-danger';
  }
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

function EditPeerModal({ peer, isAdmin, globalConfig, onClose, onSave }) {
  const peerSyncMode = globalConfig?.peer_sync_mode || 'disabled';
  const [form, setForm] = useState({
    name: peer.name,
    groups: peer.groups || peer.tags || '',
    assigned_ips: peer.assigned_ips,
    static_endpoint: peer.static_endpoint || '',
    keepalive: peer.keepalive ? String(peer.keepalive) : '',
    expires_at: peer.expires_at ? new Date(peer.expires_at).toISOString().slice(0, 16) : '',
    traffic_upload_bps: peer.traffic_upload_bps || 0,
    traffic_download_bps: peer.traffic_download_bps || 0,
    traffic_latency_ms: peer.traffic_latency_ms ? String(peer.traffic_latency_ms) : '',
    is_distribute: peer.is_distribute || false,
    distribute_endpoint: peer.distribute_endpoint || '',
    peer_sync_enabled: peer.peer_sync_enabled || false,
    mesh_trust: peer.mesh_trust || 'untrusted',
  });

  const submit = async (event) => {
    event.preventDefault();
    await onSave(peer.id, {
      name: form.name,
      ...(isAdmin ? { groups: form.groups } : {}),
      ...(isAdmin ? { assigned_ips: form.assigned_ips } : {}),
      static_endpoint: form.static_endpoint,
      keepalive: form.keepalive.trim() === '' ? 0 : Number.parseInt(form.keepalive, 10),
      expires_at: form.expires_at ? new Date(form.expires_at).toISOString() : null,
      ...(isAdmin ? {
        traffic_shaper: {
          upload_bps: form.traffic_upload_bps,
          download_bps: form.traffic_download_bps,
          latency_ms: parseNumberField(form.traffic_latency_ms),
        },
        is_distribute: form.is_distribute,
        distribute_endpoint: form.distribute_endpoint,
        peer_sync_enabled: form.peer_sync_enabled,
        mesh_trust: form.mesh_trust,
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

          {isAdmin && (
            <div className="space-y-2">
              <label className="field-label">Additional groups</label>
              <input className="input-field" placeholder="staff, lab" value={form.groups} onChange={(event) => setForm({ ...form, groups: event.target.value })} />
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
                <p className="mt-2 text-sm text-[var(--muted)]">
                  Limits are applied live via the daemon API. The daemon stores values as bytes/sec internally — select your preferred unit and the conversion is handled automatically.
                  Zero means unlimited. <em>Changes only affect new connections; existing connections keep the previous limit until they reconnect.</em>
                </p>
              </div>
              <div className="grid gap-5 sm:grid-cols-2">
                <div className="space-y-2">
                  <label className="field-label">Upload limit</label>
                  <BandwidthInput initialValue={form.traffic_upload_bps} onChange={(bps) => setForm((f) => ({ ...f, traffic_upload_bps: bps }))} />
                </div>
                <div className="space-y-2">
                  <label className="field-label">Download limit</label>
                  <BandwidthInput initialValue={form.traffic_download_bps} onChange={(bps) => setForm((f) => ({ ...f, traffic_download_bps: bps }))} />
                </div>
              </div>
              <div className="space-y-2">
                <label className="field-label">Target latency (ms)</label>
                <input className="input-field" type="number" min="0" placeholder="15 (default)" value={form.traffic_latency_ms} onChange={(event) => setForm({ ...form, traffic_latency_ms: event.target.value })} />
              </div>
            </div>
          )}

          {isAdmin && (
            <div className="space-y-3 rounded-3xl border border-[var(--border)] bg-[var(--surface-soft)] p-4">
              <div>
                <span className="eyebrow">Distribute Peer</span>
                <p className="mt-2 text-sm text-[var(--muted)]">When enabled, this peer is included in all other clients' downloaded configs as an extra [Peer] block for direct connection.</p>
              </div>
              <label className="flex items-center gap-3 text-sm font-medium">
                <input type="checkbox" checked={form.is_distribute} onChange={(event) => setForm({ ...form, is_distribute: event.target.checked })} />
                <span>Mark as distribute peer</span>
              </label>
              {peerSyncMode === 'opt_in' && (
                <label className="flex items-center gap-3 text-sm font-medium">
                  <input type="checkbox" checked={form.peer_sync_enabled} onChange={(event) => setForm({ ...form, peer_sync_enabled: event.target.checked })} />
                  <span>Opt this client into peer syncing / P2P discovery</span>
                </label>
              )}
              {form.is_distribute && (
                <div className="space-y-4">
                  <div className="space-y-2">
                    <label className="field-label">Distribute endpoint override</label>
                    <input
                      className="input-field font-mono text-sm"
                      placeholder="Auto-detected from last handshake (leave blank)"
                      value={form.distribute_endpoint}
                      onChange={(event) => setForm({ ...form, distribute_endpoint: event.target.value })}
                    />
                    <p className="text-xs text-[var(--muted)]">Override the endpoint advertised in other clients' configs. Leave blank to use the last-seen IP.</p>
                  </div>
                  {peerSyncMode !== 'disabled' && (
                    <div className="space-y-2">
                      <label className="field-label">Mesh trust</label>
                      <select className="input-field" value={form.mesh_trust} onChange={(event) => setForm({ ...form, mesh_trust: event.target.value })}>
                        <option value="untrusted">Untrusted</option>
                        <option value="trusted_always">Trusted always</option>
                        <option value="trusted_if_dynamic_acls">Trusted only if the other peer has dynamic ACLs</option>
                      </select>
                      <p className="text-xs text-[var(--muted)]">Controls how uwgsocks relay fallback treats this distributed peer. It trusts the WireGuard endpoint behavior, not the routed networks behind it.</p>
                    </div>
                  )}
                </div>
              )}
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

export default function PeersTab({ isAdmin, currentUsername, onSelectPeer }) {
  const [peers, setPeers] = useState([]);
  const [globalConfig, setGlobalConfig] = useState({});
  const [loading, setLoading] = useState(true);
  const [pinging, setPinging] = useState(null);
  const [editingPeer, setEditingPeer] = useState(null);
  const [sharingPeer, setSharingPeer] = useState(null);
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(1);
  const [expandedPeers, setExpandedPeers] = useState({});

  const pageSize = 25;

  useEffect(() => {
    fetchPeers();
    const intervalId = window.setInterval(fetchPeers, 15000);
    return () => window.clearInterval(intervalId);
  }, []);

  const fetchPeers = async () => {
    try {
      const [data, cfg] = await Promise.all([
        api.getPeers(),
        api.getPublicConfig().catch(() => ({})),
      ]);
      setPeers(data || []);
      setGlobalConfig(cfg || {});
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

  const filteredPeers = useMemo(() => {
    const query = search.trim().toLowerCase();
    if (!query) return peers;
    return peers.filter((peer) => {
      const haystack = [
        peer.name,
        peer.username,
        peer.assigned_ips,
        peer.public_key,
        peer.static_endpoint,
        peer.endpoint_ip,
        peer.transport_name,
        peer.transport_endpoint,
      ]
        .filter(Boolean)
        .join(' ')
        .toLowerCase();
      return haystack.includes(query);
    });
  }, [peers, search]);

  const totalPages = Math.max(1, Math.ceil(filteredPeers.length / pageSize));
  const pagedPeers = useMemo(() => {
    const start = (page - 1) * pageSize;
    return filteredPeers.slice(start, start + pageSize);
  }, [filteredPeers, page]);

  const groups = useMemo(() => {
    const map = pagedPeers.reduce((accumulator, peer) => {
      const group = peer.username || 'Unknown';
      if (!accumulator[group]) accumulator[group] = [];
      accumulator[group].push(peer);
      return accumulator;
    }, {});
    const entries = Object.entries(map);
    entries.sort(([a], [b]) => {
      if (a === currentUsername) return -1;
      if (b === currentUsername) return 1;
      return a.localeCompare(b);
    });
    return entries;
  }, [pagedPeers, currentUsername]);

  useEffect(() => {
    setPage(1);
  }, [search]);

  useEffect(() => {
    if (page > totalPages) {
      setPage(totalPages);
    }
  }, [page, totalPages]);

  const toggleExpanded = (peerId) => {
    setExpandedPeers((current) => ({ ...current, [peerId]: !current[peerId] }));
  };

  if (loading) {
    return (
      <div className="state-shell py-24">
        <Loader2 className="animate-spin text-[var(--accent)]" size={36} />
        <p className="text-sm text-[var(--muted)]">Loading peers…</p>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      <section className="panel p-5 sm:p-6">
        <div className="peer-toolbar">
          <div>
            <span className="eyebrow">Device Inventory</span>
            <h3 className="mt-2 text-2xl font-black tracking-tight">Search, filter, and inspect peer configs</h3>
            <p className="mt-2 text-sm text-[var(--muted)]">
              {filteredPeers.length} result{filteredPeers.length === 1 ? '' : 's'}
              {filteredPeers.length !== peers.length ? ` of ${peers.length}` : ''} · page {page} of {totalPages}
            </p>
          </div>
          <label className="peer-search">
            <Search size={16} />
            <input
              type="search"
              className="input-field"
              placeholder="Search owner, device, IP, public key, or config endpoint"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
            />
          </label>
        </div>
      </section>

      {groups.map(([username, userPeers]) => (
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

          <div className="peer-list">
            {userPeers.map((peer) => {
              const hasNonce = !!localStorage.getItem(`nonce_${peer.public_key}`);
              const canRevealConfig = peer.has_private_key_material && (!peer.is_e2e || hasNonce);
              const canShareConfig = canRevealConfig;
              const hasShaper = (peer.traffic_upload_bps || 0) > 0 || (peer.traffic_download_bps || 0) > 0 || (peer.traffic_latency_ms || 0) > 0;
              const hasTransportDetails = !!(peer.transport_name || peer.transport_state || peer.transport_endpoint || peer.transport_source_addr || peer.transport_carrier_remote_addr);
              const isExpanded = !!expandedPeers[peer.id];

              const canManage = peer.is_owner || isAdmin;

              return (
                <article key={peer.id} className={`peer-card ${peer.enabled ? '' : 'peer-card-disabled'}`}>
                  <div className="flex flex-col gap-5">
                    <div className="peer-row">
                      <button type="button" className="peer-row-summary" onClick={() => toggleExpanded(peer.id)} aria-expanded={isExpanded}>
                        <div className="peer-icon">
                          <Smartphone size={22} />
                        </div>
                        <div className="min-w-0 space-y-2">
                          <div className="flex flex-wrap items-center gap-2">
                            <h4 className="text-lg font-black tracking-tight">{peer.name}</h4>
                            {!peer.enabled && <span className="status-chip status-chip-danger">Disabled</span>}
                            {peer.is_distribute && <span className="status-chip"><Share2 size={12} /> Distribute</span>}
                            {peer.transport_state && (
                              <span className={transportStateChipClass(peer.transport_state)}>
                                {formatTransportState(peer.transport_state)}
                              </span>
                            )}
                            {hasShaper && <span className="status-chip">Shaped</span>}
                          </div>
                          <div className="flex flex-wrap gap-3 text-sm text-[var(--muted)]">
                            <span className="font-mono text-[var(--accent)]">{peer.assigned_ips}</span>
                            <span>{peer.username || 'Unknown owner'}</span>
                            <span>{peer.has_handshake ? `Handshake ${new Date(peer.last_handshake_time).toLocaleTimeString()}` : 'No handshake yet'}</span>
                            <span>{formatBytes((peer.transmit_bytes || 0) + (peer.receive_bytes || 0))} total</span>
                          </div>
                        </div>
                        <span className="peer-row-toggle">
                          {isExpanded ? <ChevronUp size={18} /> : <ChevronDown size={18} />}
                        </span>
                      </button>

                      <div className="peer-row-actions">
                        <button type="button" onClick={() => handlePing(peer.id)} disabled={pinging === peer.id} className="ghost-button">
                          {pinging === peer.id ? <Loader2 className="animate-spin" size={16} /> : <Activity size={16} />}
                          <span>Ping</span>
                        </button>
                        {canManage && (
                          <button type="button" onClick={() => setEditingPeer(peer)} className="ghost-button">
                            <Edit3 size={16} />
                            <span>Edit</span>
                          </button>
                        )}
                        {canManage && (
                          <button type="button" onClick={() => handleToggle(peer)} className="ghost-button">
                            {peer.enabled ? <Power size={16} /> : <PowerOff size={16} />}
                            <span>{peer.enabled ? 'Disable' : 'Enable'}</span>
                          </button>
                        )}
                        {canManage && (
                          <button
                            type="button"
                            onClick={() => canShareConfig ? setSharingPeer(peer) : null}
                            className={`ghost-button ${canShareConfig ? '' : 'ghost-button-disabled'}`}
                            title={canShareConfig ? 'Share config' : 'This browser cannot unlock a shareable config for this peer'}
                          >
                            <Link2 size={16} />
                            <span>Share</span>
                          </button>
                        )}
                        {canManage && (
                          <button
                            type="button"
                            onClick={() => canRevealConfig ? onSelectPeer(peer) : null}
                            className={`primary-button ${canRevealConfig ? '' : 'primary-button-disabled'}`}
                            title={canRevealConfig ? 'Open config' : 'This browser cannot decrypt the stored config'}
                          >
                            <QrCode size={16} />
                            <span>Config</span>
                          </button>
                        )}
                        {canManage && (
                          <button type="button" onClick={() => handleDelete(peer.id)} className="ghost-button ghost-button-danger">
                            <Trash2 size={16} />
                            <span>Delete</span>
                          </button>
                        )}
                      </div>
                    </div>

                    {isExpanded && (
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
                          {hasTransportDetails && (
                            <div className="stat-tile">
                              <span className="stat-label">Live transport</span>
                              <strong className="break-all font-mono text-sm">
                                {peer.transport_name || 'unknown'}
                                {peer.transport_state ? ` · ${formatTransportState(peer.transport_state)}` : ''}
                              </strong>
                              {(peer.transport_endpoint || peer.transport_source_addr || peer.transport_carrier_remote_addr) && (
                                <div className="mt-2 space-y-1 text-xs text-[var(--muted)]">
                                  {peer.transport_endpoint && <div>endpoint {peer.transport_endpoint}</div>}
                                  {peer.transport_source_addr && <div>source {peer.transport_source_addr}</div>}
                                  {peer.transport_carrier_remote_addr && <div>carrier {peer.transport_carrier_remote_addr}</div>}
                                </div>
                              )}
                            </div>
                          )}
                          {(isAdmin || peer.public_key) && (
                            <div className="stat-tile">
                              <span className="stat-label">Public key</span>
                              <strong className="break-all font-mono text-sm">{peer.public_key || 'Hidden by policy'}</strong>
                            </div>
                          )}
                          {(peer.endpoint_ip || peer.static_endpoint) && (
                            <div className="stat-tile">
                              <span className="stat-label">Bootstrap endpoint</span>
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
                    )}
                  </div>
                </article>
              );
            })}
          </div>
        </section>
      ))}

      {filteredPeers.length === 0 && (
        <div className="state-shell py-16">
          <Search size={28} className="text-[var(--accent)]" />
          <p className="text-sm text-[var(--muted)]">No peers matched this search.</p>
        </div>
      )}

      {filteredPeers.length > 0 && totalPages > 1 && (
        <section className="panel p-4 sm:p-5">
          <div className="pagination-row">
            <p className="text-sm text-[var(--muted)]">
              Showing {(page - 1) * pageSize + 1}-{Math.min(page * pageSize, filteredPeers.length)} of {filteredPeers.length}
            </p>
            <div className="flex flex-wrap gap-2">
              <button type="button" className="ghost-button" disabled={page === 1} onClick={() => setPage((current) => Math.max(1, current - 1))}>
                Previous
              </button>
              <button type="button" className="ghost-button" disabled={page === totalPages} onClick={() => setPage((current) => Math.min(totalPages, current + 1))}>
                Next
              </button>
            </div>
          </div>
        </section>
      )}

      {editingPeer && (
        <EditPeerModal
          peer={editingPeer}
          isAdmin={isAdmin}
          globalConfig={globalConfig}
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
