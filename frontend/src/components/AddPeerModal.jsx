import { useEffect, useState } from 'react';
import { Loader2, X } from 'lucide-react';
import { api } from '../lib/api';
import { encryptPrivateKey, generateKeyPair, generateNonce, hashNonce } from '../lib/crypto';

export default function AddPeerModal({ onClose, onSuccess }) {
  const [name, setName] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [globalConfig, setGlobalConfig] = useState({});
  const [manualPublicKey, setManualPublicKey] = useState('');
  const [staticEndpoint, setStaticEndpoint] = useState('');
  const [keepalive, setKeepalive] = useState('');
  const [requestedIP, setRequestedIP] = useState('');
  const [expiresAt, setExpiresAt] = useState('');
  const [peerSyncEnabled, setPeerSyncEnabled] = useState(false);

  useEffect(() => {
    api.getPublicConfig().then(setGlobalConfig).catch(() => {});
  }, []);

  const handleSubmit = async (event) => {
    event.preventDefault();
    setLoading(true);
    setError('');

    try {
      let publicKey = manualPublicKey.trim();
      let encryptedPrivateKey = '';
      let nonceHash = '';

      const e2eEnabled = globalConfig.e2e_encryption_enabled === 'true';

      if (!publicKey && e2eEnabled) {
        const keys = await generateKeyPair();
        publicKey = keys.publicKey;

        const nonce = generateNonce();
        encryptedPrivateKey = await encryptPrivateKey(keys.privateKey, nonce);
        nonceHash = await hashNonce(nonce);
        localStorage.setItem(`nonce_${publicKey}`, nonce);
      }

      const keepaliveValue = keepalive.trim() === '' ? 0 : Number.parseInt(keepalive, 10);

      const result = await api.createPeer({
        name,
        public_key: publicKey,
        nonce_hash: nonceHash,
        encrypted_private_key: encryptedPrivateKey,
        requested_ip: requestedIP.trim(),
        keepalive: Number.isNaN(keepaliveValue) ? 0 : keepaliveValue,
        static_endpoint: staticEndpoint.trim(),
        peer_sync_enabled: peerSyncEnabled,
        is_manual_key: Boolean(publicKey && manualPublicKey.trim()),
        expires_at: expiresAt ? new Date(expiresAt).toISOString() : null,
      });

      onSuccess({
        ...result,
        name,
        public_key: result.public_key || publicKey,
      });
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const showManualInput = globalConfig.allow_custom_private_key === 'true';
  const peerSyncMode = globalConfig.peer_sync_mode || 'disabled';

  return (
    <div className="modal-backdrop">
      <div className="modal-panel modal-panel-wide">
        <div className="flex items-start justify-between gap-4 border-b border-[var(--border)] px-6 py-5">
          <div className="space-y-2">
            <span className="eyebrow">New Device</span>
            <h2 className="text-2xl font-black tracking-tight">Create a new WireGuard client</h2>
            <p className="text-sm text-[var(--muted)]">
              Leave keepalive blank unless this client needs dependable inbound reachability through NAT.
            </p>
          </div>
          <button type="button" onClick={onClose} className="ghost-button" aria-label="Close">
            <X size={18} />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-6 px-6 py-6">
          <div className="grid gap-5 md:grid-cols-2">
            <div className="space-y-2 md:col-span-2">
              <label className="field-label">Device Name</label>
              <input
                type="text"
                required
                autoFocus
                className="input-field"
                placeholder="iPhone 15, MacBook Pro, branch office router"
                value={name}
                onChange={(event) => setName(event.target.value)}
              />
            </div>

            <div className="info-tile md:col-span-2">
              <strong>Storage mode</strong>
              <p className="text-sm text-[var(--muted)]">
                {globalConfig.e2e_encryption_enabled === 'true'
                  ? 'Private keys are browser-encrypted before they reach the server.'
                  : 'Private keys are managed server-side so you can reopen configs later without a browser nonce.'}
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={() => setShowAdvanced((current) => !current)}
            className="secondary-button"
          >
            <span>{showAdvanced ? 'Hide advanced options' : 'Show advanced options'}</span>
          </button>

          {showAdvanced && (
            <div className="grid gap-5 rounded-3xl border border-[var(--border)] bg-[var(--surface-soft)] p-5 md:grid-cols-2">
              {showManualInput && (
                <div className="space-y-2 md:col-span-2">
                  <label className="field-label">Manual Public Key</label>
                  <input
                    type="text"
                    className="input-field font-mono text-sm"
                    placeholder="Optional Base64 public key"
                    value={manualPublicKey}
                    onChange={(event) => setManualPublicKey(event.target.value)}
                  />
                  <p className="text-xs text-[var(--muted)]">
                    Use this when the device generated its own keypair and you do not want the UI to retain private material.
                  </p>
                </div>
              )}

              <div className="space-y-2">
                <label className="field-label">Static Endpoint</label>
                <input
                  type="text"
                  className="input-field"
                  placeholder="Optional host:port override"
                  value={staticEndpoint}
                  onChange={(event) => setStaticEndpoint(event.target.value)}
                />
              </div>

              <div className="space-y-2">
                <label className="field-label">Keepalive</label>
                <input
                  type="number"
                  className="input-field"
                  min="0"
                  placeholder="Leave blank for none"
                  value={keepalive}
                  onChange={(event) => setKeepalive(event.target.value)}
                />
              </div>

              <div className="space-y-2">
                <label className="field-label">Custom Tunnel IPs</label>
                <input
                  type="text"
                  className="input-field"
                  placeholder="Admin-only override"
                  value={requestedIP}
                  onChange={(event) => setRequestedIP(event.target.value)}
                />
              </div>

              <div className="space-y-2">
                <label className="field-label">Expiration</label>
                <input
                  type="datetime-local"
                  className="input-field"
                  value={expiresAt}
                  onChange={(event) => setExpiresAt(event.target.value)}
                />
              </div>

              {peerSyncMode === 'opt_in' && (
                <div className="space-y-2 md:col-span-2">
                  <label className="flex items-center gap-3 text-sm font-medium">
                    <input type="checkbox" checked={peerSyncEnabled} onChange={(event) => setPeerSyncEnabled(event.target.checked)} />
                    <span>Opt this client into peer syncing / P2P discovery</span>
                  </label>
                  <p className="text-xs text-[var(--muted)]">Adds the `#!Control=` directive for uwgsocks clients and allows this peer to use the tunnel-only peer sync controller.</p>
                </div>
              )}
            </div>
          )}

          {error && (
            <div className="error-banner">
              {error}
            </div>
          )}

          <div className="flex flex-col-reverse gap-3 border-t border-[var(--border)] pt-4 sm:flex-row sm:justify-end">
            <button type="button" onClick={onClose} className="ghost-button justify-center">
              Cancel
            </button>
            <button type="submit" disabled={loading} className="primary-button justify-center">
              {loading ? <Loader2 className="animate-spin" size={18} /> : null}
              <span>{loading ? 'Creating device…' : 'Create device'}</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
