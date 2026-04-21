import { useEffect, useState } from 'react';
import { Check, Copy, Download, Loader2, QrCode, X } from 'lucide-react';
import { QRCodeSVG } from 'qrcode.react';
import { api } from '../lib/api';
import { decryptPrivateKey, hashNonce } from '../lib/crypto';
import { buildWireGuardConfig, downloadConfigFile, stripWGDirectives } from '../lib/config';

export default function ConfigModal({ peer, onClose }) {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [config, setConfig] = useState('');
  const [copied, setCopied] = useState(false);
  const [simpleView, setSimpleView] = useState(false);

  useEffect(() => {
    let cancelled = false;

    async function loadConfig() {
      setLoading(true);
      setError('');

      try {
        if (!peer.has_private_key_material) {
          throw new Error('This device has no stored private key material. Use the original bootstrap printout or a manual device-generated key instead.');
        }

        const [globalConfig, distributePeers] = await Promise.all([
          api.getPublicConfig(),
          api.getDistributePeers().catch(() => []),
        ]);
        let privateKey = '';
        let presharedKey = '';
        let assignedIPs = peer.assigned_ips;

        if (peer.is_e2e) {
          const nonce = localStorage.getItem(`nonce_${peer.public_key}`);
          if (!nonce) {
            throw new Error('This browser does not have the local nonce needed to decrypt this config.');
          }

          const nonceHash = await hashNonce(nonce);
          const privateData = await api.getPeerPrivate(peer.id, nonceHash);
          try {
            privateKey = await decryptPrivateKey(privateData.encrypted_private_key, nonce);
          } catch {
            const aesKey = await api.getHMACNonce(nonce);
            privateKey = await decryptPrivateKey(privateData.encrypted_private_key, nonce, aesKey);
          }
          presharedKey = privateData.preshared_key;
          assignedIPs = privateData.assigned_ips;
        } else {
          const privateData = await api.getPeerPrivate(peer.id);
          privateKey = privateData.encrypted_private_key;
          presharedKey = privateData.preshared_key;
          assignedIPs = privateData.assigned_ips;
        }

        const myDistributePeers = distributePeers.filter((dp) => dp.public_key !== peer.public_key);
        const configText = buildWireGuardConfig({
          privateKey,
          assignedIPs,
          dns: globalConfig.client_dns,
          mtu: globalConfig.global_mtu,
          serverPublicKey: globalConfig.server_pubkey,
          endpoint: globalConfig.endpoints_visible === 'false' && !peer.is_owner ? 'HIDDEN' : globalConfig.server_endpoint,
          transport: globalConfig.default_transport,
          presharedKey,
          keepalive: peer.keepalive,
          enableIPv6: globalConfig.enable_client_ipv6,
          allowedIPs: globalConfig.client_allowed_ips,
          directiveTCP: globalConfig.client_config_tcp,
          directiveTURN: globalConfig.client_config_turn_url,
          directiveSkipVerifyTLS: globalConfig.client_config_skipverifytls,
          directiveURL: globalConfig.client_config_url,
          directiveControl: globalConfig.client_config_control_url,
          peerSyncEnabled: !!peer.peer_sync_enabled || globalConfig.peer_sync_mode === 'enabled',
          distributePeers: myDistributePeers,
        });

        if (!cancelled) {
          setConfig(configText);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err.message);
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    loadConfig();
    return () => {
      cancelled = true;
    };
  }, [peer]);

  const copyToClipboard = async () => {
    await navigator.clipboard.writeText(simpleView ? stripWGDirectives(config) : config);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 2000);
  };

  const displayedConfig = simpleView ? stripWGDirectives(config) : config;
  const hasDirectiveLines = config.includes('#!');

  return (
    <div className="modal-backdrop">
      <div className="modal-panel modal-panel-wide">
        <div className="flex items-start justify-between gap-4 border-b border-[var(--border)] px-6 py-5">
          <div className="space-y-2">
            <span className="eyebrow">Device Config</span>
            <h2 className="text-2xl font-black tracking-tight">{peer.name}</h2>
            <p className="text-sm text-[var(--muted)]">Scan the QR code, copy the text, or download a `.conf` file directly.</p>
          </div>
          <button type="button" onClick={onClose} className="ghost-button" aria-label="Close">
            <X size={18} />
          </button>
        </div>

        <div className="space-y-6 px-6 py-6">
          {loading ? (
            <div className="state-shell py-16">
              <Loader2 className="animate-spin text-[var(--accent)]" size={32} />
              <p className="text-sm text-[var(--muted)]">Unlocking configuration…</p>
            </div>
          ) : error ? (
            <div className="error-banner">
              {error}
            </div>
          ) : (
            <>
              <div className="grid gap-6 lg:grid-cols-[320px_1fr]">
                <div className="card p-4">
                  <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-[var(--muted)]">
                    <QrCode size={16} />
                    <span>QR import</span>
                  </div>
                  <div className="rounded-3xl bg-white p-4">
                    <QRCodeSVG value={config} size={256} className="mx-auto h-auto w-full" />
                  </div>
                </div>

                <div className="space-y-4">
                  <div className="grid gap-4 sm:grid-cols-2">
                    <div className="stat-tile">
                      <span className="stat-label">Public key</span>
                      <strong className="break-all font-mono text-sm">{peer.public_key || 'Hidden'}</strong>
                    </div>
                    <div className="stat-tile">
                      <span className="stat-label">Tunnel IPs</span>
                      <strong className="break-all font-mono text-sm">{peer.assigned_ips}</strong>
                    </div>
                  </div>

                  <div className="flex flex-wrap gap-2">
                    {hasDirectiveLines && (
                      <label className="ghost-button gap-2">
                        <input type="checkbox" checked={simpleView} onChange={(event) => setSimpleView(event.target.checked)} />
                        <span>Show simple config only</span>
                      </label>
                    )}
                    <button type="button" onClick={copyToClipboard} className="secondary-button">
                      {copied ? <Check size={16} /> : <Copy size={16} />}
                      <span>{copied ? 'Copied' : 'Copy'}</span>
                    </button>
                    <button type="button" onClick={() => downloadConfigFile(peer.name, displayedConfig)} className="primary-button">
                      <Download size={16} />
                      <span>Download `.conf`</span>
                    </button>
                  </div>

                  <pre className="config-block">{displayedConfig}</pre>
                </div>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
