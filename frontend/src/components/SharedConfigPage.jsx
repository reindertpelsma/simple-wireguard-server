import { useEffect, useRef, useState } from 'react';
import { AlertTriangle, Copy, Download, Loader2, ShieldCheck } from 'lucide-react';
import { api } from '../lib/api';
import { decryptPrivateKey, hashNonce } from '../lib/crypto';
import { buildWireGuardConfig, downloadConfigFile, stripWGDirectives } from '../lib/config';
import ThemeToggle from './ThemeToggle';

export default function SharedConfigPage({ token, theme, onToggleTheme }) {
  const [config, setConfig] = useState('');
  const [status, setStatus] = useState('loading');
  const [message, setMessage] = useState('');
  const [meta, setMeta] = useState(null);
  const [copied, setCopied] = useState(false);
  const [simpleView, setSimpleView] = useState(false);
  const loadedTokenRef = useRef('');

  useEffect(() => {
    if (loadedTokenRef.current === token) {
      return undefined;
    }
    loadedTokenRef.current = token;

    let cancelled = false;

    async function load() {
      setStatus('loading');
      setMessage('');

      try {
        const nonce = window.location.hash.replace(/^#/, '');
        const nonceHash = nonce ? await hashNonce(nonce) : '';
        const shared = await api.getSharedConfig(token, nonceHash);

        let privateKey = shared.private_key;
        if (shared.is_e2e) {
          if (!nonce) {
            throw new Error('This link needs the decryption fragment after # to unlock the config.');
          }
          privateKey = await decryptPrivateKey(shared.encrypted_private_key, nonce);
        }

        const configText = buildWireGuardConfig({
          privateKey,
          assignedIPs: shared.assigned_ips,
          dns: shared.client_dns,
          mtu: shared.mtu,
          serverPublicKey: shared.server_public_key,
          endpoint: shared.server_endpoint,
          transport: shared.default_transport,
          presharedKey: shared.preshared_key,
          keepalive: shared.keepalive,
          enableIPv6: shared.enable_client_ipv6,
          allowedIPs: shared.client_allowed_ips,
          directiveTCP: shared.client_config_tcp,
          directiveTURN: shared.client_config_turn_url,
          directiveSkipVerifyTLS: shared.client_config_skipverifytls,
          directiveURL: shared.client_config_url,
          directiveControl: shared.client_config_control_url,
          peerSyncEnabled: !!shared.peer_sync_enabled,
          distributePeers: shared.distribute_peers,
        });

        if (!cancelled) {
          setMeta(shared);
          setConfig(configText);
          setStatus('ready');
        }
      } catch (error) {
        if (!cancelled) {
          setMessage(error.message || 'Failed to load this shared config.');
          setStatus('error');
        }
      }
    }

    load();
    return () => {
      cancelled = true;
    };
  }, [token]);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(simpleView ? stripWGDirectives(config) : config);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1800);
  };

  const displayedConfig = simpleView ? stripWGDirectives(config) : config;
  const hasDirectiveLines = config.includes('#!');

  return (
    <div className="app-shell px-4 py-6 sm:px-6">
      <div className="mx-auto flex w-full max-w-4xl justify-end">
        <ThemeToggle theme={theme} onToggle={onToggleTheme} />
      </div>

      <div className="mx-auto mt-6 w-full max-w-4xl">
        <div className="panel p-6 sm:p-8">
          <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
            <div className="space-y-3">
              <span className="eyebrow">Shared Config</span>
              <h1 className="text-3xl font-black tracking-tight sm:text-4xl">
                WireGuard setup, ready to import
              </h1>
              <p className="max-w-2xl text-sm text-[var(--muted)] sm:text-base">
                This page is self-authenticated by the link token. If the link owner enabled one-time access, opening it successfully consumes that share.
              </p>
            </div>
            <div className="status-badge">
              <ShieldCheck size={16} />
              <span>{meta?.one_use ? 'One-use link' : 'Reusable link'}</span>
            </div>
          </div>

          {status === 'loading' && (
            <div className="state-shell py-20">
              <Loader2 className="animate-spin text-[var(--accent)]" size={34} />
              <p className="text-sm text-[var(--muted)]">Unlocking the shared configuration…</p>
            </div>
          )}

          {status === 'error' && (
            <div className="state-shell py-16">
              <AlertTriangle size={34} className="text-[var(--danger)]" />
              <div className="space-y-2 text-center">
                <p className="text-lg font-bold">This shared link could not be opened</p>
                <p className="max-w-xl text-sm text-[var(--muted)]">{message}</p>
              </div>
            </div>
          )}

          {status === 'ready' && meta && (
            <div className="mt-8 space-y-6">
              <div className="grid gap-4 sm:grid-cols-3">
                <div className="stat-tile">
                  <span className="stat-label">Device</span>
                  <strong>{meta.peer_name}</strong>
                </div>
                <div className="stat-tile">
                  <span className="stat-label">Tunnel IPs</span>
                  <strong className="break-all font-mono text-sm">{meta.assigned_ips}</strong>
                </div>
                <div className="stat-tile">
                  <span className="stat-label">Endpoint</span>
                  <strong className="break-all font-mono text-sm">{meta.server_endpoint}</strong>
                </div>
              </div>

              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <h2 className="text-lg font-bold">Configuration file</h2>
                  <p className="text-sm text-[var(--muted)]">Downloads with a `.conf` filename for direct import into WireGuard clients.</p>
                </div>
                <div className="flex flex-wrap gap-2">
                  {hasDirectiveLines && (
                    <label className="ghost-button gap-2">
                      <input type="checkbox" checked={simpleView} onChange={(event) => setSimpleView(event.target.checked)} />
                      <span>Show simple config only</span>
                    </label>
                  )}
                  <button type="button" onClick={handleCopy} className="secondary-button">
                    <Copy size={16} />
                    <span>{copied ? 'Copied' : 'Copy'}</span>
                  </button>
                  <button type="button" onClick={() => downloadConfigFile(meta.download_name, displayedConfig)} className="primary-button">
                    <Download size={16} />
                    <span>Download `.conf`</span>
                  </button>
                </div>
              </div>

              <pre className="config-block">{displayedConfig}</pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
