import { useState, useEffect } from 'react';
import { api } from '../lib/api';
import { decryptPrivateKey, hashNonce } from '../lib/crypto';
import { X, Download, Copy, Check, Loader2 } from 'lucide-react';
import { QRCodeSVG } from 'qrcode.react';

export default function ConfigModal({ peer, onClose }) {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [config, setConfig] = useState('');
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    loadConfig();
  }, [peer]);

  const loadConfig = async () => {
    setLoading(true);
    setError('');
    try {
      const globalConfig = await api.getPublicConfig();
      let privateKey = 'REPLACE_ME_WITH_YOUR_PRIVATE_KEY';
      let psk = 'OPTIONAL_PSK';
      let assignedIPs = peer.assigned_ips;

      if (!peer.is_manual_key) {
        const nonce = localStorage.getItem(`nonce_${peer.public_key}`);
        if (!nonce) throw new Error('Local decryption key (nonce) missing for this device.');

        const nonceHash = await hashNonce(nonce);
        const privateData = await api.getPeerPrivate(peer.id, nonceHash);
        const aesKey = await api.getHMACNonce(nonce);
        privateKey = await decryptPrivateKey(privateData.encrypted_private_key, nonce, aesKey);
        psk = privateData.preshared_key;
        assignedIPs = privateData.assigned_ips;
      }

      const configLines = [
        '[Interface]',
        `PrivateKey = ${privateKey}`,
        `Address = ${assignedIPs}`,
        `DNS = ${globalConfig.client_dns || '1.1.1.1'}`,
        `MTU = ${globalConfig.global_mtu || '1420'}`,
        '',
        '[Peer]',
        `PublicKey = ${globalConfig.server_pubkey}`,
        `Endpoint = ${globalConfig.endpoints_visible === 'false' && !peer.is_owner ? 'HIDDEN' : globalConfig.server_endpoint}`,
        `AllowedIPs = 0.0.0.0/0, ::/0`,
        `PresharedKey = ${psk}`,
        `PersistentKeepalive = ${peer.keepalive || 25}`,
      ];

      setConfig(configLines.join('\n'));
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(config);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const downloadConfig = () => {
    const blob = new Blob([config], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${peer.name.replace(/\s+/g, '_')}.conf`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50">
      <div className="bg-gray-900 border border-gray-800 rounded-2xl w-full max-w-2xl max-h-[90vh] overflow-hidden flex flex-col">
        <div className="p-6 border-b border-gray-800 flex justify-between items-center bg-gray-900 sticky top-0">
          <div>
            <h2 className="text-2xl font-bold">{peer.name}</h2>
            <p className="text-gray-400 text-sm">Device Configuration</p>
          </div>
          <button onClick={onClose} className="text-gray-500 hover:text-white">
            <X size={20} />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-6">
          {loading ? (
            <div className="flex flex-col items-center justify-center py-20">
              <Loader2 className="animate-spin h-10 w-10 text-purple-500 mb-4" />
              <p className="text-gray-400">Decrypting configuration...</p>
            </div>
          ) : error ? (
            <div className="bg-red-500/10 border border-red-500/50 rounded-lg p-4 text-red-500 text-center">
              <p className="font-bold">Error</p>
              <p className="text-sm mt-1">{error}</p>
            </div>
          ) : (
            <div className="space-y-8">
              <div className="flex flex-col items-center bg-white p-4 rounded-xl">
                <QRCodeSVG value={config} size={256} />
              </div>

              <div className="grid grid-cols-1 gap-4">
                <div>
                  <span className="text-gray-500 text-xs font-bold uppercase tracking-widest block mb-1">Your Device Public Key</span>
                  <code className="bg-gray-950 p-2 rounded border border-gray-800 text-xs block truncate text-purple-400 font-mono">{peer.public_key}</code>
                </div>
              </div>

              <div className="space-y-2">
                <div className="flex justify-between items-center text-sm font-medium text-gray-400">
                  <span>Configuration File</span>
                  <div className="flex gap-4">
                    <button onClick={copyToClipboard} className="flex items-center gap-1 hover:text-white transition">
                      {copied ? <Check size={14} /> : <Copy size={14} />} {copied ? 'Copied' : 'Copy'}
                    </button>
                    <button onClick={downloadConfig} className="flex items-center gap-1 hover:text-white transition">
                      <Download size={14} /> Download
                    </button>
                  </div>
                </div>
                <pre className="bg-gray-950 border border-gray-800 rounded-lg p-4 font-mono text-sm text-purple-300 overflow-x-auto">
                  {config}
                </pre>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
