import { useState, useEffect } from 'react';
import { api } from '../lib/api';
import { generateKeyPair, generateNonce, hashNonce, encryptPrivateKey } from '../lib/crypto';
import { X, Loader2 } from 'lucide-react';

export default function AddPeerModal({ onClose, onSuccess }) {
  const [name, setName] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [globalConfig, setGlobalConfig] = useState({});
  
  // Advanced Fields
  const [manualPublicKey, setManualPublicKey] = useState('');
  const [staticEndpoint, setStaticEndpoint] = useState('');
  const [keepalive, setKeepalive] = useState(25);
  const [requestedIP, setRequestedIP] = useState('');
  const [expiresAt, setExpiresAt] = useState('');

  useEffect(() => {
    api.getPublicConfig().then(setGlobalConfig);
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      let publicKey = manualPublicKey;
      let privateKey = null;
      let encryptedPrivateKey = '';
      let nonceHash = '';

      const e2eEnabled = globalConfig.e2e_encryption_enabled === 'true';

      if (!publicKey && e2eEnabled) {
        // Auto-generate keys in browser (E2E)
        const keys = await generateKeyPair();
        privateKey = keys.privateKey;
        publicKey = keys.publicKey;

        const nonce = generateNonce();
        const aesKey = await api.getHMACNonce(nonce);
        encryptedPrivateKey = await encryptPrivateKey(privateKey, nonce, aesKey);
        nonceHash = await hashNonce(nonce);
        localStorage.setItem(`nonce_${publicKey}`, nonce);
      }

      const result = await api.createPeer({
        name,
        public_key: publicKey, // If empty and !e2e, server generates
        nonce_hash: nonceHash,
        encrypted_private_key: encryptedPrivateKey,
        requested_ip: requestedIP,
        keepalive: parseInt(keepalive),
        static_endpoint: staticEndpoint,
        is_manual_key: !!manualPublicKey,
        expires_at: expiresAt ? new Date(expiresAt).toISOString() : null
      });

      onSuccess({ ...result, name, public_key: result.public_key || publicKey });
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const showManualInput = globalConfig.allow_custom_private_key === 'true';

  return (
    <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50 overflow-y-auto">
      <div className="bg-gray-900 border border-gray-800 rounded-2xl w-full max-w-lg p-8 relative my-8">
        <button onClick={onClose} className="absolute top-4 right-4 text-gray-500 hover:text-white">
          <X size={20} />
        </button>
        <h2 className="text-2xl font-bold mb-6">Add New Device</h2>
        <form onSubmit={handleSubmit} className="space-y-6">
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-2">Device Name</label>
            <input
              type="text"
              required
              autoFocus
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 focus:ring-2 focus:ring-purple-500 outline-none transition"
              placeholder="iPhone 15, MacBook Pro..."
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </div>

          <button 
            type="button" 
            onClick={() => setShowAdvanced(!showAdvanced)}
            className="text-purple-400 text-sm font-bold flex items-center gap-1 hover:text-purple-300 transition"
          >
            {showAdvanced ? 'Hide Advanced Options' : 'Show Advanced Options'}
          </button>

          {showAdvanced && (
            <div className="space-y-4 pt-4 border-t border-gray-800">
              {showManualInput && (
                <div>
                  <label className="block text-xs text-gray-500 mb-1 uppercase font-bold tracking-wider">Manual Public Key (Optional)</label>
                  <input
                    type="text"
                    className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 text-sm font-mono outline-none"
                    placeholder="Base64 Public Key"
                    value={manualPublicKey}
                    onChange={(e) => setManualPublicKey(e.target.value)}
                  />
                  <p className="text-[10px] text-gray-500 mt-1">If provided, browser key generation will be skipped and no private data will be stored.</p>
                </div>
              )}
              <div>
                <label className="block text-xs text-gray-500 mb-1 uppercase font-bold tracking-wider">Static Endpoint (Optional)</label>
                <input
                  type="text"
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 text-sm outline-none"
                  placeholder="host:port"
                  value={staticEndpoint}
                  onChange={(e) => setStaticEndpoint(e.target.value)}
                />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs text-gray-500 mb-1 uppercase font-bold tracking-wider">Keepalive (Seconds)</label>
                  <input
                    type="number"
                    className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 text-sm outline-none"
                    value={keepalive}
                    onChange={(e) => setKeepalive(e.target.value)}
                  />
                </div>
                <div>
                  <label className="block text-xs text-gray-500 mb-1 uppercase font-bold tracking-wider">Custom IP (Admin Only)</label>
                  <input
                    type="text"
                    className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 text-sm outline-none"
                    placeholder="100.64.0.x/32"
                    value={requestedIP}
                    onChange={(e) => setRequestedIP(e.target.value)}
                  />
                </div>
              </div>
              <div>
                <label className="block text-xs text-gray-500 mb-1 uppercase font-bold tracking-wider">Expiration Date (Optional)</label>
                <input
                  type="datetime-local"
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 text-sm outline-none text-white"
                  value={expiresAt}
                  onChange={(e) => setExpiresAt(e.target.value)}
                />
              </div>
            </div>
          )}

          {error && <p className="text-red-500 text-sm">{error}</p>}
          
          <button
            type="submit"
            disabled={loading}
            className="w-full bg-purple-600 hover:bg-purple-700 py-3 rounded-lg font-bold flex items-center justify-center gap-2 disabled:opacity-50 shadow-lg shadow-purple-500/20 transition"
          >
            {loading ? <Loader2 className="animate-spin" size={20} /> : 'Create Device'}
          </button>
        </form>
      </div>
    </div>
  );
}
