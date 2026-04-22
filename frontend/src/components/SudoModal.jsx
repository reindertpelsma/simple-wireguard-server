import { useState } from 'react';
import { Loader2, Lock, X } from 'lucide-react';
import { api } from '../lib/api';

export default function SudoModal({ open, onClose, onSuccess, requires2FA = false }) {
  const [password, setPassword] = useState('');
  const [totpCode, setTotpCode] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  if (!open) return null;

  const submit = async (event) => {
    event.preventDefault();
    setLoading(true);
    setError('');
    try {
      await api.reauth(password, totpCode);
      setPassword('');
      setTotpCode('');
      onSuccess?.();
      onClose?.();
    } catch (err) {
      setError(err.message || 'Re-authentication failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-backdrop">
      <div className="modal-panel">
        <div className="flex items-start justify-between gap-4 border-b border-[var(--border)] px-6 py-5">
          <div className="space-y-2">
            <span className="eyebrow">Security Check</span>
            <h2 className="text-2xl font-black tracking-tight">Unlock sensitive actions</h2>
            <p className="text-sm text-[var(--muted)]">
              Password re-authentication temporarily unlocks config downloads, credential creation, and admin changes.
            </p>
          </div>
          <button type="button" onClick={onClose} className="ghost-button" aria-label="Close">
            <X size={18} />
          </button>
        </div>

        <form onSubmit={submit} className="space-y-4 px-6 py-6">
          <div className="space-y-2">
            <label className="field-label">Password</label>
            <input
              type="password"
              className="input-field"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              required
              autoFocus
            />
          </div>
          {requires2FA && (
            <div className="space-y-2">
              <label className="field-label">Two-factor code</label>
              <input
                type="text"
                inputMode="numeric"
                className="input-field"
                value={totpCode}
                onChange={(event) => setTotpCode(event.target.value)}
                placeholder="123456"
                required
              />
            </div>
          )}
          {error ? <div className="error-banner">{error}</div> : null}
          <div className="flex justify-end gap-2">
            <button type="button" onClick={onClose} className="ghost-button">Cancel</button>
            <button type="submit" className="primary-button" disabled={loading}>
              {loading ? <Loader2 size={16} className="animate-spin" /> : <Lock size={16} />}
              <span>{loading ? 'Unlocking…' : 'Unlock changes'}</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
