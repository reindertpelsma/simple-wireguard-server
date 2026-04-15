import { describe, expect, it } from 'vitest';
import { buildWireGuardConfig, sanitizeConfigFilename } from '../lib/config';

describe('config helpers', () => {
  it('omits persistent keepalive when it is unset', () => {
    const config = buildWireGuardConfig({
      privateKey: 'priv',
      assignedIPs: '100.64.0.2/32',
      dns: '100.64.0.1',
      mtu: '1280',
      serverPublicKey: 'server-pub',
      endpoint: 'vpn.example.com:51820',
      presharedKey: 'psk',
      keepalive: 0,
    });

    expect(config).not.toContain('PersistentKeepalive');
    expect(config).toContain('PresharedKey = psk');
  });

  it('normalizes config filenames to .conf', () => {
    expect(sanitizeConfigFilename('Branch Office Tablet')).toBe('Branch_Office_Tablet.conf');
    expect(sanitizeConfigFilename('already.conf')).toBe('already.conf');
  });
});
