import { describe, expect, it } from 'vitest';
import { buildWireGuardConfig, sanitizeConfigFilename, stripWGDirectives } from '../lib/config';

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

  it('adds and strips #!Control directives', () => {
    const config = buildWireGuardConfig({
      privateKey: 'priv',
      assignedIPs: '100.64.0.2/32',
      dns: '100.64.0.1',
      mtu: '1280',
      serverPublicKey: 'server-pub',
      endpoint: 'vpn.example.com:51820',
      peerSyncEnabled: true,
      directiveControl: 'http://100.64.0.1:28765',
    });

    expect(config).toContain('#!Control=http://100.64.0.1:28765');
    expect(stripWGDirectives(config)).not.toContain('#!Control=');
  });

  it('uses the selected transport profile directives', () => {
    const config = buildWireGuardConfig({
      privateKey: 'priv',
      assignedIPs: '100.64.0.2/32',
      dns: '100.64.0.1',
      mtu: '1280',
      serverPublicKey: 'server-pub',
      endpoint: 'vpn.example.com:51820',
      transportProfile: {
        endpoint: 'ui.example.com:443',
        directive_url: 'https://ui.example.com/socket',
      },
    });

    expect(config).toContain('Endpoint = ui.example.com:443');
    expect(config).toContain('#!URL=https://ui.example.com/socket');
  });
});
