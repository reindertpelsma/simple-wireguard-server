export function buildWireGuardConfig({
  privateKey,
  assignedIPs,
  dns,
  mtu,
  serverPublicKey,
  endpoint,
  transport,
  presharedKey,
  keepalive,
}) {
  const lines = [
    '[Interface]',
    `PrivateKey = ${privateKey}`,
    `Address = ${assignedIPs}`,
    `DNS = ${dns || '1.1.1.1'}`,
    `MTU = ${mtu || '1420'}`,
    '',
    '[Peer]',
    `PublicKey = ${serverPublicKey}`,
    `Endpoint = ${endpoint}`,
    'AllowedIPs = 0.0.0.0/0, ::/0',
  ];

  if (transport && transport != 'udp') {
    lines.push(`Transport = ${transport}`);
  }

  if (presharedKey) {
    lines.push(`PresharedKey = ${presharedKey}`);
  }
  if (Number(keepalive) > 0) {
    lines.push(`PersistentKeepalive = ${Number(keepalive)}`);
  }

  return lines.join('\n');
}

export function sanitizeConfigFilename(name) {
  const cleaned = String(name || 'wireguard-client')
    .replace(/[^A-Za-z0-9._-]+/g, '_')
    .replace(/^[_./-]+|[_./-]+$/g, '');
  const base = cleaned || 'wireguard-client';
  return base.endsWith('.conf') ? base : `${base}.conf`;
}

export function downloadConfigFile(name, config) {
  const blob = new Blob([config], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = sanitizeConfigFilename(name);
  anchor.click();
  URL.revokeObjectURL(url);
}

export function formatBytes(bytes) {
  if (!bytes) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / (1024 ** index)).toFixed(index === 0 ? 0 : 2)} ${units[index]}`;
}
