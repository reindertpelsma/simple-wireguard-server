function filterIPv6FromList(ips) {
  if (!ips) return ips;
  return ips.split(',')
    .map((s) => s.trim())
    .filter((s) => {
      if (!s) return false;
      const slash = s.indexOf('/');
      const addr = slash >= 0 ? s.slice(0, slash) : s;
      return !addr.includes(':');
    })
    .join(', ');
}

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
  enableIPv6,
  allowedIPs: customAllowedIPs,
  directiveTCP,
  directiveTURN,
  directiveSkipVerifyTLS,
  directiveURL,
  distributePeers,
}) {
  const displayIPs = enableIPv6 === 'true' ? assignedIPs : filterIPv6FromList(assignedIPs);
  const allowedIPs = customAllowedIPs || '0.0.0.0/0, ::/0';

  const lines = [
    '[Interface]',
    `PrivateKey = ${privateKey}`,
    `Address = ${displayIPs}`,
    `DNS = ${dns || '1.1.1.1'}`,
    `MTU = ${mtu || '1420'}`,
  ];

  if (directiveTURN) {
    lines.push(`#!TURN=${directiveTURN}`);
  }

  lines.push('', '[Peer]',
    `PublicKey = ${serverPublicKey}`,
    `Endpoint = ${endpoint}`,
    `AllowedIPs = ${allowedIPs}`,
  );

  if (transport && transport !== 'udp') {
    lines.push(`Transport = ${transport}`);
  }

  if (directiveTCP && directiveTCP !== 'no') {
    lines.push(`#!TCP=${directiveTCP}`);
  }
  if (directiveSkipVerifyTLS === 'yes') {
    lines.push('#!SkipVerifyTLS=yes');
  }
  if (directiveURL) {
    lines.push(`#!URL=${directiveURL}`);
  }

  if (presharedKey) {
    lines.push(`PresharedKey = ${presharedKey}`);
  }
  if (Number(keepalive) > 0) {
    lines.push(`PersistentKeepalive = ${Number(keepalive)}`);
  }

  if (Array.isArray(distributePeers)) {
    for (const dp of distributePeers) {
      if (!dp.endpoint) continue;
      lines.push('', '[Peer]',
        `# ${dp.name} (distributed)`,
        `PublicKey = ${dp.public_key}`,
        `AllowedIPs = ${dp.allowed_ips}`,
        `Endpoint = ${dp.endpoint}`,
      );
    }
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
