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
  transportProfile,
  presharedKey,
  keepalive,
  enableIPv6,
  allowedIPs: customAllowedIPs,
  directiveTCP,
  directiveTURN,
  directiveSkipVerifyTLS,
  directiveURL,
  directiveControl,
  peerSyncEnabled,
  distributePeers,
}) {
  const displayIPs = enableIPv6 === 'true' ? assignedIPs : filterIPv6FromList(assignedIPs);
  const allowedIPs = customAllowedIPs || '0.0.0.0/0, ::/0';

  const selectedTransport = transportProfile || {};
  const resolvedEndpoint = selectedTransport.endpoint || endpoint;
  const resolvedTransport = selectedTransport.transport ?? transport;
  const resolvedDirectiveTCP = selectedTransport.directive_tcp ?? directiveTCP;
  const resolvedDirectiveTURN = selectedTransport.directive_turn ?? directiveTURN;
  const resolvedDirectiveURL = selectedTransport.directive_url ?? directiveURL;

  const lines = [
    '[Interface]',
    `PrivateKey = ${privateKey}`,
    `Address = ${displayIPs}`,
    `DNS = ${dns || '1.1.1.1'}`,
    `MTU = ${mtu || '1420'}`,
  ];

  if (resolvedDirectiveTURN) {
    lines.push(`#!TURN=${resolvedDirectiveTURN}`);
  }

  lines.push('', '[Peer]',
    `PublicKey = ${serverPublicKey}`,
    `Endpoint = ${resolvedEndpoint}`,
    `AllowedIPs = ${allowedIPs}`,
  );

  if (resolvedTransport && resolvedTransport !== 'udp') {
    lines.push(`Transport = ${resolvedTransport}`);
  }

  if (resolvedDirectiveTCP && resolvedDirectiveTCP !== 'no') {
    lines.push(`#!TCP=${resolvedDirectiveTCP}`);
  }
  if (directiveSkipVerifyTLS === 'yes') {
    lines.push('#!SkipVerifyTLS=yes');
  }
  if (resolvedDirectiveURL) {
    lines.push(`#!URL=${resolvedDirectiveURL}`);
  }
  if (peerSyncEnabled && directiveControl) {
    lines.push(`#!Control=${directiveControl}`);
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

export function stripWGDirectives(config) {
  return String(config || '')
    .split('\n')
    .filter((line) => !line.trimStart().startsWith('#!'))
    .join('\n');
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
