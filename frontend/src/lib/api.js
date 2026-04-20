const API_BASE = ''; // Same origin

export async function request(path, options = {}) {
  const {
    auth = true,
    redirectOnAuth = true,
    headers: extraHeaders,
    ...fetchOptions
  } = options;

  const token = auth ? localStorage.getItem('token') : null;
  const headers = {
    'Content-Type': 'application/json',
    ...(token && { 'Authorization': `Bearer ${token}` }),
    ...extraHeaders,
  };

  const response = await fetch(`${API_BASE}${path}`, {
    ...fetchOptions,
    headers,
  });

  if (response.status === 401 && redirectOnAuth) {
    localStorage.removeItem('token');
    window.location.href = '/login';
    throw new Error('Unauthorized');
  }

  if (!response.ok) {
    const error = await response.text();
    throw new Error(error || response.statusText);
  }

  const contentType = response.headers.get('content-type');
  if (contentType && contentType.includes('application/json')) {
    return response.json();
  }
  return response.text();
}

export const api = {
  login: (username, password, totpCode = '') =>
    request('/api/login', {
      method: 'POST',
      body: JSON.stringify({ username, password, totp_code: totpCode }),
    }),

  logout: () =>
    request('/api/logout', {
      method: 'POST',
      redirectOnAuth: false,
    }),

  getAuthMethods: () => request('/api/auth/methods', { auth: false, redirectOnAuth: false }),

  getMe: () => request('/api/me'),

  getPeers: () => request('/api/peers'),

  getDistributePeers: () => request('/api/distribute-peers'),

  createPeer: (data) => 
    request('/api/peers', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  deletePeer: (id) => 
    request(`/api/peers/${id}`, {
      method: 'DELETE',
    }),

  getPeerPrivate: (id, nonceHash) => 
    request(`/api/peers/${id}/private`, {
      headers: nonceHash ? { 'X-Nonce-Hash': nonceHash } : {},
    }),

  getHMACNonce: (nonce) => 
    request(`/api/auth/hmac-nonce?nonce=${nonce}`),

  getPublicConfig: () => request('/api/config/public'),
  getAdminConfig: () => request('/api/admin/config'),
  getYAMLConfig: () => request('/api/admin/yaml'),

  // Peer Updates
  updatePeer: (id, data) => 
    request(`/api/peers/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),

  pingPeer: (id) => 
    request(`/api/peers/${id}/ping`, {
      method: 'POST',
    }),

  // Admin - Users
  getUsers: () => request('/api/admin/users'),
  createUser: (data) => 
    request('/api/admin/users', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
  updateUser: (id, data) =>
    request(`/api/admin/users/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),
  deleteUser: (id) => 
    request(`/api/admin/users/${id}`, {
      method: 'DELETE',
    }),
  getTags: () => request('/api/admin/tags'),
  createTag: (data) =>
    request('/api/admin/tags', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
  updateTag: (id, data) =>
    request(`/api/admin/tags/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),
  deleteTag: (id) =>
    request(`/api/admin/tags/${id}`, {
      method: 'DELETE',
    }),

  // Admin - ACLs
  getACLs: () => request('/api/admin/acls'),
  createACL: (data) =>
    request('/api/admin/acls', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
  updateACL: (id, data) =>
    request(`/api/admin/acls/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),
  deleteACL: (id) =>
    request(`/api/admin/acls/${id}`, {
      method: 'DELETE',
    }),
  reorderACLs: (items) =>
    request('/api/admin/acls/reorder', {
      method: 'POST',
      body: JSON.stringify(items),
    }),
  searchACLTokens: (q) =>
    request(`/api/admin/acl-tokens?q=${encodeURIComponent(q)}`),

  // Admin - Forwards
  getForwards: () => request('/api/admin/forwards'),
  createForward: (data) =>
    request('/api/admin/forwards', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
  updateForward: (id, data) =>
    request(`/api/admin/forwards/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),
  deleteForward: (id) =>
    request(`/api/admin/forwards/${id}`, {
      method: 'DELETE',
    }),

  // Admin - Transports
  getTransports: () => request('/api/admin/transports'),
  createTransport: (data) =>
    request('/api/admin/transports', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
  updateTransport: (id, data) =>
    request(`/api/admin/transports/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),
  deleteTransport: (id) =>
    request(`/api/admin/transports/${id}`, {
      method: 'DELETE',
    }),

  updateGlobalConfig: (data) => 
    request('/api/admin/config', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  saveYAMLConfig: (data) =>
    request('/api/admin/yaml', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  restartDaemon: () =>
    request('/api/admin/restart', {
      method: 'POST',
    }),

  getProxyCredentials: () => request('/api/admin/proxy-credentials'),
  createProxyCredential: (data) =>
    request('/api/admin/proxy-credentials', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
  deleteProxyCredential: (id) =>
    request(`/api/admin/proxy-credentials/${id}`, {
      method: 'DELETE',
    }),

  getExposedServices: () => request('/api/admin/exposed-services'),
  createExposedService: (data) =>
    request('/api/admin/exposed-services', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
  updateExposedService: (id, data) =>
    request(`/api/admin/exposed-services/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),
  deleteExposedService: (id) =>
    request(`/api/admin/exposed-services/${id}`, {
      method: 'DELETE',
    }),

  updateMe: (data) =>
    request('/api/me', {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),

  setupTOTP: () =>
    request('/api/me/2fa/setup', {
      method: 'POST',
    }),

  enableTOTP: (code) =>
    request('/api/me/2fa/enable', {
      method: 'POST',
      body: JSON.stringify({ code }),
    }),

  disableTOTP: () =>
    request('/api/me/2fa', {
      method: 'DELETE',
    }),

  // Admin - user 2FA reset
  adminResetUserTOTP: (id) =>
    request(`/api/admin/users/${id}/2fa`, {
      method: 'DELETE',
    }),

  // My proxy credentials (available to all users)
  getMyProxyCredentials: () => request('/api/me/proxy-credentials'),
  createMyProxyCredential: (data) =>
    request('/api/me/proxy-credentials', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
  deleteMyProxyCredential: (id) =>
    request(`/api/me/proxy-credentials/${id}`, {
      method: 'DELETE',
    }),

  createShareLink: (id, data) =>
    request(`/api/peers/${id}/share-links`, {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  getSharedConfig: (token, nonceHash) =>
    request(`/api/share/${encodeURIComponent(token)}`, {
      auth: false,
      redirectOnAuth: false,
      headers: nonceHash ? { 'X-Nonce-Hash': nonceHash } : {},
    }),
};
