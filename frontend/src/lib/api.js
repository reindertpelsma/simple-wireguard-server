const API_BASE = ''; // Same origin

export async function request(path, options = {}) {
  const token = localStorage.getItem('token');
  const headers = {
    'Content-Type': 'application/json',
    ...(token && { 'Authorization': `Bearer ${token}` }),
    ...options.headers,
  };

  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
  });

  if (response.status === 401) {
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
  login: (username, password) => 
    request('/api/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    }),

  getPeers: () => request('/api/peers'),

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
      headers: { 'X-Nonce-Hash': nonceHash },
    }),

  getHMACNonce: (nonce) => 
    request(`/api/auth/hmac-nonce?nonce=${nonce}`),

  getPublicConfig: () => request('/api/config/public'),

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
  deleteUser: (id) => 
    request(`/api/admin/users/${id}`, {
      method: 'DELETE',
    }),

  // Admin - ACLs
  getACLs: () => request('/api/admin/acls'),
  createACL: (data) => 
    request('/api/admin/acls', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
  deleteACL: (id) => 
    request(`/api/admin/acls/${id}`, {
      method: 'DELETE',
    }),

  updateGlobalConfig: (data) => 
    request('/api/admin/config', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
};
