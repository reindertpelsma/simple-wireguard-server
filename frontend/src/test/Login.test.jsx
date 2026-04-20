import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import Login from '../components/Login';
import { api } from '../lib/api';

vi.mock('../lib/api', () => ({
  api: {
    login: vi.fn(),
    getAuthMethods: vi.fn(),
  }
}));

describe('Login Component', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
    api.getAuthMethods.mockResolvedValue({ oidc_enabled: false, oidc_login: '/api/oidc/login' });
  });

  it('renders login form', () => {
    render(<Login onLogin={() => {}} />);
    expect(screen.getByText(/Sign in Wireguard/i)).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/admin/i)).toBeInTheDocument();
  });

  it('calls onLogin on successful submit', async () => {
    const onLogin = vi.fn();
    api.login.mockResolvedValue({ token: 'test-token' });
    
    render(<Login onLogin={onLogin} />);
    
    fireEvent.change(screen.getByPlaceholderText(/admin/i), { target: { value: 'admin' } });
    fireEvent.change(screen.getByPlaceholderText(/••••••••••••/i), { target: { value: 'admin' } });
    fireEvent.submit(screen.getByRole('form'));
    
    await waitFor(() => expect(onLogin).toHaveBeenCalled());
    expect(localStorage.getItem('token')).toBe('test-token');
  });

  it('prompts for a 2FA code when the backend requires it', async () => {
    api.login.mockResolvedValueOnce({ requires_2fa: true });

    render(<Login onLogin={() => {}} />);

    fireEvent.change(screen.getByPlaceholderText(/admin/i), { target: { value: 'admin' } });
    fireEvent.change(screen.getByPlaceholderText(/••••••••••••/i), { target: { value: 'password' } });
    fireEvent.submit(screen.getByRole('form'));

    await waitFor(() => expect(screen.getByPlaceholderText(/123456/i)).toBeInTheDocument());
  });
});
