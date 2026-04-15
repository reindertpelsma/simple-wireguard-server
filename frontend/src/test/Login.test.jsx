import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import Login from '../components/Login';
import { api } from '../lib/api';

vi.mock('../lib/api', () => ({
  api: {
    login: vi.fn(),
  }
}));

describe('Login Component', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
  });

  it('renders login form', () => {
    render(<Login onLogin={() => {}} />);
    expect(screen.getByText(/WireGuard Manager/i)).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/Admin/i)).toBeInTheDocument();
  });

  it('calls onLogin on successful submit', async () => {
    const onLogin = vi.fn();
    api.login.mockResolvedValue({ token: 'test-token' });
    
    render(<Login onLogin={onLogin} />);
    
    fireEvent.change(screen.getByPlaceholderText(/Admin/i), { target: { value: 'admin' } });
    fireEvent.change(screen.getByPlaceholderText(/••••••••/i), { target: { value: 'admin' } });
    
    // Use submit on the form
    const form = screen.getByRole('form', { hidden: true }); // Need to add role="form" or use container
    if (!form) {
        fireEvent.click(screen.getByRole('button', { name: /Sign in/i }));
    } else {
        fireEvent.submit(form);
    }
    
    await waitFor(() => expect(onLogin).toHaveBeenCalled());
    expect(localStorage.getItem('token')).toBe('test-token');
  });
});
