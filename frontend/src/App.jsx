import { useEffect, useState } from 'react';
import { ShieldAlert } from 'lucide-react';
import Login from './components/Login';
import Dashboard from './components/Dashboard';
import SharedConfigPage from './components/SharedConfigPage';

function getInitialTheme() {
  const stored = localStorage.getItem('theme');
  if (stored === 'light' || stored === 'dark') {
    return stored;
  }
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function getSharedToken() {
  const match = window.location.pathname.match(/^\/config\/([^/]+)$/);
  return match ? decodeURIComponent(match[1]) : '';
}

function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(!!localStorage.getItem('token'));
  const [isSecure] = useState(() => window.isSecureContext);
  const [theme, setTheme] = useState(getInitialTheme);
  const sharedToken = getSharedToken();

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem('theme', theme);
  }, [theme]);

  const toggleTheme = () => {
    setTheme((current) => current === 'dark' ? 'light' : 'dark');
  };

  if (sharedToken) {
    return (
      <SharedConfigPage
        token={sharedToken}
        theme={theme}
        onToggleTheme={toggleTheme}
      />
    );
  }

  return (
    <>
      {!isSecure && (
        <div className="security-banner">
          <ShieldAlert size={16} />
          <span>Secure context recommended. Browser crypto features work best over HTTPS or localhost.</span>
        </div>
      )}

      {!isLoggedIn ? (
        <Login theme={theme} onToggleTheme={toggleTheme} onLogin={() => setIsLoggedIn(true)} />
      ) : (
        <Dashboard theme={theme} onToggleTheme={toggleTheme} onLogout={() => {
          localStorage.removeItem('token');
          setIsLoggedIn(false);
        }} />
      )}
    </>
  );
}

export default App;
