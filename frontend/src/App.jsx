import { useState, useEffect } from 'react';
import Login from './components/Login';
import Dashboard from './components/Dashboard';
import { ShieldAlert } from 'lucide-react';

function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(!!localStorage.getItem('token'));
  const [isSecure, setIsSecure] = useState(true);

  useEffect(() => {
    if (!window.isSecureContext) {
      setIsSecure(false);
    }
  }, []);

  const handleLogout = () => {
    localStorage.removeItem('token');
    setIsLoggedIn(false);
  };

  return (
    <>
      {!isSecure && (
        <div className="bg-amber-500 text-black px-4 py-2 text-sm font-bold flex items-center justify-center gap-2">
          <ShieldAlert size={16} />
          Non-Secure Context detected. Web Crypto API (required for keys) might be disabled. 
          Use localhost or HTTPS.
        </div>
      )}
      {!isLoggedIn ? (
        <Login onLogin={() => setIsLoggedIn(true)} />
      ) : (
        <Dashboard onLogout={handleLogout} />
      )}
    </>
  );
}

export default App;
