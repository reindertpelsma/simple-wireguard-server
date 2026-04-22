const THEME_KEY = 'ui_theme';
const OS_THEME_KEY = 'ui_theme_os';

function safeStorage(getter, fallback = null) {
  try {
    return getter();
  } catch {
    return fallback;
  }
}

function readCookie(name) {
  if (typeof document === 'undefined') return '';
  const prefix = `${name}=`;
  for (const part of document.cookie.split(';')) {
    const value = part.trim();
    if (value.startsWith(prefix)) {
      return decodeURIComponent(value.slice(prefix.length));
    }
  }
  return '';
}

function writeCookie(name, value) {
  if (typeof document === 'undefined') return;
  document.cookie = `${name}=${encodeURIComponent(value)}; Path=/; Max-Age=31536000; SameSite=Lax`;
}

export function detectOSTheme() {
  try {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
      return 'light';
    }
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  } catch {
    return 'light';
  }
}

export function persistTheme(theme, osTheme = detectOSTheme()) {
  safeStorage(() => localStorage.setItem(THEME_KEY, theme));
  safeStorage(() => localStorage.setItem(OS_THEME_KEY, osTheme));
  writeCookie(THEME_KEY, theme);
  writeCookie(OS_THEME_KEY, osTheme);
}

function readThemeValue(key) {
  const stored = safeStorage(() => localStorage.getItem(key), '');
  return stored || readCookie(key);
}

export function resolveInitialTheme() {
  const osTheme = detectOSTheme();
  const lastOSTheme = readThemeValue(OS_THEME_KEY);
  const savedTheme = readThemeValue(THEME_KEY);
  if (lastOSTheme !== osTheme) {
    persistTheme(osTheme, osTheme);
    return osTheme;
  }
  if (savedTheme === 'light' || savedTheme === 'dark') {
    persistTheme(savedTheme, osTheme);
    return savedTheme;
  }
  persistTheme(osTheme, osTheme);
  return osTheme;
}

export function applyTheme(theme) {
  if (typeof document !== 'undefined') {
    document.documentElement.dataset.theme = theme;
  }
  persistTheme(theme, detectOSTheme());
}

export function watchOSTheme(onChange) {
  try {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
      return () => {};
    }
    const query = window.matchMedia('(prefers-color-scheme: dark)');
    const handler = () => {
      const next = detectOSTheme();
      persistTheme(next, next);
      onChange(next);
    };
    if (typeof query.addEventListener === 'function') {
      query.addEventListener('change', handler);
      return () => query.removeEventListener('change', handler);
    }
    if (typeof query.addListener === 'function') {
      query.addListener(handler);
      return () => query.removeListener(handler);
    }
  } catch {
    // ignore
  }
  return () => {};
}
