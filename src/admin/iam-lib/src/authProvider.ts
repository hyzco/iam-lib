import { jwtDecode } from 'jwt-decode';
import { AuthProvider } from 'react-admin';

const API = import.meta.env.VITE_API_URL ?? 'http://localhost:3001';

console.log("API", API)

interface Tokens {
  accessToken: string;
  refreshToken: string;
}

const key = 'tokens';

const getTokens = (): Tokens | null => {
  const raw = localStorage.getItem(key);
  return raw ? (JSON.parse(raw) as Tokens) : null;
};

const setTokens = (t: Tokens) => localStorage.setItem(key, JSON.stringify(t));
const clearTokens = () => localStorage.removeItem(key);

const isExpired = (token: string) => {
  const { exp } = jwtDecode<{ exp: number }>(token);
  return Date.now() >= exp * 1000;
};

const refresh = async () => {
  const tokens = getTokens();
  if (!tokens) throw new Error();
  const res = await fetch(`${API}/auth/refresh`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refreshToken: tokens.refreshToken }),
  });
  if (!res.ok) throw new Error('Session expired');
  const fresh = (await res.json()) as Tokens;
  setTokens(fresh);
  return fresh.accessToken;
};

export const authProvider: AuthProvider = {
  login: async ({ username, password }) => {
    const res = await fetch(`${API}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: username, password }),
    });
    if (!res.ok) throw new Error('Invalid credentials');
    setTokens(await res.json());
  },

  logout: async () => {
    const tokens = getTokens();
    if (tokens) {
      await fetch(`${API}/auth/logout`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken: tokens.refreshToken }),
      }).catch(() => undefined);
    }
    clearTokens();
  },

  checkAuth: async () => {
    const tokens = getTokens();
    if (!tokens) throw new Error();
    if (isExpired(tokens.accessToken)) await refresh();
  },

  getIdentity: async () => {
    const { accessToken } = getTokens() ?? {};
    if (!accessToken) throw new Error();
    const res = await fetch(`${API}/auth/me`, {
      headers: { Authorization: `${accessToken}` },
    });
    if (!res.ok) throw new Error();
    return res.json();
  },

  checkError: ({ status }) =>
    status === 401 || status === 403 ? Promise.reject() : Promise.resolve(),

  getPermissions: () => Promise.resolve(),
};
