/**
 * The single place the API token lives on the client.
 *
 * Kept outside the Zustand auth store on purpose: plain modules (the asset API
 * client) need to read it without importing a React store, and the store needs
 * to write it on sign-in. One module both sides share avoids an import cycle.
 */

const TOKEN_KEY = 'rwahub-api-token';

export function getApiToken(): string | null {
  try {
    return localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setApiToken(token: string | null) {
  try {
    if (token) {
      localStorage.setItem(TOKEN_KEY, token);
    } else {
      localStorage.removeItem(TOKEN_KEY);
    }
  } catch {
    // Storage can be unavailable (private mode); the session still works
    // in-memory for as long as the page lives.
  }
}

export function clearApiToken() {
  setApiToken(null);
}

/** Authorization header for an authenticated request, or {} when signed out. */
export function authHeaders(): Record<string, string> {
  const token = getApiToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}
