/**
 * Client half of the wallet sign-in handshake.
 *
 * Mirrors the server contract in src/server/services/walletAuth.js:
 *   1. ask for a nonce + the exact message to sign
 *   2. personal_sign that message with the connected wallet
 *   3. exchange the signature for a JWT
 *
 * The message is never built here — it is whatever the server sent back. That
 * is what keeps the nonce binding meaningful.
 */

import { API_BASE_URL } from '@/utils/apiBase';
import { setApiToken, authHeaders } from '@/utils/authToken';

export type ApiUser = {
  id: string;
  email?: string | null;
  name?: string;
  provider?: string;
  roles?: string[];
  wallet?: { address?: string };
};

async function readError(response: Response, fallback: string) {
  const body = await response.json().catch(() => null);
  return new Error(body?.error || fallback);
}

async function requestNonce(address: string): Promise<{ nonce: string; message: string }> {
  const response = await fetch(`${API_BASE_URL}/auth/wallet/nonce`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ address }),
  });

  if (!response.ok) {
    throw await readError(response, 'Could not start wallet sign-in');
  }
  return response.json();
}

async function verifySignature(address: string, signature: string) {
  const response = await fetch(`${API_BASE_URL}/auth/wallet/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ address, signature }),
  });

  if (!response.ok) {
    throw await readError(response, 'Wallet sign-in failed');
  }
  return response.json() as Promise<{ token: string; user: ApiUser }>;
}

/**
 * Runs the full handshake for an already-connected wallet and stores the JWT.
 * `signMessage` is injected so this stays testable and provider-agnostic.
 */
export async function signInWithWallet(
  address: string,
  signMessage: (message: string) => Promise<string>
): Promise<{ token: string; user: ApiUser }> {
  const { message } = await requestNonce(address);
  const signature = await signMessage(message);
  const result = await verifySignature(address, signature);

  setApiToken(result.token);
  return result;
}

/** Email + password sign-in, for accounts created through /api/auth/register. */
export async function signInWithPassword(email: string, password: string) {
  const response = await fetch(`${API_BASE_URL}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });

  if (!response.ok) {
    throw await readError(response, 'Invalid credentials');
  }

  const result = (await response.json()) as { token: string; user: ApiUser };
  setApiToken(result.token);
  return result;
}

/** Confirms the stored token is still valid and returns the server's user. */
export async function fetchProfile(): Promise<ApiUser | null> {
  const response = await fetch(`${API_BASE_URL}/auth/profile`, {
    headers: { ...authHeaders() },
  });

  if (!response.ok) {
    return null;
  }
  return response.json();
}
