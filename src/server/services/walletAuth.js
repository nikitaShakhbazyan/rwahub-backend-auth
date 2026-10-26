/**
 * Wallet authentication (nonce + signature).
 *
 * Proving wallet ownership is a two-step handshake:
 *   1. POST /api/auth/wallet/nonce  -> server mints a one-time nonce for an address
 *   2. POST /api/auth/wallet/verify -> client returns personal_sign(message),
 *      server recovers the signer and checks it matches the claimed address
 *
 * The nonce is what makes this an actual proof rather than a claim: a signature
 * is only accepted once, for a message the server itself generated, within a
 * short window. Without it, a captured signature could be replayed forever.
 *
 * Nonces live in memory, which is correct for this demo and explicitly not for
 * production (a restart or a second instance drops them) — see README notes.
 */

const crypto = require('crypto');
const { ethers } = require('ethers');

const NONCE_TTL_MS = 5 * 60 * 1000; // 5 minutes
const ADDRESS_PATTERN = /^0x[a-fA-F0-9]{40}$/;

/** address (lowercased) -> { nonce, issuedAt, expiresAt } */
const nonces = new Map();

function isValidAddress(address) {
  return typeof address === 'string' && ADDRESS_PATTERN.test(address);
}

function normalizeAddress(address) {
  return String(address).toLowerCase();
}

function purgeExpired(now = Date.now()) {
  for (const [address, entry] of nonces.entries()) {
    if (entry.expiresAt <= now) {
      nonces.delete(address);
    }
  }
}

/**
 * The exact string the wallet is asked to sign. It is sent to the client so the
 * user can read what they are signing, and rebuilt server-side at verify time
 * so a client cannot talk us into verifying a different message.
 */
function buildSignInMessage(address, nonce) {
  return [
    'RWAHub wants you to sign in with your wallet.',
    '',
    `Address: ${address}`,
    `Nonce: ${nonce}`,
    '',
    'Signing this message proves you control this wallet.',
    'It costs no gas and sends no transaction.',
  ].join('\n');
}

function createNonce(address) {
  const now = Date.now();
  purgeExpired(now);

  const key = normalizeAddress(address);
  const nonce = crypto.randomBytes(16).toString('hex');

  nonces.set(key, { nonce, issuedAt: now, expiresAt: now + NONCE_TTL_MS });

  return {
    address: key,
    nonce,
    expiresAt: new Date(now + NONCE_TTL_MS).toISOString(),
    message: buildSignInMessage(key, nonce),
  };
}

/**
 * Verifies a signature against the stored nonce for `address`.
 * Returns { ok: true } or { ok: false, reason } — never throws on bad input,
 * so routes can map reasons to status codes without a try/catch dance.
 */
function verifySignature(address, signature) {
  if (!isValidAddress(address)) {
    return { ok: false, reason: 'invalid_address' };
  }
  if (typeof signature !== 'string' || signature.length < 2) {
    return { ok: false, reason: 'invalid_signature' };
  }

  const key = normalizeAddress(address);
  const entry = nonces.get(key);

  if (!entry) {
    return { ok: false, reason: 'nonce_not_found' };
  }
  if (entry.expiresAt <= Date.now()) {
    nonces.delete(key);
    return { ok: false, reason: 'nonce_expired' };
  }

  const message = buildSignInMessage(key, entry.nonce);

  let recovered;
  try {
    recovered = ethers.utils.verifyMessage(message, signature);
  } catch {
    // Malformed signature bytes: burn the nonce so it cannot be ground against.
    nonces.delete(key);
    return { ok: false, reason: 'invalid_signature' };
  }

  // Single-use: consume the nonce whatever the outcome, so one nonce can never
  // authorize two sign-ins and a wrong guess cannot be retried.
  nonces.delete(key);

  if (normalizeAddress(recovered) !== key) {
    return { ok: false, reason: 'signature_mismatch' };
  }

  return { ok: true, address: key };
}

/** Test seam — lets the suite assert expiry without waiting five minutes. */
function _clearNonces() {
  nonces.clear();
}

module.exports = {
  NONCE_TTL_MS,
  isValidAddress,
  normalizeAddress,
  buildSignInMessage,
  createNonce,
  verifySignature,
  _clearNonces,
};
