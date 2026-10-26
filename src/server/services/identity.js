/**
 * Identity service.
 *
 * Single source of truth for "who is the caller". Every auth provider
 * (password, wallet signature) funnels through `toIdentity` so the rest of the
 * API only ever deals with one shape, and `issueToken` is the only place that
 * decides what goes into a JWT.
 *
 * Keeping this out of the route handlers is what makes `req.user` trustworthy:
 * routes never assemble an identity themselves, they only read the one the
 * auth middleware attached.
 */

const jwt = require('jsonwebtoken');

const DEFAULT_ROLES = ['buyer'];

function getJwtSecret() {
  const secret = process.env.JWT_SECRET;
  if (!secret || secret === 'fallback-secret') {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('JWT_SECRET must be configured');
    }
    return 'dev-only-insecure-secret';
  }
  return secret;
}

/**
 * Normalizes a stored user record into the canonical identity shape.
 * This is the object that becomes the JWT payload and, later, `req.user`.
 */
function toIdentity(user) {
  if (!user || !user.id) {
    throw new Error('Cannot build an identity without a user id');
  }

  return {
    userId: user.id,
    email: user.email || null,
    // Wallet address is part of identity, not a separate rail. A wallet user
    // and an email user are both just identities with different providers.
    walletAddress: user.wallet && user.wallet.address
      ? String(user.wallet.address).toLowerCase()
      : null,
    roles: Array.isArray(user.roles) && user.roles.length ? user.roles : DEFAULT_ROLES,
    provider: user.provider || 'password',
  };
}

function issueToken(user) {
  return jwt.sign(toIdentity(user), getJwtSecret(), {
    expiresIn: process.env.JWT_EXPIRES_IN || '7d',
  });
}

function verifyToken(token) {
  return jwt.verify(token, getJwtSecret());
}

/** Strips secrets before a user record is sent over the wire. */
function toPublicUser(user) {
  if (!user) return null;
  const { password, ...rest } = user;
  return rest;
}

module.exports = {
  getJwtSecret,
  toIdentity,
  issueToken,
  verifyToken,
  toPublicUser,
  DEFAULT_ROLES,
};
