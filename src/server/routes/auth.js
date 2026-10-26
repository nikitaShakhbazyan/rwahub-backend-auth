const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const db = require('../models/database');
const { authLimiter } = require('../middleware/rateLimiting');
const { authenticateToken } = require('../middleware/auth');
const { validateUserRegistration, validateUserLogin } = require('../middleware/validation');
const { issueToken, verifyToken, toPublicUser } = require('../services/identity');
const walletAuth = require('../services/walletAuth');

/**
 * Why a wallet signature and not just an address:
 * the frontend already knows the connected address, but an address alone is a
 * claim, not a proof. Posting `{ address }` would let anyone mint a token for
 * a wallet they do not control. The nonce + personal_sign handshake below is
 * what makes the wallet a real identity the API can assign ownership to.
 */

// Register new user
router.post('/register', authLimiter, validateUserRegistration, async (req, res) => {
  try {
    const { email, password, name } = req.body;

    // Validate required fields
    if (!email || !password || !name) {
      return res.status(400).json({ 
        error: 'Missing required fields: email, password, name' 
      });
    }

    // Check if user already exists
    const existingUser = Array.from(db.users.values()).find(user => user.email === email);
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create new user
    const newUser = {
      id: `user_${Date.now()}`,
      email,
      password: hashedPassword,
      name,
      roles: ['buyer'],
      kyc: {
        status: 'pending',
        documents: {}
      },
      wallet: {
        address: `0x${Math.random().toString(16).substr(2, 40)}`,
        balance: 0,
        currency: 'USDT'
      },
      stats: {
        assetsListed: 0,
        assetsSold: 0,
        assetsBought: 0,
        totalValue: 0,
        rating: 0,
        reviews: 0
      },
      createdAt: new Date(),
      updatedAt: new Date()
    };

    // Store user (in production, save to database)
    db.users.set(newUser.id, newUser);

    res.status(201).json({
      user: toPublicUser(newUser),
      token: issueToken(newUser),
      message: 'User registered successfully'
    });
  } catch (error) {
    console.error('Error registering user:', error);
    res.status(500).json({ error: 'Failed to register user' });
  }
});

// Login user
router.post('/login', authLimiter, validateUserLogin, async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = db.getUserByEmail(email);

    // Same 401 and the same shape whether the account is missing or the
    // password is wrong, so the response cannot be used to enumerate emails.
    const isValidPassword = user && user.password
      ? await bcrypt.compare(password, user.password)
      : false;

    if (!isValidPassword) {
      return res.status(401).json({
        error: 'Invalid credentials',
        code: 'INVALID_CREDENTIALS'
      });
    }

    res.json({
      user: toPublicUser(user),
      token: issueToken(user),
      message: 'Login successful'
    });
  } catch (error) {
    console.error('Error logging in user:', error);
    res.status(500).json({ error: 'Failed to login user' });
  }
});

// --- Wallet sign-in (nonce + signature) -------------------------------------

/**
 * Step 1: mint a one-time nonce for an address and return the exact message
 * the wallet should sign. No account is created here — this endpoint proves
 * nothing on its own and is safe to call for any address.
 */
router.post('/wallet/nonce', authLimiter, (req, res) => {
  try {
    const { address } = req.body;

    if (!walletAuth.isValidAddress(address)) {
      return res.status(400).json({
        error: 'A valid EVM wallet address is required',
        code: 'INVALID_ADDRESS'
      });
    }

    const { nonce, message, expiresAt } = walletAuth.createNonce(address);
    res.json({ address: walletAuth.normalizeAddress(address), nonce, message, expiresAt });
  } catch (error) {
    console.error('Error creating wallet nonce:', error);
    res.status(500).json({ error: 'Failed to create nonce', code: 'NONCE_FAILED' });
  }
});

/**
 * Step 2: verify personal_sign over the stored nonce. On success the wallet
 * becomes a real user record and gets the same JWT a password login would —
 * which is the whole point: one identity model, two providers.
 */
router.post('/wallet/verify', authLimiter, (req, res) => {
  try {
    const { address, signature } = req.body;

    if (!walletAuth.isValidAddress(address)) {
      return res.status(400).json({
        error: 'A valid EVM wallet address is required',
        code: 'INVALID_ADDRESS'
      });
    }
    if (!signature) {
      return res.status(400).json({ error: 'Signature is required', code: 'SIGNATURE_REQUIRED' });
    }

    const result = walletAuth.verifySignature(address, signature);
    if (!result.ok) {
      // A failed proof is an authentication failure, not a malformed request:
      // the client asked correctly, it just did not demonstrate ownership.
      const needsNewNonce = result.reason === 'nonce_not_found' || result.reason === 'nonce_expired';
      return res.status(401).json({
        error: needsNewNonce
          ? 'Nonce is missing or expired. Request a new one and sign again.'
          : 'Wallet signature verification failed',
        code: result.reason.toUpperCase()
      });
    }

    const user = db.findOrCreateWalletUser(result.address);

    res.json({
      user: toPublicUser(user),
      token: issueToken(user),
      message: 'Wallet sign-in successful'
    });
  } catch (error) {
    console.error('Error verifying wallet signature:', error);
    res.status(500).json({ error: 'Failed to verify wallet', code: 'WALLET_VERIFY_FAILED' });
  }
});

// Get current user profile
router.get('/profile', authenticateToken, (req, res) => {
  try {
    const user = db.getUserById(req.user.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found', code: 'USER_NOT_FOUND' });
    }
    res.json(toPublicUser(user));
  } catch (error) {
    console.error('Error fetching user profile:', error);
    res.status(500).json({ error: 'Failed to fetch user profile' });
  }
});

// Update user profile
router.patch('/profile', authenticateToken, (req, res) => {
  try {
    const userId = req.user.userId;
    const user = db.getUserById(userId);

    if (!user) {
      return res.status(404).json({ error: 'User not found', code: 'USER_NOT_FOUND' });
    }

    const allowedFields = ['name'];
    const updates = {};
    for (const field of allowedFields) {
      if (req.body[field] !== undefined) {
        updates[field] = req.body[field];
      }
    }

    const updatedUser = {
      ...user,
      ...updates,
      id: user.id,
      email: user.email,
      password: user.password,
      roles: user.roles,
      updatedAt: new Date()
    };

    db.users.set(userId, updatedUser);

    res.json(toPublicUser(updatedUser));
  } catch (error) {
    console.error('Error updating user profile:', error);
    res.status(500).json({ error: 'Failed to update user profile' });
  }
});

router.post('/refresh', authLimiter, (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({ error: 'Token required' });
    }

    let payload;
    try {
      payload = verifyToken(token);
    } catch {
      return res.status(401).json({ error: 'Invalid token', code: 'TOKEN_INVALID' });
    }

    const storedUser = db.getUserById(payload.userId);
    if (!storedUser) {
      return res.status(401).json({ error: 'Invalid token', code: 'TOKEN_INVALID' });
    }

    res.json({ token: issueToken(storedUser) });
  } catch (error) {
    console.error('Error refreshing token:', error);
    res.status(500).json({ error: 'Failed to refresh token' });
  }
});

// Logout (client-side token removal)
router.post('/logout', (req, res) => {
  res.json({ message: 'Logout successful' });
});

module.exports = router;
