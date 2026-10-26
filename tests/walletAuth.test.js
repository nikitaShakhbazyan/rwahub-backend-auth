const request = require('supertest');
const { ethers } = require('ethers');
const app = require('../src/server/server');
const walletAuth = require('../src/server/services/walletAuth');

// Hardhat account #0 — a publicly known test key, safe to hardcode.
const TEST_PK = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';

/** Runs the full handshake and returns the issued JWT. */
async function signIn(wallet) {
  const nonceRes = await request(app)
    .post('/api/auth/wallet/nonce')
    .send({ address: wallet.address })
    .expect(200);

  const signature = await wallet.signMessage(nonceRes.body.message);

  const verifyRes = await request(app)
    .post('/api/auth/wallet/verify')
    .send({ address: wallet.address, signature })
    .expect(200);

  return verifyRes.body;
}

describe('Wallet authentication (nonce + signature)', () => {
  let wallet;

  beforeEach(() => {
    wallet = new ethers.Wallet(TEST_PK);
    walletAuth._clearNonces();
  });

  describe('POST /api/auth/wallet/nonce', () => {
    it('returns a nonce and the exact message to sign', async () => {
      const res = await request(app)
        .post('/api/auth/wallet/nonce')
        .send({ address: wallet.address })
        .expect(200);

      expect(res.body.nonce).toMatch(/^[0-9a-f]{32}$/);
      expect(res.body.address).toBe(wallet.address.toLowerCase());
      expect(res.body.message).toContain(res.body.nonce);
      expect(res.body.message).toContain(wallet.address.toLowerCase());
    });

    it('rejects a malformed address with 400', async () => {
      const res = await request(app)
        .post('/api/auth/wallet/nonce')
        .send({ address: 'not-an-address' })
        .expect(400);

      expect(res.body.code).toBe('INVALID_ADDRESS');
    });

    it('issues a different nonce on each call', async () => {
      const first = await request(app).post('/api/auth/wallet/nonce').send({ address: wallet.address });
      const second = await request(app).post('/api/auth/wallet/nonce').send({ address: wallet.address });

      expect(first.body.nonce).not.toBe(second.body.nonce);
    });
  });

  describe('POST /api/auth/wallet/verify', () => {
    it('issues a JWT whose identity carries the wallet address', async () => {
      const body = await signIn(wallet);

      expect(body.token).toEqual(expect.any(String));
      expect(body.user.provider).toBe('wallet');
      expect(body.user.wallet.address).toBe(wallet.address.toLowerCase());

      const payload = JSON.parse(
        Buffer.from(body.token.split('.')[1], 'base64').toString()
      );
      expect(payload.walletAddress).toBe(wallet.address.toLowerCase());
      expect(payload.userId).toBe(body.user.id);
    });

    it('returns the same user for the same wallet on repeat sign-in', async () => {
      const first = await signIn(wallet);
      const second = await signIn(wallet);

      expect(second.user.id).toBe(first.user.id);
    });

    it('rejects a replayed signature — the nonce is single use', async () => {
      const nonceRes = await request(app)
        .post('/api/auth/wallet/nonce')
        .send({ address: wallet.address });
      const signature = await wallet.signMessage(nonceRes.body.message);

      await request(app)
        .post('/api/auth/wallet/verify')
        .send({ address: wallet.address, signature })
        .expect(200);

      const replay = await request(app)
        .post('/api/auth/wallet/verify')
        .send({ address: wallet.address, signature })
        .expect(401);

      expect(replay.body.code).toBe('NONCE_NOT_FOUND');
    });

    it('rejects a signature produced by a different key', async () => {
      const nonceRes = await request(app)
        .post('/api/auth/wallet/nonce')
        .send({ address: wallet.address });

      const impostor = ethers.Wallet.createRandom();
      const forged = await impostor.signMessage(nonceRes.body.message);

      const res = await request(app)
        .post('/api/auth/wallet/verify')
        .send({ address: wallet.address, signature: forged })
        .expect(401);

      expect(res.body.code).toBe('SIGNATURE_MISMATCH');
    });

    it('rejects a signature over a message the server never issued', async () => {
      await request(app).post('/api/auth/wallet/nonce').send({ address: wallet.address });
      const signature = await wallet.signMessage('let me in');

      const res = await request(app)
        .post('/api/auth/wallet/verify')
        .send({ address: wallet.address, signature })
        .expect(401);

      expect(res.body.code).toBe('SIGNATURE_MISMATCH');
    });

    it('rejects verification when no nonce was requested', async () => {
      const signature = await wallet.signMessage('anything');

      const res = await request(app)
        .post('/api/auth/wallet/verify')
        .send({ address: wallet.address, signature })
        .expect(401);

      expect(res.body.code).toBe('NONCE_NOT_FOUND');
    });

    it('requires a signature', async () => {
      const res = await request(app)
        .post('/api/auth/wallet/verify')
        .send({ address: wallet.address })
        .expect(400);

      expect(res.body.code).toBe('SIGNATURE_REQUIRED');
    });
  });

  describe('wallet identity end to end', () => {
    it('lets a wallet user create an asset owned by their identity', async () => {
      const { token, user } = await signIn(wallet);

      const res = await request(app)
        .post('/api/assets')
        .set('Authorization', `Bearer ${token}`)
        .send({
          title: 'Wallet Owned Villa',
          description: 'created by a wallet-authenticated user',
          category: 'real-estate',
          price: { amount: 2500, currency: 'USDT' },
          owner: { id: 'attacker', name: 'Spoofed' },
        })
        .expect(201);

      expect(res.body.ownerId).toBe(user.id);
      expect(res.body.owner.walletAddress).toBe(wallet.address.toLowerCase());
    });
  });
});
