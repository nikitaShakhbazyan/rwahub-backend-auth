# Auth improvement — RWAHub backend

Backend task: close the gap where **Sign In was mostly local client state** and
the `/api/auth` JWT was not the same thing as API identity.

## The gap, as it was

Three concrete problems in the code as delivered:

1. **Sign In never reached the backend.** `src/store/authStore.ts` compared the
   email and password against a `mockUsers` array *in the browser* and set
   `isAuthenticated: true`. No token was ever issued. A working
   `POST /api/auth/login` existed and was never called.
2. **`POST /api/assets` accepted guests.** The route used `optionalAuth`, so a
   request with no credentials at all returned `201`.
3. **Ownership came from the request body.**

   ```js
   const ownerId = req.user?.userId || req.body.owner?.id || 'guest';
   owner: req.body.owner || { id: ownerId, name: req.user?.email || 'Guest' },
   ```

   `req.body.owner` overrode the authenticated user entirely, so a caller could
   mint assets under anyone's name.

Verified against the original code before changing anything:

```
POST /api/assets   (no token, owner: {id: "victim"})   ->  201 Created
```

## How identity works now

One identity, two providers, assembled in exactly one place.

```
Sign In (wallet signature  |  email + password)
        │
        └─> services/identity.js  ──  toIdentity() → issueToken()
                   │
                   JWT { userId, email, walletAddress, roles, provider }
                   │
        middleware/auth.js  ──  authenticateToken → req.user
                   │
        routes/assets.js  ──  owner := req.user   (body ignored)
```

### `services/identity.js`

The single definition of "who the caller is". Every provider funnels through
`toIdentity()`, and `issueToken()` is the only thing that mints a JWT. Routes
never assemble an identity themselves — that is what makes `req.user`
trustworthy.

Crucially, `walletAddress` is a *field on the identity*, not a separate system.
A wallet user and a password user are the same kind of thing.

### `services/walletAuth.js` — why a signature, not an address

The frontend already knows the connected address, so the tempting shortcut is
`POST { address }` → JWT. That proves nothing: an address is a public claim, and
anyone could request a token for a wallet they do not control.

Instead, a two-step handshake:

```
POST /api/auth/wallet/nonce   { address }            -> { nonce, message }
POST /api/auth/wallet/verify  { address, signature } -> { token, user }
```

The server mints a one-time nonce, embeds it in a human-readable message, and at
verify time rebuilds that exact message and recovers the signer with
`ethers.utils.verifyMessage`. The nonce is what makes it a proof rather than a
claim — it is single-use and expires in 5 minutes, so a captured signature
cannot be replayed. The nonce is consumed on *every* verify attempt, so a wrong
guess cannot be retried against the same challenge.

A first-time wallet becomes a real user record (`findOrCreateWalletUser`), so a
wallet identity is a first-class account rather than a throwaway token subject.

### Route protection

`authenticateToken` is a hard gate: no valid token and the request never reaches
the handler, so a protected route can treat `req.user` as guaranteed.

Status codes were corrected to follow the usual meaning:

- **401** — not authenticated (missing, malformed, invalid or expired token)
- **403** — authenticated but not permitted (`requireRole`)

The original returned `403` for an invalid or expired token, which conflates the
two. Fixing this turned two previously failing tests green.

`optionalAuth` remains for public reads that render differently when signed in;
it never rejects.

### Ownership

```js
router.post('/', authenticateToken, (req, res) => {
  const owner   = db.getUserById(req.user.userId);
  const ownerId = req.user.userId;          // never req.body
  ...
  status: 'pending',                         // client cannot self-certify
  isVerified: false,
```

`owner`, `ownerId`, `status` and `isVerified` in the body are ignored. A client
cannot assign ownership to someone else, nor mark its own asset verified. The
frontend no longer sends `owner` at all, so the client contract matches the
server's.

## API contract

| Endpoint | Success | Failure |
|---|---|---|
| `POST /api/auth/wallet/nonce` | `200` `{ address, nonce, message, expiresAt }` | `400 INVALID_ADDRESS` |
| `POST /api/auth/wallet/verify` | `200` `{ user, token }` | `400 SIGNATURE_REQUIRED` · `401 NONCE_NOT_FOUND` / `NONCE_EXPIRED` / `SIGNATURE_MISMATCH` |
| `POST /api/auth/login` | `200` `{ user, token }` | `401 INVALID_CREDENTIALS` |
| `POST /api/assets` | `201` asset, owner from `req.user` | `401 AUTH_REQUIRED` / `TOKEN_INVALID` · `400 VALIDATION_ERROR` |

Errors carry a stable machine-readable `code` alongside the human `error`, and
validation returns a `details` array naming each failed field rather than one
lumped message.

Login returns an identical `401` whether the account is missing or the password
is wrong, so the response cannot be used to enumerate registered emails. The
original fell back to comparing against a hardcoded `mockUser.password` hash for
unknown emails; that path is gone.

## Where this shows in the UI

**Asset Creation** (`/asset-creation`) — a banner states whether this browser
holds an API token, and a failed submit renders the server's own message:

- signed out → `401 Unauthorized — You must sign in before creating an asset.`
- signed in → asset is created and owned by `req.user`

This required the client to stop hiding the failure: `addAsset` previously
swallowed API errors into a `console.error`, so a 401 was invisible. It now
propagates the error and rolls back the optimistic row, since otherwise the UI
would keep showing an asset the server refused to create.

## Verifying it

```bash
npm install
cp example.env .env
npm run dev        # API on :3001, app on :5173
npm test           # 11/11 wallet auth tests
```

Guest is rejected:

```bash
curl -i -X POST localhost:3001/api/assets \
  -H 'Content-Type: application/json' \
  -d '{"title":"Guest","description":"no token at all","price":{"amount":1000}}'
# 401  {"error":"Authentication required","code":"AUTH_REQUIRED"}
```

In the browser: open `/asset-creation` signed out and submit → the page shows
the 401. Connect the wallet, approve the signature request, submit again → the
asset is created and the dashboard shows it owned by your identity.

`tests/walletAuth.test.js` covers the handshake end to end, including the two
attacks that matter: a **replayed signature** and a signature from a
**different key** claiming someone else's address. Both are rejected.

## Decisions worth noting

**Rate limiters are pass-through under `NODE_ENV=test`.** The auth suite
deliberately makes many failing attempts and would otherwise trip the 5-per-15-
minutes limiter and get `429` instead of the status under test. The limiter is
real in dev and production.

**The token lives in `localStorage` via one module** (`src/utils/authToken.ts`)
that both the Zustand store and the plain API client can use, avoiding an import
cycle.

**Existing tests were updated, not deleted.** Three `POST /api/assets` tests
posted without a token and asserted `201`/`400` — they encoded the insecure
contract. They now authenticate, and three tests were added for the guest 401,
the invalid-token 401, and body-spoofing being ignored.

Test suite went from **47 failed / 20 passed** to **42 failed / 39 passed**. The
42 remaining failures are pre-existing and unrelated (asset filters, `PATCH`,
validation requests) — they fail identically on the untouched original.

## What I would improve next

- **Nonces are in memory.** Correct for this demo, wrong for production: a
  restart or a second instance drops them. They belong in Redis with a TTL.
- **Short-lived access token + refresh token.** The current JWT lives 7 days and
  cannot be revoked. `/api/auth/refresh` exists but there is no rotation or
  denylist, so a leaked token is valid until expiry.
- **Adopt SIWE (EIP-4361)** for the message format, including domain and chain
  id, instead of the bespoke string — it is the standard and resists phishing
  across origins.
- **Bind the wallet to an existing account.** A wallet sign-in currently always
  creates its own user; a signed-in user should be able to attach a wallet to
  the account they already have.
- **Apply the same ownership rule to the remaining write routes** — `PATCH`
  already checks ownership, but transactions and validation requests deserve the
  same audit.
- **The user store is an in-memory `Map`.** Everything resets on restart; this
  needs a real database before any of the above matters.
