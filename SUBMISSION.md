GitHub:
https://github.com/nikitaShakhbazyan/rwahub-backend-auth

Loom:
[PASTE LOOM LINK HERE]

Summary:

**How identity now works (Sign In → JWT → protected routes)**

Sign In never reached the backend before: `authStore.ts` compared credentials
against a `mockUsers` array in the browser and set `isAuthenticated: true`. No
token was issued, so the client believed it was signed in while the API had no
idea who it was. A working `POST /api/auth/login` existed and was never called.

Identity is now defined in one place — `src/server/services/identity.js`. Every
provider funnels through `toIdentity()`, and `issueToken()` is the only thing
that mints a JWT:

    Sign In (wallet signature | email + password)
          └─> identity.js — toIdentity() → issueToken()
                   JWT { userId, email, walletAddress, roles, provider }
          └─> middleware/auth.js — authenticateToken → req.user
          └─> routes/assets.js — owner := req.user (body ignored)

`walletAddress` is a field *on* that identity, not a parallel system. A wallet
user and a password user are the same kind of thing — which is exactly what
closes the stated gap. Routes never assemble an identity themselves; they only
read the one the middleware attached, and that is what makes `req.user`
trustworthy.

Wallet sign-in is a nonce handshake, not an address exchange:

    POST /api/auth/wallet/nonce   { address }            → { nonce, message }
    POST /api/auth/wallet/verify  { address, signature } → { token, user }

The server mints a one-time nonce, embeds it in a readable message, then at
verify time rebuilds that exact message and recovers the signer with
`verifyMessage`. The nonce is single-use, expires in 5 minutes, and is consumed
on every attempt — so a signature cannot be replayed and a wrong guess cannot be
retried against the same challenge.

**How POST /api/assets uses req.user and rejects guests**

    router.post('/', authenticateToken, (req, res) => {
      const ownerId = req.user.userId;   // never req.body
      ...
      status: 'pending', isVerified: false

Three changes. The route is gated with `authenticateToken` instead of
`optionalAuth`, so an unauthenticated request never reaches the handler.
Ownership comes from the token: the original computed
`req.user?.userId || req.body.owner?.id || 'guest'` and then wrote
`owner: req.body.owner || {...}` — the body overrode the authenticated user
entirely, so anyone could mint assets under someone else's name. Now `owner`,
`ownerId`, `status` and `isVerified` in the body are ignored outright, not used
as a fallback. And status codes follow their meaning: 401 for unauthenticated,
403 reserved for authenticated-but-forbidden (invalid tokens previously returned
403, which conflates the two).

Measured on the original code, then after:

    before:  POST /api/assets (no token, owner: {id:"victim"})  → 201 Created
    after:   no token         → 401 AUTH_REQUIRED
             bad token        → 401 TOKEN_INVALID
             valid JWT + spoofed owner → 201, owner from req.user, spoof ignored

**Which existing UI page shows success and 401**

Asset Creation — `/asset-creation`. A banner states whether this browser holds
an API token. Submitting signed out renders the server's refusal:
`401 Unauthorized — You must sign in before creating an asset.` After connecting
the wallet and approving the signature, submitting succeeds and the asset is
owned by `req.user`.

Two things had to change for this to be visible. `addAsset` previously swallowed
API failures into a `console.error`, so a 401 was invisible and the user saw a
false success; it now propagates the error and rolls back the optimistic row.
The route also sat behind `RequireAuth`, which redirected guests away — so the
required scenario could not be reproduced. Authorization for creating an asset
belongs to the API, not the router; the client guard only concealed the gap this
task is about. Dashboard, explorer, profile and my-assets stay behind
`RequireAuth` — those are views of a user's own data.

**Architecture decisions**

*One identity, two providers.* Password and wallet resolve to the same
normalized `req.user`. Treating the wallet as a separate rail is what produced
the original gap.

*Nonce + signature over a plain address exchange.* The frontend already knows
the connected address, so `POST { address }` → JWT would have been one line. But
an address is a public claim, not a proof — anyone could request a token for a
wallet they do not control. This is the decision I would most want to defend.

*Ownership is server-assigned, never client-asserted.* Identity-bearing fields
in the body are discarded rather than merged. Trusting them even as a fallback
is precisely what made the original exploitable.

*401 vs 403 separated.* "I don't know who you are" and "I know, and you may not"
are different answers.

*No user enumeration.* Login returns an identical 401 whether the account is
missing or the password is wrong. The original fell back to comparing against a
hardcoded hash for unknown emails, leaking existence through timing.

*Error contract.* Responses carry a stable `code` alongside the human-readable
`error`, and validation returns a `details` array naming each failed field — so
a client can branch on a 401 without parsing prose.

*Tests were updated, not deleted.* Three `POST /api/assets` tests posted without
a token and asserted 201 — they encoded the insecure contract. They now
authenticate, plus three new ones for the guest 401, invalid-token 401, and
body-spoofing being ignored. Suite went from 47 failed / 20 passed to 42 failed
/ 39 passed, plus 11 new wallet-auth tests covering the two attacks that matter:
a replayed signature and a signature from a different key claiming someone
else's address. The 42 remaining failures are pre-existing and unrelated — they
fail identically on the untouched original.

Solidity and Hardhat are untouched; `.env` is untracked and gitignored.

**What I would improve next**

- Nonces live in memory — fine here, wrong in production: a restart or a second
  instance drops them. They belong in Redis with a TTL.
- Short-lived access token plus refresh rotation. The JWT lives 7 days and
  cannot be revoked; `/api/auth/refresh` exists but has no rotation or denylist.
- Adopt SIWE (EIP-4361) for the message format, including domain and chain id,
  instead of the bespoke string — it is the standard and resists cross-origin
  phishing.
- Let a signed-in user bind a wallet to their existing account; today a wallet
  sign-in always creates its own user.
- Apply the same ownership audit to the remaining write routes — `PATCH` already
  checks it, transactions and validation requests deserve the same.
- The user store is an in-memory `Map`; everything resets on restart. A real
  database comes before any of the above matters.
