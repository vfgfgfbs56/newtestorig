# JEND Guard v1

JEND Guard is the project's own anti-automation layer. It is not a CAPTCHA and it does not claim to prove that a human is present. Its purpose is to make bulk automation expensive and replay-resistant while keeping the normal UI frictionless.

## Flow

1. Browser requests `/api/security/challenge?action=register|qr-create`.
2. Worker creates a random 256-bit seed, one-time challenge id, expiry and difficulty.
3. Challenge is bound in D1 to the request action and an HMAC of the client IP + User-Agent. The raw IP is not stored.
4. `public/guard/jend-guard-v1.wasm`, compiled from `native/guard.cpp`, searches for a 32-bit counter such that:

   `SHA-256(seed || uint32_le(counter))`

   has the required number of leading zero bits.
5. Browser places `{ id, counter }` inside the already encrypted JEND request.
6. Worker recomputes one SHA-256, checks action/binding/expiry, then atomically marks the challenge used.
7. Reuse, expiry or a wrong counter is rejected.

## Current difficulty

- QR creation starts at 17 leading zero bits.
- Registration starts at 18 leading zero bits.
- If one client requests many challenges in a minute, difficulty rises automatically by up to +2 bits.
- Challenge TTL: 90 seconds.

The Worker verifies a proof cheaply; the client performs the expensive search. Difficulty can be adjusted in `worker/security.js` without changing the WASM format.

## WASM

The committed binary is `public/guard/jend-guard-v1.wasm` and is only about a few KB. Cloudflare does not need a C++ compiler because the binary is committed to GitHub and Vite copies `public/` into `dist/`.

Source: `native/guard.cpp`.

Rebuild locally on macOS/Linux with Clang:

```bash
npm run guard:build
```

Do not replace SHA-256 with a homemade cryptographic hash. The custom part is the challenge protocol and WASM execution; the cryptographic primitive remains standard SHA-256.

## Security properties

JEND Guard adds:

- one-time server challenges;
- short TTL;
- action binding;
- client-binding without storing raw IP;
- computational cost per registration / QR creation;
- atomic consumption to prevent replay;
- existing D1 rate limits;
- existing JEND ECDH + HKDF + AES-GCM envelope.

It does **not** make automation impossible. A bot that runs a real browser can execute the WASM too, but must pay the same proof-of-work cost and remains subject to server rate limits.
