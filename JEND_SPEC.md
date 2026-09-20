# JEND v1

`JEND` — собственный бинарный транспортный контейнер проекта. Это **не собственный криптоалгоритм**: внутри используются стандартные ECDH P-256, HKDF-SHA-256 и AES-256-GCM.

HTTP Content-Type:

```text
application/jend
```

## Request packet

```text
0..3    ASCII "JEND"
4       version = 1
5       kind = 0 (request)
6..9    issued_at, uint32 big-endian
10..25  request_id, 16 random bytes
26..90  ephemeral ECDH P-256 public key, raw/uncompressed, 65 bytes
91..102 AES-GCM IV, 12 random bytes
103..   AES-GCM ciphertext + authentication tag
```

Key agreement:

```text
client ephemeral private key
        +
server public ECDH key
        ↓
ECDH P-256 shared secret
        ↓
HKDF-SHA-256
 salt = request_id
 info = JEND/1/request/<API path>
        ↓
AES-256-GCM request key
```

AAD:

```text
JEND/1/request\n<API path>\n<issued_at>\n<base64url request_id>
```

The plaintext is UTF-8 JSON, but it exists only inside authenticated ciphertext while crossing the application API boundary.

## Response packet

```text
0..3    ASCII "JEND"
4       version = 1
5       kind = 1 (response)
6..9    issued_at, uint32 big-endian
10..25  same request_id
26..37  AES-GCM IV, 12 random bytes
38..    AES-GCM ciphertext + authentication tag
```

The response key is independently derived with:

```text
info = JEND/1/response/<API path>
```

## Replay protection

State-changing JEND requests write only their random `request_id` and a short expiration timestamp to D1. A second request with the same identifier is rejected.

## What JEND does not replace

JEND is an additional application-layer envelope. It does not replace HTTPS/TLS, JEND Guard, rate limiting, session security or device signatures.
