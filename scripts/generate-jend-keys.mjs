import { webcrypto } from "node:crypto";

const { subtle } = webcrypto;
const pair = await subtle.generateKey(
  { name: "ECDH", namedCurve: "P-256" },
  true,
  ["deriveBits"]
);
const privateJwk = await subtle.exportKey("jwk", pair.privateKey);
const publicJwk = await subtle.exportKey("jwk", pair.publicKey);

for (const jwk of [privateJwk, publicJwk]) {
  delete jwk.key_ops;
  delete jwk.alg;
  delete jwk.use;
}

console.log("\nJEND_PRIVATE_JWK (Cloudflare Secret):\n");
console.log(JSON.stringify(privateJwk));
console.log("\nJEND_PUBLIC_JWK (для проверки; добавлять в Cloudflare не нужно):\n");
console.log(JSON.stringify(publicJwk));
console.log("\nВажно: приватный JWK не сохраняйте в GitHub, .env или .dev.vars в репозитории.\n");
