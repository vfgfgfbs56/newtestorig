#include <stdint.h>

static inline uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
static inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
static inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
static inline uint32_t bsig0(uint32_t x) { return rotr(x,2) ^ rotr(x,13) ^ rotr(x,22); }
static inline uint32_t bsig1(uint32_t x) { return rotr(x,6) ^ rotr(x,11) ^ rotr(x,25); }
static inline uint32_t ssig0(uint32_t x) { return rotr(x,7) ^ rotr(x,18) ^ (x >> 3); }
static inline uint32_t ssig1(uint32_t x) { return rotr(x,17) ^ rotr(x,19) ^ (x >> 10); }

static const uint32_t K[64] = {
  0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
  0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
  0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
  0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
  0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
  0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
  0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
  0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

static void sha256_36(const uint8_t msg[36], uint8_t out[32]) {
  uint8_t block[64] = {0};
  for (int i = 0; i < 36; ++i) block[i] = msg[i];
  block[36] = 0x80;
  const uint64_t bitlen = 36ull * 8ull;
  for (int i = 0; i < 8; ++i) block[63 - i] = (uint8_t)(bitlen >> (8 * i));

  uint32_t w[64];
  for (int i = 0; i < 16; ++i) {
    const int j = i * 4;
    w[i] = ((uint32_t)block[j] << 24) | ((uint32_t)block[j+1] << 16) |
           ((uint32_t)block[j+2] << 8) | (uint32_t)block[j+3];
  }
  for (int i = 16; i < 64; ++i) w[i] = ssig1(w[i-2]) + w[i-7] + ssig0(w[i-15]) + w[i-16];

  uint32_t a=0x6a09e667u,b=0xbb67ae85u,c=0x3c6ef372u,d=0xa54ff53au;
  uint32_t e=0x510e527fu,f=0x9b05688cu,g=0x1f83d9abu,h=0x5be0cd19u;
  for (int i = 0; i < 64; ++i) {
    const uint32_t t1 = h + bsig1(e) + ch(e,f,g) + K[i] + w[i];
    const uint32_t t2 = bsig0(a) + maj(a,b,c);
    h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
  }
  uint32_t H[8] = {
    0x6a09e667u+a,0xbb67ae85u+b,0x3c6ef372u+c,0xa54ff53au+d,
    0x510e527fu+e,0x9b05688cu+f,0x1f83d9abu+g,0x5be0cd19u+h
  };
  for (int i = 0; i < 8; ++i) {
    out[i*4]   = (uint8_t)(H[i] >> 24);
    out[i*4+1] = (uint8_t)(H[i] >> 16);
    out[i*4+2] = (uint8_t)(H[i] >> 8);
    out[i*4+3] = (uint8_t)H[i];
  }
}

static int has_leading_zero_bits(const uint8_t hash[32], uint32_t bits) {
  const uint32_t full = bits / 8;
  const uint32_t rem = bits % 8;
  for (uint32_t i = 0; i < full; ++i) if (hash[i] != 0) return 0;
  if (rem) {
    const uint8_t mask = (uint8_t)(0xffu << (8 - rem));
    if ((hash[full] & mask) != 0) return 0;
  }
  return 1;
}

extern "C" __attribute__((visibility("default"))) int32_t solve(
  uint32_t w0, uint32_t w1, uint32_t w2, uint32_t w3,
  uint32_t w4, uint32_t w5, uint32_t w6, uint32_t w7,
  uint32_t difficulty, uint32_t start, uint32_t max_iters
) {
  if (difficulty < 8 || difficulty > 28 || max_iters == 0) return -1;
  const uint32_t words[8] = {w0,w1,w2,w3,w4,w5,w6,w7};
  uint8_t msg[36];
  for (int i = 0; i < 8; ++i) {
    msg[i*4]   = (uint8_t)words[i];
    msg[i*4+1] = (uint8_t)(words[i] >> 8);
    msg[i*4+2] = (uint8_t)(words[i] >> 16);
    msg[i*4+3] = (uint8_t)(words[i] >> 24);
  }

  uint8_t hash[32];
  for (uint32_t i = 0; i < max_iters; ++i) {
    const uint32_t counter = start + i;
    msg[32] = (uint8_t)counter;
    msg[33] = (uint8_t)(counter >> 8);
    msg[34] = (uint8_t)(counter >> 16);
    msg[35] = (uint8_t)(counter >> 24);
    sha256_36(msg, hash);
    if (has_leading_zero_bits(hash, difficulty)) return (int32_t)counter;
  }
  return -1;
}
