// Host test stub for mbedtls/md.h, implementing the small subset of the
// mbedtls_md_* HMAC API that firmware/common/crypto_envelope.h uses. This
// is a real (not fake) HMAC-SHA256 -- crypto_envelope.h's sign/verify round
// trip must actually work for the replay-state-machine tests to be
// meaningful -- just self-contained so the host test doesn't need a system
// mbedtls install.
#ifndef HOST_STUB_MBEDTLS_MD_H
#define HOST_STUB_MBEDTLS_MD_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

// ---- SHA-256 core (public-domain algorithm, standard constants) -----------

typedef struct {
  uint8_t data[64];
  uint32_t datalen;
  uint64_t bitlen;
  uint32_t state[8];
} host_sha256_ctx;

#define HOST_SHA256_ROTR(a, b) (((a) >> (b)) | ((a) << (32 - (b))))

static const uint32_t host_sha256_k[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void host_sha256_transform(host_sha256_ctx *ctx, const uint8_t data[]) {
  uint32_t a, b, c, d, e, f, g, h, t1, t2, m[64];
  int i, j;
  for (i = 0, j = 0; i < 16; i++, j += 4)
    m[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j+1] << 16) |
           ((uint32_t)data[j+2] << 8) | ((uint32_t)data[j+3]);
  for (; i < 64; i++) {
    uint32_t s0 = HOST_SHA256_ROTR(m[i-15], 7) ^ HOST_SHA256_ROTR(m[i-15], 18) ^ (m[i-15] >> 3);
    uint32_t s1 = HOST_SHA256_ROTR(m[i-2], 17) ^ HOST_SHA256_ROTR(m[i-2], 19) ^ (m[i-2] >> 10);
    m[i] = m[i-16] + s0 + m[i-7] + s1;
  }

  a=ctx->state[0]; b=ctx->state[1]; c=ctx->state[2]; d=ctx->state[3];
  e=ctx->state[4]; f=ctx->state[5]; g=ctx->state[6]; h=ctx->state[7];

  for (i = 0; i < 64; i++) {
    uint32_t S1 = HOST_SHA256_ROTR(e,6) ^ HOST_SHA256_ROTR(e,11) ^ HOST_SHA256_ROTR(e,25);
    uint32_t ch = (e & f) ^ (~e & g);
    t1 = h + S1 + ch + host_sha256_k[i] + m[i];
    uint32_t S0 = HOST_SHA256_ROTR(a,2) ^ HOST_SHA256_ROTR(a,13) ^ HOST_SHA256_ROTR(a,22);
    uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    t2 = S0 + maj;
    h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
  }

  ctx->state[0]+=a; ctx->state[1]+=b; ctx->state[2]+=c; ctx->state[3]+=d;
  ctx->state[4]+=e; ctx->state[5]+=f; ctx->state[6]+=g; ctx->state[7]+=h;
}

static void host_sha256_init(host_sha256_ctx *ctx) {
  ctx->datalen = 0;
  ctx->bitlen = 0;
  ctx->state[0]=0x6a09e667; ctx->state[1]=0xbb67ae85;
  ctx->state[2]=0x3c6ef372; ctx->state[3]=0xa54ff53a;
  ctx->state[4]=0x510e527f; ctx->state[5]=0x9b05688c;
  ctx->state[6]=0x1f83d9ab; ctx->state[7]=0x5be0cd19;
}

static void host_sha256_update(host_sha256_ctx *ctx, const uint8_t data[], size_t len) {
  for (size_t i = 0; i < len; i++) {
    ctx->data[ctx->datalen++] = data[i];
    if (ctx->datalen == 64) {
      host_sha256_transform(ctx, ctx->data);
      ctx->bitlen += 512;
      ctx->datalen = 0;
    }
  }
}

static void host_sha256_final(host_sha256_ctx *ctx, uint8_t hash[32]) {
  uint32_t i = ctx->datalen;

  if (ctx->datalen < 56) {
    ctx->data[i++] = 0x80;
    while (i < 56) ctx->data[i++] = 0x00;
  } else {
    ctx->data[i++] = 0x80;
    while (i < 64) ctx->data[i++] = 0x00;
    host_sha256_transform(ctx, ctx->data);
    memset(ctx->data, 0, 56);
  }

  ctx->bitlen += (uint64_t)ctx->datalen * 8;
  for (int k = 0; k < 8; k++)
    ctx->data[63 - k] = (uint8_t)(ctx->bitlen >> (8 * k));
  host_sha256_transform(ctx, ctx->data);

  for (i = 0; i < 4; i++) {
    for (int j = 0; j < 8; j++)
      hash[j * 4 + i] = (uint8_t)(ctx->state[j] >> (24 - i * 8));
  }
}

static void host_hmac_sha256(const uint8_t *key, size_t key_len,
                              const uint8_t *msg, size_t msg_len,
                              uint8_t out[32]) {
  uint8_t k[64] = {0};
  if (key_len > 64) {
    host_sha256_ctx c;
    host_sha256_init(&c);
    host_sha256_update(&c, key, key_len);
    host_sha256_final(&c, k);
  } else {
    memcpy(k, key, key_len);
  }

  uint8_t i_key_pad[64], o_key_pad[64];
  for (int i = 0; i < 64; i++) {
    i_key_pad[i] = k[i] ^ 0x36;
    o_key_pad[i] = k[i] ^ 0x5c;
  }

  uint8_t inner_hash[32];
  host_sha256_ctx ctx;
  host_sha256_init(&ctx);
  host_sha256_update(&ctx, i_key_pad, 64);
  host_sha256_update(&ctx, msg, msg_len);
  host_sha256_final(&ctx, inner_hash);

  host_sha256_init(&ctx);
  host_sha256_update(&ctx, o_key_pad, 64);
  host_sha256_update(&ctx, inner_hash, 32);
  host_sha256_final(&ctx, out);
}

// ---- mbedtls_md_* HMAC subset used by crypto_envelope.h -------------------

typedef int mbedtls_md_type_t;
#define MBEDTLS_MD_SHA256 1

typedef struct { int type; } mbedtls_md_info_t;
static const mbedtls_md_info_t host_md_sha256_info = { MBEDTLS_MD_SHA256 };

typedef struct {
  uint8_t key[64];
  int key_len;
  uint8_t buf[512];
  int buf_len;
} mbedtls_md_context_t;

static inline const mbedtls_md_info_t *mbedtls_md_info_from_type(mbedtls_md_type_t t) {
  (void)t;
  return &host_md_sha256_info;
}

static inline void mbedtls_md_init(mbedtls_md_context_t *ctx) {
  memset(ctx, 0, sizeof(*ctx));
}

static inline int mbedtls_md_setup(mbedtls_md_context_t *ctx,
                                    const mbedtls_md_info_t *info, int hmac) {
  (void)info; (void)hmac;
  ctx->key_len = 0;
  ctx->buf_len = 0;
  return 0;
}

static inline int mbedtls_md_hmac_starts(mbedtls_md_context_t *ctx,
                                          const unsigned char *key, size_t keylen) {
  if (keylen > sizeof(ctx->key)) keylen = sizeof(ctx->key);
  memcpy(ctx->key, key, keylen);
  ctx->key_len = (int)keylen;
  ctx->buf_len = 0;
  return 0;
}

static inline int mbedtls_md_hmac_update(mbedtls_md_context_t *ctx,
                                          const unsigned char *data, size_t len) {
  if (ctx->buf_len + (int)len > (int)sizeof(ctx->buf))
    len = sizeof(ctx->buf) - ctx->buf_len;
  memcpy(ctx->buf + ctx->buf_len, data, len);
  ctx->buf_len += (int)len;
  return 0;
}

static inline int mbedtls_md_hmac_finish(mbedtls_md_context_t *ctx, unsigned char *output) {
  host_hmac_sha256(ctx->key, (size_t)ctx->key_len, ctx->buf, (size_t)ctx->buf_len, output);
  return 0;
}

static inline void mbedtls_md_free(mbedtls_md_context_t *ctx) { (void)ctx; }

#endif
