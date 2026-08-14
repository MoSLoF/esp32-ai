// Host test stub for mbedtls/pk.h. ota_verify_manifest()'s ECDSA
// signature check isn't exercised by the R5-03 journal/recovery behavioral
// test (it targets the counter/partition state machine, not manifest
// signing) -- this only needs to type-check.
#ifndef HOST_STUB_MBEDTLS_PK_H
#define HOST_STUB_MBEDTLS_PK_H

#include <stddef.h>

typedef struct { int unused; } mbedtls_pk_context;

#ifndef MBEDTLS_MD_SHA256
#define MBEDTLS_MD_SHA256 1
#endif

static inline void mbedtls_pk_init(mbedtls_pk_context *ctx) { (void)ctx; }
static inline void mbedtls_pk_free(mbedtls_pk_context *ctx) { (void)ctx; }
static inline int mbedtls_pk_parse_public_key(mbedtls_pk_context *ctx,
                                               const unsigned char *key, size_t keylen) {
  (void)ctx; (void)key; (void)keylen;
  return -1; // never actually called by the R5-03 test
}
static inline int mbedtls_pk_verify(mbedtls_pk_context *ctx, int md_alg,
                                     const unsigned char *hash, size_t hash_len,
                                     const unsigned char *sig, size_t sig_len) {
  (void)ctx; (void)md_alg; (void)hash; (void)hash_len; (void)sig; (void)sig_len;
  return -1;
}

#endif
