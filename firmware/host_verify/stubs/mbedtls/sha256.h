// Host test stub for mbedtls/sha256.h. ota_verify.h's streaming SHA-256
// (ota_verify_sha_begin/update/finish) isn't exercised by the R5-03
// journal/recovery behavioral test -- this only needs to type-check.
#ifndef HOST_STUB_MBEDTLS_SHA256_H
#define HOST_STUB_MBEDTLS_SHA256_H

#include <stddef.h>
#include <stdint.h>

typedef struct { int unused; } mbedtls_sha256_context;

static inline void mbedtls_sha256_init(mbedtls_sha256_context *ctx) { (void)ctx; }
static inline void mbedtls_sha256_starts(mbedtls_sha256_context *ctx, int is224) { (void)ctx; (void)is224; }
static inline void mbedtls_sha256_update(mbedtls_sha256_context *ctx, const unsigned char *in, size_t len) {
  (void)ctx; (void)in; (void)len;
}
static inline void mbedtls_sha256_finish(mbedtls_sha256_context *ctx, unsigned char out[32]) {
  (void)ctx; (void)out;
}
static inline void mbedtls_sha256_free(mbedtls_sha256_context *ctx) { (void)ctx; }
static inline void mbedtls_sha256(const unsigned char *in, size_t len, unsigned char out[32], int is224) {
  (void)in; (void)len; (void)out; (void)is224;
}

#endif
