/* SHA-256 (FIPS 180-4), freestanding C17. No standard library. */
#ifndef AN_SHA256_H
#define AN_SHA256_H

#include <stdint.h>

typedef struct {
  uint32_t h[8];
  uint8_t buf[64];
  uint32_t fill;  /* bytes waiting in buf, 0..63 */
  uint64_t total; /* bytes hashed so far */
} an_sha256_ctx;

void an_sha256_init(an_sha256_ctx *c);
void an_sha256_update(an_sha256_ctx *c, const uint8_t *p, uint32_t n);
void an_sha256_final(an_sha256_ctx *c, uint8_t out[32]);
void an_sha256(const uint8_t *p, uint32_t n, uint8_t out[32]);

#endif
