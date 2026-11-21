#ifndef HMAC_SHA256_H
#define HMAC_SHA256_H

#include "sha256.h"
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PBKDF2_SHA256_SALT_SIZE 16U

typedef struct
{
    sha256_ctx_t inner_ctx;
    uint8_t outer_pad[64U];
} hmac_sha256_ctx;

void hmac_sha256_init(hmac_sha256_ctx *ctx, const uint8_t *key, size_t key_len);
void hmac_sha256_update(hmac_sha256_ctx *ctx, const uint8_t *data, size_t data_len);
void hmac_sha256_final(hmac_sha256_ctx *ctx, uint8_t mac[32U]);

void hmac_sha256(uint8_t mac[32U],
                 const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len);

/* Gecersiz bir girdi verildiginde false doner ve ciktiya yazmaz. */
bool pbkdf2_hmac_sha256(uint8_t output[32U], const uint8_t *password,
                       size_t password_len, const uint8_t salt[PBKDF2_SHA256_SALT_SIZE],
                       uint32_t iterations);

#ifdef __cplusplus
}
#endif

#endif /* HMAC_SHA256_H */
