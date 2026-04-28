#include "sha256.h"
#include <string.h>

void hmac_sha256(uint8_t mac[32],
                 const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len)
{
    uint8_t k_pad[64];
    sha256_ctx ctx;
    uint8_t inner[32];

    /* Key > 64 byte ise hash'le */
    uint8_t key_hash[32];
    if (key_len > 64) {
        sha256(key, key_len, key_hash);
        key = key_hash;
        key_len = 32;
    }

    /* ipad */
    memset(k_pad, 0x36, 64);
    for (size_t i = 0; i < key_len; i++) k_pad[i] ^= key[i];

    sha256_init(&ctx);
    sha256_update(&ctx, k_pad, 64);
    sha256_update(&ctx, data, data_len);
    sha256_final(&ctx, inner);

    /* opad */
    memset(k_pad, 0x5c, 64);
    for (size_t i = 0; i < key_len; i++) k_pad[i] ^= key[i];

    sha256_init(&ctx);
    sha256_update(&ctx, k_pad, 64);
    sha256_update(&ctx, inner, 32);
    sha256_final(&ctx, mac);
}
