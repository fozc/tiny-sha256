#ifndef HMAC_SHA256_H
#define HMAC_SHA256_H

#include "sha256.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void hmac_sha256(uint8_t mac[32],
                 const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len);

#ifdef __cplusplus
}
#endif

#endif /* HMAC_SHA256_H */
