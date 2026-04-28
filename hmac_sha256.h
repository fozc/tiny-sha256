#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
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

#endif /* SHA256_H */
