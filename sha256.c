#include "sha256.h"
#include <string.h>

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  /* Big-endian: SHA-256 is natively big-endian, no swap needed */
  #define BSWAP32(x) (x)
#elif defined(__GNUC__) || defined(__clang__)
  #define BSWAP32(x) __builtin_bswap32(x)
#elif defined(_MSC_VER)
  #include <stdlib.h>
  #define BSWAP32(x) _byteswap_ulong(x)
#else
  static inline uint32_t BSWAP32(uint32_t x) {
      return ((x >> 24) & 0x000000FF) |
             ((x >>  8) & 0x0000FF00) |
             ((x <<  8) & 0x00FF0000) |
             ((x << 24) & 0xFF000000);
  }
#endif

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

 
static void sha256_process_block(uint32_t h[8], const uint8_t block[64]) {
    uint32_t w[16];
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3],
             e = h[4], f = h[5], g = h[6], hh = h[7];

    for (int i = 0; i < 64; i++) {
        uint32_t wi;
        if (i < 16) {
            /* Big-endian load: Cortex-M4'te LDR + REV */
            uint32_t tmp;
            memcpy(&tmp, &block[i * 4], 4);
            wi = BSWAP32(tmp);
            w[i] = wi;
        } else {
            uint32_t w15 = w[(i - 15) & 0xF];
            uint32_t w2  = w[(i -  2) & 0xF];
            uint32_t s0  = ROR32(w15, 7)  ^ ROR32(w15, 18) ^ (w15 >> 3);
            uint32_t s1  = ROR32(w2,  17) ^ ROR32(w2,  19) ^ (w2  >> 10);
            wi = w[(i - 16) & 0xF] + s0 + w[(i - 7) & 0xF] + s1;
            w[i & 0xF] = wi;
        }

        uint32_t S1    = ROR32(e, 6)  ^ ROR32(e, 11) ^ ROR32(e, 25);
        uint32_t ch    = g ^ (e & (f ^ g));
        uint32_t temp1 = hh + S1 + ch + K[i] + wi;
        uint32_t S0    = ROR32(a, 2)  ^ ROR32(a, 13) ^ ROR32(a, 22);
        uint32_t maj   = (a & b) ^ (c & (a ^ b));
        uint32_t temp2 = S0 + maj;

        hh = g; g = f; f = e; e = d + temp1;
        d  = c; c = b; b = a; a = temp1 + temp2;
    }

    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

 
static void sha256_write_be32(uint8_t *dst, const uint32_t *src, int count) {
    for (int i = 0; i < count; i++) {
        uint32_t tmp = BSWAP32(src[i]);
        memcpy(&dst[i * 4], &tmp, 4);
    }
}

 
void sha256_init(sha256_ctx *ctx) {
    ctx->h[0] = 0x6a09e667; ctx->h[1] = 0xbb67ae85;
    ctx->h[2] = 0x3c6ef372; ctx->h[3] = 0xa54ff53a;
    ctx->h[4] = 0x510e527f; ctx->h[5] = 0x9b05688c;
    ctx->h[6] = 0x1f83d9ab; ctx->h[7] = 0x5be0cd19;
    ctx->block_len = 0;
    ctx->total_len = 0;
}

void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len) {
    ctx->total_len += len;
 
    if (ctx->block_len > 0) {
        size_t need = 64 - ctx->block_len;
        if (len < need) {
            memcpy(ctx->block + ctx->block_len, data, len);
            ctx->block_len += (uint8_t)len;
            return;
        }
        memcpy(ctx->block + ctx->block_len, data, need);
        sha256_process_block(ctx->h, ctx->block);
        data += need;
        len  -= need;
        ctx->block_len = 0;
    }
 
    while (len >= 64) {
        sha256_process_block(ctx->h, data);
        data += 64;
        len  -= 64;
    }
 
    if (len > 0) {
        memcpy(ctx->block, data, len);
        ctx->block_len = (uint8_t)len;
    }
}

void sha256_final(sha256_ctx *ctx, uint8_t hash[32]) {
    uint8_t *block = ctx->block;
    size_t remaining = ctx->block_len;
 
    block[remaining++] = 0x80;
    memset(block + remaining, 0, 64 - remaining);
 
    if (remaining > 56) {
        sha256_process_block(ctx->h, block);
        memset(block, 0, 64);
    }

    uint64_t bit_len = ctx->total_len * 8;
    block[56] = (uint8_t)(bit_len >> 56);
    block[57] = (uint8_t)(bit_len >> 48);
    block[58] = (uint8_t)(bit_len >> 40);
    block[59] = (uint8_t)(bit_len >> 32);
    block[60] = (uint8_t)(bit_len >> 24);
    block[61] = (uint8_t)(bit_len >> 16);
    block[62] = (uint8_t)(bit_len >>  8);
    block[63] = (uint8_t)(bit_len);

    sha256_process_block(ctx->h, block);

    /* (big-endian) */
    sha256_write_be32(hash, ctx->h, 8);

    memset(ctx, 0, sizeof(*ctx));
}
 
void sha256(const uint8_t *data, size_t len, uint8_t hash[32]) {
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, hash);
}