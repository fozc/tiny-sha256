# tiny-sha256

Lightweight SHA-256 implementation optimized for Cortex-M4 microcontrollers.

- **~1 KB flash** (`-Os`), **0 bytes BSS**, **~200 bytes runtime RAM**
- No dynamic memory allocation — fully stack-based
- No dependencies beyond `<string.h>`, `<stdint.h>`, `<stddef.h>`
- Portable: GCC, Clang, MSVC, any C99 compiler

## API

### One-shot

Hash all data in a single call:

```c
#include "sha256.h"

uint8_t hash[32];
sha256((const uint8_t *)"abc", 3, hash);
```

### Incremental

Feed data in chunks — ideal for UART, SPI, DMA, or file streaming:

```c
sha256_ctx ctx;
sha256_init(&ctx);
sha256_update(&ctx, buf1, len1);
sha256_update(&ctx, buf2, len2);
sha256_final(&ctx, hash);
```

## Salt usage

A salt is a random value prepended to the data before hashing. It ensures
identical inputs produce different hashes, preventing rainbow table attacks.

The incremental API supports this naturally — no extra function needed:

```c
uint8_t salt[16];  // 16+ bytes, generated from RNG/TRNG
uint8_t hash[32];

sha256_ctx ctx;
sha256_init(&ctx);
sha256_update(&ctx, salt, sizeof(salt));       // salt first
sha256_update(&ctx, password, password_len);   // then data
sha256_final(&ctx, hash);

// Store: salt (plaintext) + hash
// Verify: recompute with same salt, compare hash
```

**Notes:**
- Use at least 16 bytes of salt (128-bit)
- Generate a unique salt per entry — never reuse
- Salt is not secret — store it alongside the hash
- For password storage, prefer key-stretching (PBKDF2, bcrypt) when resources allow

## Building

```
gcc -O2 -o test_sha256 test/test_sha256.c sha256.c -I.
```

## Testing

```
cd test
gcc -O2 -I.. -o test_sha256 test_sha256.c ../sha256.c
./test_sha256
```

The test suite includes:
- NIST FIPS 180-4 known-answer vectors
- Padding boundary tests (55, 56, 63, 64, 65, 119, 128 bytes)
- Incremental API edge cases (1-byte chunks, empty updates, block crossing)
- 1,000,000 x 'a' long data test
- 512 KB pseudo-random file hash test

## License

Public domain / your project's license.
