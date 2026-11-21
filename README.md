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
sha256_ctx_t ctx;
sha256_init(&ctx);
sha256_update(&ctx, buf1, len1);
sha256_update(&ctx, buf2, len2);
sha256_final(&ctx, hash);
```

### HMAC-SHA-256

Compute a keyed message authentication code (RFC 2104 / RFC 4231):

```c
#include "hmac_sha256.h"

uint8_t mac[32];
hmac_sha256(mac,
            key,  key_len,
            data, data_len);
```

For input delivered in chunks, initialize the context, pass each chunk to
`hmac_sha256_update()`, and finish with `hmac_sha256_final()`.

```c
hmac_sha256_ctx ctx;
hmac_sha256_init(&ctx, key, key_len);
hmac_sha256_update(&ctx, buf1, len1);
hmac_sha256_update(&ctx, buf2, len2);
hmac_sha256_final(&ctx, mac);
```

Keys longer than 64 bytes are hashed before use. Finalizing clears the context.

### PBKDF2-HMAC-SHA256

Derive a 32-byte verifier using a caller-supplied 16-byte salt and a positive
iteration count. Measure execution time on the target before choosing the
iteration count.

```c
#include "hmac_sha256.h"

uint8_t verifier[32];
bool derived = pbkdf2_hmac_sha256(verifier, password, password_len, salt, iterations);
```

The function returns false for a zero iteration count, a null output or salt,
or a null password with a nonzero length. The output is untouched on failure.

## Salt usage

### Single-pass salted SHA-256

A fresh random salt makes identical inputs produce different digests.
Provide `salt` as a buffer already filled with 16 random bytes. The
incremental API computes `SHA256(salt || data)`:

```c
uint8_t hash[32];
sha256_ctx_t ctx;

sha256_init(&ctx);
sha256_update(&ctx, salt, 16U);      // Salt first
sha256_update(&ctx, data, data_len); // Then the input data
sha256_final(&ctx, hash);
```

Keep the salt alongside the digest if you need to reproduce it. For password
records, use [PBKDF2-HMAC-SHA256](#pbkdf2-hmac-sha256).

### Salt for a PBKDF2 password record

The calling application generates a fresh 16-byte salt from a cryptographically
secure random source when creating or replacing a password record. After a
successful derivation, store the salt and iteration count with the verifier.

To verify a password, load the stored salt, iteration count, and verifier.
Pass the candidate password and the stored parameters to
`pbkdf2_hmac_sha256()`, then compare the two verifiers in constant time.

## Testing

```
gcc -O2 -I. -o test_sha256 test/test_sha256.c sha256.c hmac_sha256.c
gcc -O2 -I. -o test_hmac_sha256 test/test_hmac_sha256.c hmac_sha256.c sha256.c
./test_sha256
./test_hmac_sha256
```

The SHA-256 suite covers known answers, padding, incremental updates, and
long inputs. The HMAC suite checks an RFC 4231 long-key vector with both APIs.
PBKDF2 vectors cover multiple iteration counts, an empty password, and a
password longer than the SHA-256 block size.

## License

Public domain / your project's license.
