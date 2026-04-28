/*
 * SHA-256 / HMAC-SHA-256 Test
 *
 * Build:
 *   gcc -O2 -I.. -o test_sha256 test_sha256.c ../sha256.c ../hmac_sha256.c
 *
 * Run:
 *   ./test_sha256
 */

#include "sha256.h"
#include "hmac_sha256.h"
#include <stdio.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/*  Helper: convert 32-byte hash to hex string                       */
/* ------------------------------------------------------------------ */
static void to_hex(const uint8_t hash[32], char out[65]) {
    for (int i = 0; i < 32; i++)
        sprintf(out + i * 2, "%02x", hash[i]);
    out[64] = '\0';
}

/* ------------------------------------------------------------------ */
/*  Test vector structure                                             */
/* ------------------------------------------------------------------ */
typedef struct {
    const char *name;
    const char *input;
    size_t      input_len;
    const char *expected_hex;
} test_vector;

/* NIST FIPS 180-4 + common test vectors */
static const test_vector vectors[] = {
    {
        "Empty string",
        "",
        0,
        "e3b0c44298fc1c149afbf4c8996fb924"
        "27ae41e4649b934ca495991b7852b855"
    },
    {
        "\"abc\"",
        "abc",
        3,
        "ba7816bf8f01cfea414140de5dae2223"
        "b00361a396177a9cb410ff61f20015ad"
    },
    {
        "1 byte (0xbd)",
        "\xbd",
        1,
        "68325720aabd7c82f30f554b313d0570"
        "c95accbb7dc4b5aae11204c08ffe732b"
    },
    {
        "4 bytes (0xc98c8e55)",
        "\xc9\x8c\x8e\x55",
        4,
        "7abc22c0ae5af26ce93dbb94433a0e0b"
        "2e119d014f8e7f65bd56c61ccccd9504"
    },
    {
        "55 bytes (pad+len fits in one block)",
        "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrs",
        55,
        "82a01e3dd9cf63b32f2137747c00d92a"
        "eacfcea35dc58b37cf6b01fbcd7b5092"
    },
    {
        "448-bit (56 byte — padding boundary)",
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        56,
        "248d6a61d20638b8e5c026930c3e6039"
        "a33ce45964ff2167f6ecedd419db06c1"
    },
    {
        "63 bytes (one byte less than block)",
        "abcdefghijklmnopqrstuvwxyz0123456789"
        "abcdefghijklmnopqrstuvwxyz0",
        63,
        "b499f29a5bed5082ce023ec3a5e7f7df"
        "025e37906d05391cdeea9b6a2d1f1a8e"
    },
    {
        "64 bytes (exact one block)",
        "abcdefghijklmnopqrstuvwxyz0123456789"
        "abcdefghijklmnopqrstuvwxyz01",
        64,
        "9811e1ddf569b14d62a237a466700c99"
        "034c0836d098a02b2bd146265489c068"
    },
    {
        "65 bytes (one byte over block)",
        "abcdefghijklmnopqrstuvwxyz0123456789"
        "abcdefghijklmnopqrstuvwxyz012",
        65,
        "4e43e86934fadc32af139ed8d8dbd9cc"
        "1c1e9468ddcc136e0c64669f0b116bd2"
    },
    {
        "896-bit (112 byte — two-block padding)",
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
        "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        112,
        "cf5b16a778af8380036ce59e7b049237"
        "0b249b11e8f07a51afac45037afee9d1"
    },
    {
        "119 bytes (two-block padding boundary)",
        "abcdefghijklmnopqrstuvwxyz0123456789"
        "abcdefghijklmnopqrstuvwxyz0123456789"
        "abcdefghijklmnopqrstuvwxyz0123456789"
        "abcdefghijk",
        119,
        "b1a702951b2223de0788c49ac9fdfd63"
        "cbc653a61e993245b709e8034d7c6366"
    },
    {
        "128 bytes (exact two blocks)",
        "abcdefghijklmnopqrstuvwxyz0123456789"
        "abcdefghijklmnopqrstuvwxyz0123456789"
        "abcdefghijklmnopqrstuvwxyz0123456789"
        "abcdefghijklmnopqrst",
        128,
        "3c72b2c0505cf2b81c8743192935976a"
        "7906b5a123b5b0cdf3c5d66d7fef4c64"
    },
};

#define NUM_VECTORS (sizeof(vectors) / sizeof(vectors[0]))

/* ------------------------------------------------------------------ */
/*  Test 1: One-shot API                                              */
/* ------------------------------------------------------------------ */
static int test_oneshot(void) {
    int pass = 0, fail = 0;

    printf("=== One-shot API tests ===\n");
    for (size_t i = 0; i < NUM_VECTORS; i++) {
        uint8_t hash[32];
        char hex[65];

        sha256((const uint8_t *)vectors[i].input, vectors[i].input_len, hash);
        to_hex(hash, hex);

        if (strcmp(hex, vectors[i].expected_hex) == 0) {
            printf("  [PASS] %s\n", vectors[i].name);
            pass++;
        } else {
            printf("  [FAIL] %s\n", vectors[i].name);
            printf("    expected: %s\n", vectors[i].expected_hex);
            printf("    got:      %s\n", hex);
            fail++;
        }
    }

    printf("  Result: %d/%d passed\n\n", pass, pass + fail);
    return fail;
}

/* ------------------------------------------------------------------ */
/*  Test 2: Incremental API — feed data in varying chunks             */
/* ------------------------------------------------------------------ */
static int test_incremental(void) {
    int pass = 0, fail = 0;

    printf("=== Incremental API tests ===\n");
    for (size_t i = 0; i < NUM_VECTORS; i++) {
        const uint8_t *data = (const uint8_t *)vectors[i].input;
        size_t len = vectors[i].input_len;

        /* Feed data 1 byte at a time (worst-case test) */
        sha256_ctx ctx;
        sha256_init(&ctx);
        for (size_t j = 0; j < len; j++)
            sha256_update(&ctx, &data[j], 1);

        uint8_t hash[32];
        char hex[65];
        sha256_final(&ctx, hash);
        to_hex(hash, hex);

        if (strcmp(hex, vectors[i].expected_hex) == 0) {
            printf("  [PASS] %s (1-byte chunks)\n", vectors[i].name);
            pass++;
        } else {
            printf("  [FAIL] %s (1-byte chunks)\n", vectors[i].name);
            printf("    expected: %s\n", vectors[i].expected_hex);
            printf("    got:      %s\n", hex);
            fail++;
        }
    }

    /* Feed "abc" in 2 chunks: "a" + "bc" */
    {
        sha256_ctx ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, (const uint8_t *)"a", 1);
        sha256_update(&ctx, (const uint8_t *)"bc", 2);

        uint8_t hash[32];
        char hex[65];
        sha256_final(&ctx, hash);
        to_hex(hash, hex);

        const char *expected =
            "ba7816bf8f01cfea414140de5dae2223"
            "b00361a396177a9cb410ff61f20015ad";

        if (strcmp(hex, expected) == 0) {
            printf("  [PASS] \"abc\" (\"a\" + \"bc\" split)\n");
            pass++;
        } else {
            printf("  [FAIL] \"abc\" (\"a\" + \"bc\" split)\n");
            printf("    expected: %s\n", expected);
            printf("    got:      %s\n", hex);
            fail++;
        }
    }

    /* Empty updates should not affect the result */
    {
        sha256_ctx ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, (const uint8_t *)"a", 0);
        sha256_update(&ctx, (const uint8_t *)"abc", 3);
        sha256_update(&ctx, (const uint8_t *)"", 0);

        uint8_t hash[32];
        char hex[65];
        sha256_final(&ctx, hash);
        to_hex(hash, hex);

        const char *expected =
            "ba7816bf8f01cfea414140de5dae2223"
            "b00361a396177a9cb410ff61f20015ad";

        if (strcmp(hex, expected) == 0) {
            printf("  [PASS] \"abc\" with empty updates interleaved\n");
            pass++;
        } else {
            printf("  [FAIL] \"abc\" with empty updates interleaved\n");
            printf("    expected: %s\n", expected);
            printf("    got:      %s\n", hex);
            fail++;
        }
    }

    /* init + final with no update (zero-length input) */
    {
        sha256_ctx ctx;
        sha256_init(&ctx);

        uint8_t hash[32];
        char hex[65];
        sha256_final(&ctx, hash);
        to_hex(hash, hex);

        const char *expected =
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855";

        if (strcmp(hex, expected) == 0) {
            printf("  [PASS] init + final (no update)\n");
            pass++;
        } else {
            printf("  [FAIL] init + final (no update)\n");
            printf("    expected: %s\n", expected);
            printf("    got:      %s\n", hex);
            fail++;
        }
    }

    /* Feed 65 bytes as 64 + 1 (exact block boundary crossing) */
    {
        const char *input =
            "abcdefghijklmnopqrstuvwxyz0123456789"
            "abcdefghijklmnopqrstuvwxyz012";
        sha256_ctx ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, (const uint8_t *)input, 64);
        sha256_update(&ctx, (const uint8_t *)input + 64, 1);

        uint8_t hash[32];
        char hex[65];
        sha256_final(&ctx, hash);
        to_hex(hash, hex);

        const char *expected =
            "4e43e86934fadc32af139ed8d8dbd9cc"
            "1c1e9468ddcc136e0c64669f0b116bd2";

        if (strcmp(hex, expected) == 0) {
            printf("  [PASS] 65 bytes as 64+1 (block boundary cross)\n");
            pass++;
        } else {
            printf("  [FAIL] 65 bytes as 64+1 (block boundary cross)\n");
            printf("    expected: %s\n", expected);
            printf("    got:      %s\n", hex);
            fail++;
        }
    }

    printf("  Result: %d/%d passed\n\n", pass, pass + fail);
    return fail;
}

/* ------------------------------------------------------------------ */
/*  Test 3: 1 million 'a' characters (long data test)                 */
/* ------------------------------------------------------------------ */
static int test_million_a(void) {
    int fail = 0;

    printf("=== Long data test (1,000,000 x 'a') ===\n");

    /* Feed 1000 x 1000-byte chunks = 1,000,000 bytes */
    uint8_t buf[1000];
    memset(buf, 'a', sizeof(buf));

    sha256_ctx ctx;
    sha256_init(&ctx);
    for (int i = 0; i < 1000; i++)
        sha256_update(&ctx, buf, sizeof(buf));

    uint8_t hash[32];
    char hex[65];
    sha256_final(&ctx, hash);
    to_hex(hash, hex);

    const char *expected =
        "cdc76e5c9914fb9281a1c7e284d73e67"
        "f1809a48a497200e046d39ccc7112cd0";

    if (strcmp(hex, expected) == 0) {
        printf("  [PASS] 1.000.000 x 'a'\n");
    } else {
        printf("  [FAIL] 1.000.000 x 'a'\n");
        printf("    expected: %s\n", expected);
        printf("    got:      %s\n", hex);
        fail++;
    }

    printf("  Result: %d/1 passed\n\n", 1 - fail);
    return fail;
}

/* ------------------------------------------------------------------ */
/*  Test 4: File hashing (512KB binary file)                          */
/* ------------------------------------------------------------------ */
static int test_file_hash(void) {
    int fail = 0;

    printf("=== File hash test (512 KB) ===\n");

    const char *filename = "test_512k.bin";
    FILE *f = fopen(filename, "rb");
    if (!f) {
        printf("  [SKIP] %s not found\n\n", filename);
        return 0;
    }

    /* Hash the file in 256-byte chunks (realistic MCU buffer size) */
    sha256_ctx ctx;
    sha256_init(&ctx);

    uint8_t buf[256];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
        sha256_update(&ctx, buf, n);
    fclose(f);

    uint8_t hash[32];
    char hex[65];
    sha256_final(&ctx, hash);
    to_hex(hash, hex);

    /* SHA-256 of test_512k.bin: 512 KB pseudo-random (Python random, seed=20260325) */
    const char *expected =
        "cdacb237446efb460fb5a34079f4f9e0"
        "bae72ec26493ed3db4b7c7c9799d4231";

    if (strcmp(hex, expected) == 0) {
        printf("  [PASS] test_512k.bin (512 KB, 256-byte chunks)\n");
    } else {
        printf("  [FAIL] test_512k.bin (512 KB, 256-byte chunks)\n");
        printf("    expected: %s\n", expected);
        printf("    got:      %s\n", hex);
        fail++;
    }

    printf("  Result: %d/1 passed\n\n", 1 - fail);
    return fail;
}

/* ------------------------------------------------------------------ */
/*  Test 5: HMAC-SHA-256 — RFC 4231 known-answer tests               */
/* ------------------------------------------------------------------ */
static int test_hmac_sha256(void) {
    int pass = 0, fail = 0;

    printf("=== HMAC-SHA-256 tests (RFC 4231) ===\n");

    /* Helper macro to run one HMAC vector */
#define HMAC_CHECK(label, key, key_len, data, data_len, expected_hex) \
    do { \
        uint8_t mac[32]; \
        char    hex[65]; \
        hmac_sha256(mac, (const uint8_t *)(key), (key_len), \
                        (const uint8_t *)(data), (data_len)); \
        to_hex(mac, hex); \
        if (strcmp(hex, (expected_hex)) == 0) { \
            printf("  [PASS] %s\n", (label)); \
            pass++; \
        } else { \
            printf("  [FAIL] %s\n", (label)); \
            printf("    expected: %s\n", (expected_hex)); \
            printf("    got:      %s\n", hex); \
            fail++; \
        } \
    } while (0)

    /* --- TC1: 20-byte key of 0x0b, "Hi There" --- */
    {
        static const uint8_t key[] = {
            0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
            0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b
        };
        HMAC_CHECK("TC1: key=20x0b, data=\"Hi There\"",
                   key, sizeof(key), "Hi There", 8,
                   "b0344c61d8db38535ca8afceaf0bf12b"
                   "881dc200c9833da726e9376c2e32cff7");
    }

    /* --- TC2: "Jefe", "what do ya want for nothing?" --- */
    HMAC_CHECK("TC2: key=\"Jefe\", data=\"what do ya want for nothing?\"",
               "Jefe", 4,
               "what do ya want for nothing?", 28,
               "5bdcc146bf60754e6a042426089575c7"
               "5a003f089d2739839dec58b964ec3843");

    /* --- TC3: 20-byte key of 0xaa, 50-byte data of 0xdd --- */
    {
        static const uint8_t key[20]  = {
            0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
            0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa
        };
        static const uint8_t data[50] = {
            0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,
            0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,
            0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,
            0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,
            0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd
        };
        HMAC_CHECK("TC3: key=20x0xaa, data=50x0xdd",
                   key, sizeof(key), data, sizeof(data),
                   "773ea91e36800e46854db8ebd09181a7"
                   "2959098b3ef8c122d9635514ced565fe");
    }

    /* --- TC4: 25-byte sequential key, 50-byte data of 0xcd --- */
    {
        static const uint8_t key[] = {
            0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,
            0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,
            0x15,0x16,0x17,0x18,0x19
        };
        static const uint8_t data[50] = {
            0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,
            0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,
            0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,
            0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,
            0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd
        };
        HMAC_CHECK("TC4: key=0x01..0x19, data=50x0xcd",
                   key, sizeof(key), data, sizeof(data),
                   "82558a389a443c0ea4cc819899f2083a"
                   "85f0faa3e578f8077a2e3ff46729665b");
    }

    /* --- TC5: 20-byte key of 0x0c, "Test With Truncation" --- */
    {
        static const uint8_t key[20] = {
            0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,
            0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c
        };
        HMAC_CHECK("TC5: key=20x0x0c, data=\"Test With Truncation\"",
                   key, sizeof(key), "Test With Truncation", 20,
                   "a3b6167473100ee06e0c796c2955552b"
                   "fa6f7c0a6a8aef8b93f860aab0cd20c5");
    }

    /* --- TC6: 131-byte key of 0xaa (> block size), short data --- */
    {
        uint8_t key[131];
        memset(key, 0xaa, sizeof(key));
        HMAC_CHECK("TC6: key=131x0xaa (>block), \"Test Using Larger Than Block-Size Key - Hash Key First\"",
                   key, sizeof(key),
                   "Test Using Larger Than Block-Size Key - Hash Key First", 54,
                   "60e431591ee0b67f0d8a26aacbf5b77f"
                   "8e0bc6213728c5140546040f0ee37f54");
    }

    /* --- TC7: 131-byte key of 0xaa (> block size), long data --- */
    {
        uint8_t key[131];
        memset(key, 0xaa, sizeof(key));
        const char *data =
            "This is a test using a larger than block-size key and a larger"
            " than block-size data. The key needs to be hashed before being"
            " used by the HMAC algorithm.";
        HMAC_CHECK("TC7: key=131x0xaa (>block), long data",
                   key, sizeof(key), data, strlen(data),
                   "9b09ffa71b942fcb27635fbcd5b0e944"
                   "bfdc63644f0713938a7f51535c3a35e2");
    }

#undef HMAC_CHECK

    printf("  Result: %d/%d passed\n\n", pass, pass + fail);
    return fail;
}

/* ------------------------------------------------------------------ */
/*  Main                                                              */
/* ------------------------------------------------------------------ */
int main(void) {
    printf("libsha256 test suite\n");
    printf("====================\n\n");

    int total_fail = 0;
    total_fail += test_oneshot();
    total_fail += test_incremental();
    total_fail += test_million_a();
    total_fail += test_file_hash();
    total_fail += test_hmac_sha256();

    printf("====================\n");
    if (total_fail == 0)
        printf("ALL TESTS PASSED\n");
    else
        printf("%d TEST(S) FAILED\n", total_fail);

    return total_fail ? 1 : 0;
}
