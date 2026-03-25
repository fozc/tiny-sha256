/*
 * SHA-256 Test — NIST FIPS 180-4 known-answer tests
 *
 * Build:
 *   gcc -O2 -I.. -o test_sha256 test_sha256.c ../sha256.c
 *
 * Run:
 *   ./test_sha256
 */

#include "sha256.h"
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

    printf("====================\n");
    if (total_fail == 0)
        printf("ALL TESTS PASSED\n");
    else
        printf("%d TEST(S) FAILED\n", total_fail);

    return total_fail ? 1 : 0;
}
