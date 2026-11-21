/*
 * test_hmac_sha256.c
 * Author: Fatih Ozcan
 *         fatihozcan@gmail.com
 */
#include "hmac_sha256.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void assert_digest(const uint8_t digest[32U], const char expected[65U])
{
    static const char hex[] = "0123456789abcdef";
    char actual[65U] = {0};

    for (size_t index = 0U; index < 32U; index++)
    {
        actual[2U * index] = hex[digest[index] >> 4U];
        actual[2U * index + 1U] = hex[digest[index] & 0x0FU];
    }
    assert(strcmp(actual, expected) == 0);
}

static void test_hmac_long_key(void)
{
    static const uint8_t message[] = "Test Using Larger Than Block-Size Key - Hash Key First";
    static const char expected[] = "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54";
    uint8_t key[131U];
    uint8_t mac[32U];
    hmac_sha256_ctx ctx;

    memset(key, 0xAA, sizeof(key));
    hmac_sha256(mac, key, sizeof(key), message, sizeof(message) - 1U);
    assert_digest(mac, expected);

    hmac_sha256_init(&ctx, key, sizeof(key));
    hmac_sha256_update(&ctx, message, 13U);
    hmac_sha256_update(&ctx, NULL, 0U);
    hmac_sha256_update(&ctx, message + 13U, sizeof(message) - 14U);
    hmac_sha256_final(&ctx, mac);
    assert_digest(mac, expected);
}

static const uint8_t salt[PBKDF2_SHA256_SALT_SIZE] = {
    0U, 1U, 2U, 3U, 4U, 5U, 6U, 7U, 8U, 9U, 10U, 11U, 12U, 13U, 14U, 15U
};

static void test_pbkdf2_vectors(void)
{
    static const uint8_t password[] = "password";
    static const struct
    {
        uint32_t iterations;
        char expected[65U];
    } vectors[] = {
        {1U, "e1b08f92be8174d9f442d95d89aa4ccdc311231a4d70d0b854d1548de8fabdfd"},
        {2U, "a0ffd34292e4e7d519ee0f25124e0c5b9481d88be40f4662eb6cb4b9e43f9f41"},
        {4096U, "91700e3c494e10071700866601efd486e43765fa8b42b9a129203386a5ca509b"},
    };
    uint8_t derived[32U];
    uint8_t long_password[80U];

    for (size_t index = 0U; index < sizeof(vectors) / sizeof(vectors[0]); index++)
    {
        assert(pbkdf2_hmac_sha256(derived, password, sizeof(password) - 1U, salt, vectors[index].iterations));
        assert_digest(derived, vectors[index].expected);
    }

    assert(pbkdf2_hmac_sha256(derived, NULL, 0U, salt, 2U));
    assert_digest(derived, "b01769faf6a2ed2eb6258f32dca850daa77c443f81273b0efb782e1023abdb25");

    memset(long_password, 'x', sizeof(long_password));
    assert(pbkdf2_hmac_sha256(derived, long_password, sizeof(long_password), salt, 2U));
    assert_digest(derived, "5836dfbeac4d34b239de958efe52ce67f643ef4a97f9899cbf9a633a177a1a88");
}

static void test_pbkdf2_invalid_arguments(void)
{
    uint8_t derived[32U];
    uint8_t expected[32U];
    memset(derived, 0xA5, sizeof(derived));
    memset(expected, 0xA5, sizeof(expected));

    assert(!pbkdf2_hmac_sha256(derived, NULL, 0U, salt, 0U));
    assert(!pbkdf2_hmac_sha256(derived, NULL, 0U, NULL, 1U));
    assert(!pbkdf2_hmac_sha256(derived, NULL, 1U, salt, 1U));
    assert(!pbkdf2_hmac_sha256(NULL, NULL, 0U, salt, 1U));
    assert(memcmp(derived, expected, sizeof(derived)) == 0);
}

int main(void)
{
    test_hmac_long_key();
    test_pbkdf2_vectors();
    test_pbkdf2_invalid_arguments();
    puts("HMAC-SHA256 and PBKDF2-HMAC-SHA256 tests passed.");
    return 0;
}
/*** end of file ***/
