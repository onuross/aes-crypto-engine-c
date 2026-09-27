/**
 * @file test_aes.c
 * @brief Official NIST FIPS-197 & SP 800-38A Verification Suite for AES Engine.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "aes.h"

#define COLOR_GREEN "\033[0;32m"
#define COLOR_RED   "\033[0;31m"
#define COLOR_RESET "\033[0m"

static int g_tests_run = 0;
static int g_tests_passed = 0;

/**
 * @brief Compares two byte buffers and logs the test result.
 */
static void assert_bytes_equal(const char *test_name, const uint8_t *actual, const uint8_t *expected, size_t len) {
    g_tests_run++;
    if (memcmp(actual, expected, len) == 0) {
        g_tests_passed++;
        printf("[%sPASS%s] %s\n", COLOR_GREEN, COLOR_RESET, test_name);
    } else {
        printf("[%sFAIL%s] %s\n", COLOR_RED, COLOR_RESET, test_name);
        printf("  Expected: ");
        for (size_t i = 0; i < len; i++) {
            printf("%02x", expected[i]);
        }
        printf("\n  Actual:   ");
        for (size_t i = 0; i < len; i++) {
            printf("%02x", actual[i]);
        }
        printf("\n");
    }
}

/**
 * @brief Tests AES-128, AES-192, and AES-256 single-block operations against NIST FIPS-197 Appendix C.
 */
static void test_nist_fips197_vectors(void) {
    const uint8_t plaintext[AES_BLOCK_SIZE] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };

    /* --- AES-128 (NIST FIPS-197 Appendix C.1) --- */
    const uint8_t key_128[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    const uint8_t expected_cipher_128[AES_BLOCK_SIZE] = {
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
        0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a
    };
    uint8_t round_keys_128[(AES_ROUNDS_128 + 1) * AES_BLOCK_SIZE];
    uint8_t block_128[AES_BLOCK_SIZE];

    memcpy(block_128, plaintext, AES_BLOCK_SIZE);
    key_expansion(key_128, round_keys_128, AES_KEY_SIZE_128);
    aes_encrypt_block(block_128, round_keys_128, AES_ROUNDS_128);
    assert_bytes_equal("NIST FIPS-197 C.1: AES-128 Block Encrypt", block_128, expected_cipher_128, AES_BLOCK_SIZE);

    aes_decrypt_block(block_128, round_keys_128, AES_ROUNDS_128);
    assert_bytes_equal("NIST FIPS-197 C.1: AES-128 Block Decrypt", block_128, plaintext, AES_BLOCK_SIZE);

    /* --- AES-192 (NIST FIPS-197 Appendix C.2) --- */
    const uint8_t key_192[24] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
    };
    const uint8_t expected_cipher_192[AES_BLOCK_SIZE] = {
        0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0,
        0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91
    };
    uint8_t round_keys_192[(AES_ROUNDS_192 + 1) * AES_BLOCK_SIZE];
    uint8_t block_192[AES_BLOCK_SIZE];

    memcpy(block_192, plaintext, AES_BLOCK_SIZE);
    key_expansion(key_192, round_keys_192, AES_KEY_SIZE_192);
    aes_encrypt_block(block_192, round_keys_192, AES_ROUNDS_192);
    assert_bytes_equal("NIST FIPS-197 C.2: AES-192 Block Encrypt", block_192, expected_cipher_192, AES_BLOCK_SIZE);

    aes_decrypt_block(block_192, round_keys_192, AES_ROUNDS_192);
    assert_bytes_equal("NIST FIPS-197 C.2: AES-192 Block Decrypt", block_192, plaintext, AES_BLOCK_SIZE);

    /* --- AES-256 (NIST FIPS-197 Appendix C.3) --- */
    const uint8_t key_256[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    const uint8_t expected_cipher_256[AES_BLOCK_SIZE] = {
        0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
        0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89
    };
    uint8_t round_keys_256[(AES_ROUNDS_256 + 1) * AES_BLOCK_SIZE];
    uint8_t block_256[AES_BLOCK_SIZE];

    memcpy(block_256, plaintext, AES_BLOCK_SIZE);
    key_expansion(key_256, round_keys_256, AES_KEY_SIZE_256);
    aes_encrypt_block(block_256, round_keys_256, AES_ROUNDS_256);
    assert_bytes_equal("NIST FIPS-197 C.3: AES-256 Block Encrypt", block_256, expected_cipher_256, AES_BLOCK_SIZE);

    aes_decrypt_block(block_256, round_keys_256, AES_ROUNDS_256);
    assert_bytes_equal("NIST FIPS-197 C.3: AES-256 Block Decrypt", block_256, plaintext, AES_BLOCK_SIZE);
}

/**
 * @brief Tests multi-block ECB and CBC modes against NIST SP 800-38A Appendix F.
 */
static void test_nist_sp800_38a_modes(void) {
    const uint8_t key_128[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    const uint8_t iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    const uint8_t plaintext[32] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51
    };
    const uint8_t expected_ecb[32] = {
        0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
        0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97,
        0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d,
        0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf
    };
    const uint8_t expected_cbc[32] = {
        0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
        0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
        0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee,
        0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2
    };

    uint8_t buffer[32];

    /* ECB Mode Test */
    memcpy(buffer, plaintext, sizeof(buffer));
    ecb_encrypt(buffer, key_128, AES_KEY_SIZE_128, sizeof(buffer));
    assert_bytes_equal("NIST SP 800-38A F.1.1: AES-128 ECB Encrypt (2 Blocks)", buffer, expected_ecb, sizeof(buffer));

    ecb_decrypt(buffer, key_128, AES_KEY_SIZE_128, sizeof(buffer));
    assert_bytes_equal("NIST SP 800-38A F.1.2: AES-128 ECB Decrypt (2 Blocks)", buffer, plaintext, sizeof(buffer));

    /* CBC Mode Test */
    memcpy(buffer, plaintext, sizeof(buffer));
    cbc_encrypt(buffer, key_128, AES_KEY_SIZE_128, iv, sizeof(buffer));
    assert_bytes_equal("NIST SP 800-38A F.2.1: AES-128 CBC Encrypt (2 Blocks)", buffer, expected_cbc, sizeof(buffer));

    cbc_decrypt(buffer, key_128, AES_KEY_SIZE_128, iv, sizeof(buffer));
    assert_bytes_equal("NIST SP 800-38A F.2.2: AES-128 CBC Decrypt (2 Blocks)", buffer, plaintext, sizeof(buffer));
}

int main(void) {
    printf("============================================================\n");
    printf("   AES Cryptographic Engine - NIST Verification Test Suite  \n");
    printf("============================================================\n");

    test_nist_fips197_vectors();
    test_nist_sp800_38a_modes();

    printf("------------------------------------------------------------\n");
    printf("Test Summary: %d / %d passed.\n", g_tests_passed, g_tests_run);
    printf("============================================================\n");

    return (g_tests_passed == g_tests_run) ? 0 : 1;
}