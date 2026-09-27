/**
 * @file main.c
 * @brief Command-line demonstration of AES-256 CBC and AES-128 ECB encryption.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "aes.h"


/**
 * @brief Prints a labeled byte array in hexadecimal format.
 */
static void print_hex(const char *label, const uint8_t *data, size_t length) {
    printf("%-18s: ", label);
    for (size_t i = 0; i < length; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

int main(void) {
    /* 32-byte (2-block) zero-padded buffer */
    const char *message = "AES Crypto Engine by OST!";
    uint8_t buffer[32];

    /* 256-bit (32-byte) secret key */
    const uint8_t key_256[32] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };

    /* 128-bit (16-byte) Initialization Vector (IV) */
    const uint8_t iv[AES_BLOCK_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    /* Safely zero-pad the 32-byte buffer and copy the message without over-reading */
    memset(buffer, 0, sizeof(buffer));
    memcpy(buffer, message, strlen(message));

    printf("============================================================\n");
    printf("        AES-256 CBC Mode Encryption & Decryption Demo       \n");
    printf("============================================================\n");
    printf("Original ASCII    : %.32s\n", (const char *)buffer);
    print_hex("Plaintext (Hex)", buffer, sizeof(buffer));
    print_hex("IV (128-bit)", iv, sizeof(iv));

    /* Encrypt in-place using AES-256-CBC */
    cbc_encrypt(buffer, key_256, AES_KEY_SIZE_256, iv, sizeof(buffer));
    print_hex("Ciphertext (CBC)", buffer, sizeof(buffer));

    /* Decrypt in-place using AES-256-CBC */
    cbc_decrypt(buffer, key_256, AES_KEY_SIZE_256, iv, sizeof(buffer));
    print_hex("Decrypted (Hex)", buffer, sizeof(buffer));
    printf("Recovered ASCII   : %.32s\n", (const char *)buffer);
    printf("============================================================\n");

    return 0;
}