/**
 * @file aes.h
 * @brief Advanced Encryption Standard (AES-128/192/256) Cryptographic Engine API.
 *
 * Provides low-level Galois Field GF(2^8) state transformations, key schedule
 * expansion, single-block cipher routines, and block cipher modes of operation
 * (ECB and CBC) compliant with NIST FIPS PUB 197.
 */

#ifndef AES_H
#define AES_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================== */
/*                           AES CONSTANTS & MACROS                           */
/* ========================================================================== */

#define AES_BLOCK_SIZE      16U   /**< AES block size in bytes (128 bits) */

#define AES_KEY_SIZE_128    128U  /**< 128-bit key length */
#define AES_KEY_SIZE_192    192U  /**< 192-bit key length */
#define AES_KEY_SIZE_256    256U  /**< 256-bit key length */

#define AES_ROUNDS_128      10U   /**< Number of rounds for AES-128 */
#define AES_ROUNDS_192      12U   /**< Number of rounds for AES-192 */
#define AES_ROUNDS_256      14U   /**< Number of rounds for AES-256 */

/* ========================================================================== */
/*                        KEY SCHEDULE & HELPER FUNCTIONS                     */
/* ========================================================================== */

/**
 * @brief Determines the number of AES rounds based on the key size.
 *
 * @param[in] key_size Key size in bits (128, 192, or 256).
 * @return unsigned int Number of rounds (10 for 128-bit, 12 for 192-bit, 14 for 256-bit keys).
 */
unsigned int num_rounds(unsigned int key_size);

/**
 * @brief Determines the number of 32-bit words (Nk) in the cipher key.
 *
 * @param[in] key_size Key size in bits (128, 192, or 256).
 * @return unsigned int Number of 32-bit words (4 for 128-bit, 6 for 192-bit, 8 for 256-bit keys).
 */
unsigned int num_key_words(unsigned int key_size);

/**
 * @brief Retrieves a substituted byte value from the forward AES S-Box.
 *
 * The S-Box (Substitution Box) applies a non-linear byte substitution used in
 * the SubBytes transformation and KeyExpansion routine.
 *
 * @param[in] num Byte value to look up in the S-Box (0x00 - 0xFF).
 * @return uint8_t Substituted byte value from the S-Box.
 */
uint8_t get_sbox_value(uint8_t num);

/**
 * @brief Retrieves a substituted byte value from the inverse AES S-Box.
 *
 * The inverse S-Box is used during the InvSubBytes transformation in AES decryption.
 *
 * @param[in] num Byte value to look up in the inverse S-Box (0x00 - 0xFF).
 * @return uint8_t Substituted byte value from the inverse S-Box.
 */
uint8_t get_sbox_invert(uint8_t num);

/**
 * @brief Computes the round constant (Rcon) for the AES key schedule.
 *
 * Calculated as x^(num-1) in the Galois Field GF(2^8) modulo the
 * irreducible polynomial m(x) = x^8 + x^4 + x^3 + x + 1.
 *
 * @param[in] num Round index (1-10 for AES-128, 1-12 for AES-192, 1-14 for AES-256).
 * @return uint8_t Round constant byte value.
 */
uint8_t rc(uint8_t num);

/**
 * @brief Expands the original cipher key into the full round key schedule.
 *
 * Generates the expanded key material required for AddRoundKey operations across
 * all encryption and decryption rounds.
 *
 * @param[in]  key        Pointer to the original cipher key (16, 24, or 32 bytes).
 * @param[out] round_keys Pointer to buffer storing expanded keys (16 * (rounds + 1) bytes).
 * @param[in]  key_size   Key size in bits (128, 192, or 256).
 */
void key_expansion(const uint8_t *key, uint8_t *round_keys, unsigned int key_size);

/**
 * @brief Extracts a specific 16-byte round key from the expanded key schedule.
 *
 * @param[in]  round_keys Pointer to the expanded key schedule produced by key_expansion().
 * @param[out] round_key  Pointer to the 16-byte buffer where the extracted round key is stored.
 * @param[in]  round      Target round index (0 to rounds, where 0 is the initial pre-whitening key).
 */
void get_round_key(const uint8_t *round_keys, uint8_t *round_key, uint8_t round);

/* ========================================================================== */
/*                     CORE AES STATE TRANSFORMATIONS                         */
/* ========================================================================== */

/**
 * @brief Performs the AddRoundKey transformation.
 *
 * Combines the 16-byte AES state matrix with the 16-byte round key via bitwise XOR.
 *
 * @param[in,out] state     Pointer to the 16-byte AES state matrix.
 * @param[in]     round_key Pointer to the 16-byte round key.
 */
void add_round_key(uint8_t *state, const uint8_t *round_key);

/**
 * @brief Performs the SubBytes transformation.
 *
 * Independently substitutes each byte in the 16-byte state matrix using the
 * forward AES S-Box.
 *
 * @param[in,out] state Pointer to the 16-byte AES state matrix.
 */
void sub_bytes(uint8_t *state);

/**
 * @brief Performs the ShiftRows transformation.
 *
 * Cyclically shifts the rows of the 4x4 state matrix to the left by their row index:
 * - Row 0: No shift
 * - Row 1: Left shift by 1 byte
 * - Row 2: Left shift by 2 bytes
 * - Row 3: Left shift by 3 bytes
 *
 * @param[in,out] state Pointer to the 16-byte AES state matrix.
 */
void shift_rows(uint8_t *state);

/**
 * @brief Multiplies each byte of a 16-byte state buffer by 2 (xtime) in GF(2^8).
 *
 * Used in the MixColumns transformation. Implemented as a 1-bit left shift
 * followed by a conditional bitwise XOR with the irreducible polynomial
 * reduction byte 0x1B upon MSB overflow.
 *
 * @param[in,out] state_copy_2x Pointer to the 16-byte state buffer to multiply in-place.
 */
void multiply_2(uint8_t *state_copy_2x);

/**
 * @brief Multiplies each byte of a 16-byte state buffer by 3 in GF(2^8).
 *
 * Used in the MixColumns transformation. Computed as 3 * x = (2 * x) ^ x.
 *
 * @param[in,out] state_copy_3x Pointer to the 16-byte state buffer to multiply in-place.
 */
void multiply_3(uint8_t *state_copy_3x);

/**
 * @brief Performs the MixColumns transformation.
 *
 * Treats each column of the state matrix as a four-term polynomial over GF(2^8)
 * and multiplies it modulo x^4 + 1 with the fixed polynomial
 * a(x) = {03}x^3 + {01}x^2 + {01}x + {02}.
 *
 * @param[in,out] state Pointer to the 16-byte AES state matrix.
 */
void mix_columns(uint8_t *state);

/**
 * @brief Performs the InvMixColumns transformation.
 *
 * Multiplies each column of the state matrix modulo x^4 + 1 with the fixed
 * inverse polynomial a^-1(x) = {0b}x^3 + {0d}x^2 + {09}x + {0e} in GF(2^8).
 *
 * @param[in,out] state Pointer to the 16-byte AES state matrix.
 */
void inv_mix_columns(uint8_t *state);

/**
 * @brief Performs the InvSubBytes transformation.
 *
 * Substitutes each byte in the 16-byte state matrix with its corresponding
 * inverse S-Box value.
 *
 * @param[in,out] state Pointer to the 16-byte AES state matrix.
 */
void inv_sub_bytes(uint8_t *state);

/**
 * @brief Performs the InvShiftRows transformation.
 *
 * Cyclically shifts the rows of the 4x4 state matrix to the right by their row index:
 * - Row 0: No shift
 * - Row 1: Right shift by 1 byte
 * - Row 2: Right shift by 2 bytes
 * - Row 3: Right shift by 3 bytes
 *
 * @param[in,out] state Pointer to the 16-byte AES state matrix.
 */
void inv_shift_rows(uint8_t *state);

/* ========================================================================== */
/*                       SINGLE-BLOCK CIPHER ROUTINES                         */
/* ========================================================================== */

/**
 * @brief Encrypts a single 16-byte block using the AES cipher.
 *
 * Executes the standard AES encryption pipeline:
 * 1. Initial AddRoundKey (Round 0)
 * 2. Main Rounds (1 to rounds - 1): SubBytes -> ShiftRows -> MixColumns -> AddRoundKey
 * 3. Final Round (rounds): SubBytes -> ShiftRows -> AddRoundKey
 *
 * @param[in,out] block      Pointer to the 16-byte plaintext block (encrypted in-place).
 * @param[in]     round_keys Pointer to the expanded round key schedule.
 * @param[in]     rounds     Number of rounds (10 for AES-128, 12 for AES-192, 14 for AES-256).
 */
void aes_encrypt_block(uint8_t *block, const uint8_t *round_keys, unsigned int rounds);

/**
 * @brief Decrypts a single 16-byte block using the AES inverse cipher.
 *
 * Executes the standard AES decryption pipeline:
 * 1. Initial AddRoundKey (Round = rounds)
 * 2. Main Rounds (rounds - 1 down to 1): InvShiftRows -> InvSubBytes -> AddRoundKey -> InvMixColumns
 * 3. Final Round (Round 0): InvShiftRows -> InvSubBytes -> AddRoundKey
 *
 * @param[in,out] block      Pointer to the 16-byte ciphertext block (decrypted in-place).
 * @param[in]     round_keys Pointer to the expanded round key schedule.
 * @param[in]     rounds     Number of rounds (10 for AES-128, 12 for AES-192, 14 for AES-256).
 */
void aes_decrypt_block(uint8_t *block, const uint8_t *round_keys, unsigned int rounds);

/* ========================================================================== */
/*                     BLOCK CIPHER MODES OF OPERATION                        */
/* ========================================================================== */

/**
 * @brief Encrypts a data buffer using AES in Electronic Codebook (ECB) mode.
 *
 * Encrypts each 16-byte block independently.
 * @warning ECB mode does not conceal data patterns and is not semantically secure.
 *
 * @param[in,out] content  Pointer to the plaintext buffer (encrypted in-place).
 * @param[in]     key      Pointer to the cipher key (16, 24, or 32 bytes).
 * @param[in]     key_size Key size in bits (128, 192, or 256).
 * @param[in]     length   Total payload length in bytes (must be a multiple of 16).
 */
void ecb_encrypt(uint8_t *content, const uint8_t *key, unsigned int key_size, size_t length);

/**
 * @brief Decrypts a data buffer using AES in Electronic Codebook (ECB) mode.
 *
 * Decrypts each 16-byte block independently.
 *
 * @param[in,out] content  Pointer to the ciphertext buffer (decrypted in-place).
 * @param[in]     key      Pointer to the cipher key (16, 24, or 32 bytes).
 * @param[in]     key_size Key size in bits (128, 192, or 256).
 * @param[in]     length   Total payload length in bytes (must be a multiple of 16).
 */
void ecb_decrypt(uint8_t *content, const uint8_t *key, unsigned int key_size, size_t length);

/**
 * @brief Encrypts a data buffer using AES in Cipher Block Chaining (CBC) mode.
 *
 * XORs each plaintext block with the preceding ciphertext block prior to encryption.
 * The first plaintext block is XORed with the 16-byte Initialization Vector (IV).
 *
 * @param[in,out] content  Pointer to the plaintext buffer (encrypted in-place).
 * @param[in]     key      Pointer to the cipher key (16, 24, or 32 bytes).
 * @param[in]     key_size Key size in bits (128, 192, or 256).
 * @param[in]     iv       Pointer to the 16-byte Initialization Vector (IV).
 * @param[in]     length   Total payload length in bytes (must be a multiple of 16).
 */
void cbc_encrypt(uint8_t *content, const uint8_t *key, unsigned int key_size, const uint8_t *iv, size_t length);

/**
 * @brief Decrypts a data buffer using AES in Cipher Block Chaining (CBC) mode.
 *
 * Decrypts each ciphertext block and XORs the output with the previous ciphertext
 * block (or the IV for the first block) to recover the plaintext.
 *
 * @param[in,out] content  Pointer to the ciphertext buffer (decrypted in-place).
 * @param[in]     key      Pointer to the cipher key (16, 24, or 32 bytes).
 * @param[in]     key_size Key size in bits (128, 192, or 256).
 * @param[in]     iv       Pointer to the 16-byte Initialization Vector (IV).
 * @param[in]     length   Total payload length in bytes (must be a multiple of 16).
 */
void cbc_decrypt(uint8_t *content, const uint8_t *key, unsigned int key_size, const uint8_t *iv, size_t length);

#ifdef __cplusplus
}
#endif

#endif /* AES_H */