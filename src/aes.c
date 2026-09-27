/**
 * @file aes.c
 * @brief Implementation of the AES-128/192/256 Cryptographic Engine.
 *
 * Implements Galois Field GF(2^8) state transformations, key expansion,
 * block encryption/decryption, and ECB/CBC modes of operation based on
 * NIST FIPS PUB 197.
 */

#include "aes.h"

/* ========================================================================== */
/*                        S-BOX & INVERSE S-BOX TABLES                        */
/* ========================================================================== */

/**
 * @brief Forward AES S-Box substitution table (256 bytes).
 */
static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16
};

/**
 * @brief Inverse AES S-Box substitution table (256 bytes).
 */
static const uint8_t rsbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
    0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
    0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
    0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
    0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
    0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
    0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
    0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
    0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
    0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
    0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
    0x55, 0x21, 0x0c, 0x7d
};

/* ========================================================================== */
/*                         INTERNAL HELPER FUNCTIONS                          */
/* ========================================================================== */

/**
 * @brief Cyclically shifts a 4-byte array one position to the right.
 *
 * @param[in,out] temp_row_list Pointer to a 4-byte array.
 */
static void shift_one_right(uint8_t *temp_row_list) {
    uint8_t temp = temp_row_list[3];
    temp_row_list[3] = temp_row_list[2];
    temp_row_list[2] = temp_row_list[1];
    temp_row_list[1] = temp_row_list[0];
    temp_row_list[0] = temp;
}

/**
 * @brief Cyclically shifts a 4-byte array one position to the left (RotWord).
 *
 * @param[in,out] temp_row_list Pointer to a 4-byte array.
 */
static void shift_one_left(uint8_t *temp_row_list) {
    uint8_t temp = temp_row_list[0];
    temp_row_list[0] = temp_row_list[1];
    temp_row_list[1] = temp_row_list[2];
    temp_row_list[2] = temp_row_list[3];
    temp_row_list[3] = temp;
}

/* ========================================================================== */
/*                        KEY SCHEDULE & HELPER FUNCTIONS                     */
/* ========================================================================== */

unsigned int num_rounds(unsigned int key_size) {
    switch (key_size) {
        case AES_KEY_SIZE_128:
            return AES_ROUNDS_128;
        case AES_KEY_SIZE_192:
            return AES_ROUNDS_192;
        case AES_KEY_SIZE_256:
            return AES_ROUNDS_256;
        default:
            return 0;
    }
}

unsigned int num_key_words(unsigned int key_size) {
    switch (key_size) {
        case AES_KEY_SIZE_128:
            return 4;
        case AES_KEY_SIZE_192:
            return 6;
        case AES_KEY_SIZE_256:
            return 8;
        default:
            return 0;
    }
}

uint8_t get_sbox_value(uint8_t num) {
    return sbox[num];
}

uint8_t get_sbox_invert(uint8_t num) {
    return rsbox[num];
}

uint8_t rc(uint8_t num) {
    uint8_t round_const = 1;
    for (int i = 0; i < (int)num - 1; i++) {
        if (round_const >= 0x80) {
            round_const *= 2;
            round_const ^= 0x1B; /* Reduction by irreducible polynomial x^8 + x^4 + x^3 + x + 1 */
        } else {
            round_const *= 2;
        }
    }
    return round_const;
}

void key_expansion(const uint8_t *key, uint8_t *round_keys, unsigned int key_size) {
    int index;
    int round_num;
    uint8_t temp1[4];
    uint8_t temp4[4];
    uint8_t word_count = (uint8_t)num_key_words(key_size);
    uint8_t round_count = (uint8_t)num_rounds(key_size);
    uint8_t total_words = (uint8_t)(4 * (round_count + 1));
    uint8_t key_bytes = (uint8_t)(word_count * 4);

    for (index = 0; index < key_bytes; index++) {
        round_keys[index] = key[index];
    }

    for (int i = word_count; i < total_words; i++) {
        index = i * 4;
        round_num = i / word_count;

        for (int j = 0; j < 4; j++) {
            temp1[j] = round_keys[index - 4 + j];         /* Previous word W[i - 1] */
            temp4[j] = round_keys[index - key_bytes + j]; /* Word W[i - Nk] */
        }

        if (i % word_count == 0) {
            shift_one_left(temp1);
            for (int k = 0; k < 4; k++) {
                temp1[k] = get_sbox_value(temp1[k]);
            }
            temp1[0] ^= rc((uint8_t)round_num);
            for (int j = 0; j < 4; j++) {
                round_keys[index + j] = temp1[j] ^ temp4[j];
            }
        } else if ((i % word_count == 4) && (word_count > 6)) {
            /* Additional SubWord transformation for AES-256 (Nk = 8) */
            for (int k = 0; k < 4; k++) {
                temp1[k] = get_sbox_value(temp1[k]);
            }
            for (int j = 0; j < 4; j++) {
                round_keys[index + j] = temp1[j] ^ temp4[j];
            }
        } else {
            for (int j = 0; j < 4; j++) {
                round_keys[index + j] = temp1[j] ^ temp4[j];
            }
        }
    }
}

void get_round_key(const uint8_t *round_keys, uint8_t *round_key, uint8_t round) {
    int index;
    for (int i = 0; i < (int)AES_BLOCK_SIZE; i++) {
        index = i + (round * (int)AES_BLOCK_SIZE);
        round_key[i] = round_keys[index];
    }
}

/* ========================================================================== */
/*                     CORE AES STATE TRANSFORMATIONS                         */
/* ========================================================================== */

void add_round_key(uint8_t *state, const uint8_t *round_key) {
    for (int index = 0; index < (int)AES_BLOCK_SIZE; index++) {
        state[index] = round_key[index] ^ state[index];
    }
}

void sub_bytes(uint8_t *state) {
    for (int i = 0; i < (int)AES_BLOCK_SIZE; i++) {
        state[i] = get_sbox_value(state[i]);
    }
}

/*
 * State Matrix Column-Major Layout & ShiftRows Permutation:
 * 00 04 08 12                00 04 08 12
 * 01 05 09 13   ShiftRows    05 09 13 01
 * 02 06 10 14   --------->   10 14 02 06
 * 03 07 11 15                15 03 07 11
 */
void shift_rows(uint8_t *state) {
    uint8_t row_list[4];
    for (int row = 0; row < 4; row++) {
        row_list[0] = state[row];
        row_list[1] = state[row + 4];
        row_list[2] = state[row + 8];
        row_list[3] = state[row + 12];

        for (int i = 0; i < row; i++) {
            shift_one_left(row_list);
        }

        for (int i = 0; i < 4; i++) {
            state[row + (i * 4)] = row_list[i];
        }
    }
}

void multiply_2(uint8_t *state_copy_2x) {
    for (int i = 0; i < (int)AES_BLOCK_SIZE; i++) {
        if (state_copy_2x[i] > 127) { /* MSB is set (overflow in GF(2^8)) */
            state_copy_2x[i] *= 2;
            state_copy_2x[i] ^= 0x1B;
        } else {
            state_copy_2x[i] *= 2;
        }
    }
}

void multiply_3(uint8_t *state_copy_3x) {
    uint8_t temp[AES_BLOCK_SIZE];
    for (int i = 0; i < (int)AES_BLOCK_SIZE; i++) {
        temp[i] = state_copy_3x[i];
    }
    multiply_2(temp);
    for (int i = 0; i < (int)AES_BLOCK_SIZE; i++) {
        temp[i] ^= state_copy_3x[i];
        state_copy_3x[i] = temp[i];
    }
}

/*
 * MixColumns Polynomial Matrix Multiplication via Cyclic Coefficient Rotation:
 * Precomputes 2*state and 3*state tables, then rotates the polynomial row
 * {2, 3, 1, 1} right for each row element in a column.
 */
void mix_columns(uint8_t *state) {
    uint8_t state_2x[AES_BLOCK_SIZE];
    uint8_t state_3x[AES_BLOCK_SIZE];
    uint8_t polynom_row[4] = {2, 3, 1, 1};
    uint8_t temp[4];
    uint8_t poly_temp[4];
    uint8_t index;

    for (int i = 0; i < (int)AES_BLOCK_SIZE; i++) {
        state_2x[i] = state[i];
        state_3x[i] = state[i];
    }
    multiply_2(state_2x);
    multiply_3(state_3x);

    for (int col = 0; col < 4; col++) {
        for (int i = 0; i < 4; i++) {
            temp[i] = state[4 * col + i];
        }
        for (int j = 0; j < 4; j++) {
            for (int i = 0; i < 4; i++) {
                index = (uint8_t)(4 * col + i);
                if (polynom_row[i] == 2) {
                    poly_temp[i] = state_2x[index];
                } else if (polynom_row[i] == 3) {
                    poly_temp[i] = state_3x[index];
                } else {
                    poly_temp[i] = temp[i];
                }
            }
            index = (uint8_t)(4 * col + j);
            shift_one_right(polynom_row);
            state[index] = poly_temp[0] ^ poly_temp[1] ^ poly_temp[2] ^ poly_temp[3];
        }
    }
}

void inv_mix_columns(uint8_t *state) {
    uint8_t state_2x[AES_BLOCK_SIZE];
    uint8_t state_4x[AES_BLOCK_SIZE];
    uint8_t state_8x[AES_BLOCK_SIZE];
    uint8_t state_9x[AES_BLOCK_SIZE];  /* 9  = 8 ^ 1     */
    uint8_t state_11x[AES_BLOCK_SIZE]; /* 11 = 8 ^ 2 ^ 1 */
    uint8_t state_13x[AES_BLOCK_SIZE]; /* 13 = 8 ^ 4 ^ 1 */
    uint8_t state_14x[AES_BLOCK_SIZE]; /* 14 = 8 ^ 4 ^ 2 */

    uint8_t polynom_row[4] = {14, 11, 13, 9}; /* FIPS-197 inverse polynomial coefficients */
    uint8_t poly_temp[4];
    uint8_t index;

    for (int i = 0; i < (int)AES_BLOCK_SIZE; i++) {
        state_2x[i] = state[i];
    }
    multiply_2(state_2x);

    for (int i = 0; i < (int)AES_BLOCK_SIZE; i++) {
        state_4x[i] = state_2x[i];
    }
    multiply_2(state_4x);

    for (int i = 0; i < (int)AES_BLOCK_SIZE; i++) {
        state_8x[i] = state_4x[i];
    }
    multiply_2(state_8x);

    for (int i = 0; i < (int)AES_BLOCK_SIZE; i++) {
        state_9x[i]  = state_8x[i] ^ state[i];
        state_11x[i] = state_8x[i] ^ state_2x[i] ^ state[i];
        state_13x[i] = state_8x[i] ^ state_4x[i] ^ state[i];
        state_14x[i] = state_8x[i] ^ state_4x[i] ^ state_2x[i];
    }

    for (int col = 0; col < 4; col++) {
        for (int j = 0; j < 4; j++) {
            for (int i = 0; i < 4; i++) {
                index = (uint8_t)(4 * col + i);

                if (polynom_row[i] == 14) {
                    poly_temp[i] = state_14x[index];
                } else if (polynom_row[i] == 13) {
                    poly_temp[i] = state_13x[index];
                } else if (polynom_row[i] == 11) {
                    poly_temp[i] = state_11x[index];
                } else {
                    poly_temp[i] = state_9x[index];
                }
            }

            index = (uint8_t)(4 * col + j);
            shift_one_right(polynom_row);
            state[index] = poly_temp[0] ^ poly_temp[1] ^ poly_temp[2] ^ poly_temp[3];
        }
    }
}

void inv_sub_bytes(uint8_t *state) {
    for (int i = 0; i < (int)AES_BLOCK_SIZE; i++) {
        state[i] = get_sbox_invert(state[i]);
    }
}

void inv_shift_rows(uint8_t *state) {
    uint8_t row_list[4];
    for (int row = 0; row < 4; row++) {
        row_list[0] = state[row];
        row_list[1] = state[row + 4];
        row_list[2] = state[row + 8];
        row_list[3] = state[row + 12];

        for (int i = 0; i < row; i++) {
            shift_one_right(row_list);
        }

        for (int i = 0; i < 4; i++) {
            state[row + (i * 4)] = row_list[i];
        }
    }
}

/* ========================================================================== */
/*                       SINGLE-BLOCK CIPHER ROUTINES                         */
/* ========================================================================== */

void aes_encrypt_block(uint8_t *block, const uint8_t *round_keys, unsigned int rounds) {
    uint8_t round_key[AES_BLOCK_SIZE];
    get_round_key(round_keys, round_key, 0);
    add_round_key(block, round_key);

    for (unsigned int i = 1; i < rounds; i++) {
        sub_bytes(block);
        shift_rows(block);
        mix_columns(block);
        get_round_key(round_keys, round_key, (uint8_t)i);
        add_round_key(block, round_key);
    }

    sub_bytes(block);
    shift_rows(block);
    get_round_key(round_keys, round_key, (uint8_t)rounds);
    add_round_key(block, round_key);
}

void aes_decrypt_block(uint8_t *block, const uint8_t *round_keys, unsigned int rounds) {
    uint8_t round_key[AES_BLOCK_SIZE];
    get_round_key(round_keys, round_key, (uint8_t)rounds);
    add_round_key(block, round_key);
    inv_shift_rows(block);
    inv_sub_bytes(block);

    for (unsigned int i = rounds - 1; i > 0; i--) {
        get_round_key(round_keys, round_key, (uint8_t)i);
        add_round_key(block, round_key);
        inv_mix_columns(block);
        inv_shift_rows(block);
        inv_sub_bytes(block);
    }

    get_round_key(round_keys, round_key, 0);
    add_round_key(block, round_key);
}

/* ========================================================================== */
/*                     BLOCK CIPHER MODES OF OPERATION                        */
/* ========================================================================== */

void ecb_encrypt(uint8_t *content, const uint8_t *key, unsigned int key_size, size_t length) {
    uint8_t rounds = (uint8_t)num_rounds(key_size);
    uint8_t total_key_bytes = (uint8_t)((rounds + 1) * AES_BLOCK_SIZE);
    uint8_t round_keys[total_key_bytes];
    uint8_t block[AES_BLOCK_SIZE];
    size_t index;
    size_t num_blocks = length / AES_BLOCK_SIZE;

    key_expansion(key, round_keys, key_size);

    for (size_t i = 0; i < num_blocks; i++) {
        for (size_t j = 0; j < AES_BLOCK_SIZE; j++) {
            index = (i * AES_BLOCK_SIZE) + j;
            block[j] = content[index];
        }
        aes_encrypt_block(block, round_keys, rounds);
        for (size_t j = 0; j < AES_BLOCK_SIZE; j++) {
            index = (i * AES_BLOCK_SIZE) + j;
            content[index] = block[j];
        }
    }
}

void ecb_decrypt(uint8_t *content, const uint8_t *key, unsigned int key_size, size_t length) {
    uint8_t rounds = (uint8_t)num_rounds(key_size);
    uint8_t total_key_bytes = (uint8_t)((rounds + 1) * AES_BLOCK_SIZE);
    uint8_t round_keys[total_key_bytes];
    uint8_t block[AES_BLOCK_SIZE];
    size_t index;
    size_t num_blocks = length / AES_BLOCK_SIZE;

    key_expansion(key, round_keys, key_size);

    for (size_t i = 0; i < num_blocks; i++) {
        for (size_t j = 0; j < AES_BLOCK_SIZE; j++) {
            index = (i * AES_BLOCK_SIZE) + j;
            block[j] = content[index];
        }
        aes_decrypt_block(block, round_keys, rounds);
        for (size_t j = 0; j < AES_BLOCK_SIZE; j++) {
            index = (i * AES_BLOCK_SIZE) + j;
            content[index] = block[j];
        }
    }
}

void cbc_encrypt(uint8_t *content, const uint8_t *key, unsigned int key_size, const uint8_t *iv, size_t length) {
    uint8_t rounds = (uint8_t)num_rounds(key_size);
    uint8_t total_key_bytes = (uint8_t)((rounds + 1) * AES_BLOCK_SIZE);
    uint8_t round_keys[total_key_bytes];
    uint8_t block[AES_BLOCK_SIZE];
    uint8_t current_iv[AES_BLOCK_SIZE];
    size_t index;
    size_t num_blocks = length / AES_BLOCK_SIZE;

    for (size_t i = 0; i < AES_BLOCK_SIZE; i++) {
        current_iv[i] = iv[i];
    }

    key_expansion(key, round_keys, key_size);

    for (size_t i = 0; i < num_blocks; i++) {
        for (size_t j = 0; j < AES_BLOCK_SIZE; j++) {
            index = (i * AES_BLOCK_SIZE) + j;
            block[j] = content[index];
        }
        /* XOR plaintext block with the current chaining vector */
        for (size_t j = 0; j < AES_BLOCK_SIZE; j++) {
            block[j] ^= current_iv[j];
        }
        aes_encrypt_block(block, round_keys, rounds);

        /* Ciphertext block becomes the chaining vector for the next block */
        for (size_t j = 0; j < AES_BLOCK_SIZE; j++) {
            current_iv[j] = block[j];
        }
        for (size_t j = 0; j < AES_BLOCK_SIZE; j++) {
            index = (i * AES_BLOCK_SIZE) + j;
            content[index] = block[j];
        }
    }
}

void cbc_decrypt(uint8_t *content, const uint8_t *key, unsigned int key_size, const uint8_t *iv, size_t length) {
    uint8_t rounds = (uint8_t)num_rounds(key_size);
    uint8_t total_key_bytes = (uint8_t)((rounds + 1) * AES_BLOCK_SIZE);
    uint8_t round_keys[total_key_bytes];
    uint8_t block[AES_BLOCK_SIZE];
    uint8_t next_iv[AES_BLOCK_SIZE];
    uint8_t current_iv[AES_BLOCK_SIZE];
    size_t index;
    size_t num_blocks = length / AES_BLOCK_SIZE;

    key_expansion(key, round_keys, key_size);

    for (size_t i = 0; i < AES_BLOCK_SIZE; i++) {
        current_iv[i] = iv[i];
    }

    for (size_t i = 0; i < num_blocks; i++) {
        for (size_t j = 0; j < AES_BLOCK_SIZE; j++) {
            index = (i * AES_BLOCK_SIZE) + j;
            block[j] = content[index];
        }

        /* Save current ciphertext block to serve as IV for the next block */
        for (size_t j = 0; j < AES_BLOCK_SIZE; j++) {
            next_iv[j] = block[j];
        }

        aes_decrypt_block(block, round_keys, rounds);

        /* XOR decrypted block with the current chaining vector */
        for (size_t j = 0; j < AES_BLOCK_SIZE; j++) {
            block[j] ^= current_iv[j];
        }

        /* Advance chaining vector for the next iteration */
        for (size_t j = 0; j < AES_BLOCK_SIZE; j++) {
            current_iv[j] = next_iv[j];
        }

        for (size_t j = 0; j < AES_BLOCK_SIZE; j++) {
            index = (i * AES_BLOCK_SIZE) + j;
            content[index] = block[j];
        }
    }
}