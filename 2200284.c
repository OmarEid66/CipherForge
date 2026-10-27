/*
 * Project: DES Encryption and Decryption
 *
 * Team Members:
 * 1. Omar Mohamed Eid    - ID: 2200284
 * 2. Youssef Yacoub Radi - ID: 2200649
 * 3. Ahmed Naggar Hassan - ID: 2200306
 *
 */

// 1. Standard C headers and constants
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const unsigned char PC1[56] = {
    57, 49, 41, 33, 25, 17,  9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4
};

static const unsigned char PC2[48] = {
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
};

static const unsigned char E[48] = {
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1
};

static const unsigned char SBOX[8][4][16] = {
    {
        {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
        {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
        {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
        {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
    },
    {
        {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
        {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
        {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
        {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
    },
    {
        {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
        {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
        {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
        {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
    },
    {
        {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
        {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
        {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
        {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
    },
    {
        {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
        {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
        {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
        {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
    },
    {
        {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
        {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
        {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
        {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
    },
    {
        {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
        {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
        {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
        {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
    },
    {
        {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
        {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
        {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
        {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
    }
};

static const unsigned char P[32] = {
    16,  7, 20, 21,
    29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2,  8, 24, 14,
    32, 27,  3,  9,
    19, 13, 30,  6,
    22, 11,  4, 25
};

static const unsigned char SHIFTS[16] = {
    1, 1, 2, 2, 2, 2, 2, 2,
    1, 2, 2, 2, 2, 2, 2, 1
};

static const unsigned char IP[64] = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
};

static const unsigned char FP[64] = {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
};


// 2. DES bit manipulation
// 2.1 Extract a bit
unsigned int get_bit_width(uint64_t value, unsigned int position, unsigned int width)
{
    if (width < 1 || width > 64 ||
        position < 1 || position > width)
    {
        return 0;
    }

    return (unsigned int)((value >> (width - position)) & UINT64_C(1));
}

// 2.2 Permute a bit sequence
uint64_t permute(uint64_t input, const unsigned char *table, unsigned int input_width, unsigned int output_width)
{
    uint64_t output = 0;

    for (unsigned int i = 0; i < output_width; ++i)
    {
        unsigned int input_position = table[i];

        if (input_position >= 1 && input_position <= input_width)
        {
            unsigned int bit_value =
                get_bit_width(input, input_position, input_width);

            output = (output << 1) | bit_value;
        }
    }

    return output;
}

// 2.3 converts 8 bytes into a 64-bit block
uint64_t load_block(const unsigned char *buffer)
{
    uint64_t block = 0;

    for (int i = 0; i < 8; ++i)
    {
        block |= ((uint64_t)buffer[i]) << (56 - 8 * i);
    }

    return block;
}

// 2.4 converts a 64-bit block into 8 bytes
void store_block(uint64_t block, unsigned char *buffer) {
    for (int i = 0; i < 8; ++i) {
        buffer[i] = (block >> (56 - 8 * i)) & 0xFF;
    }
}

// 2.5 Rotate a 28-bit half
uint32_t rotate_left_28(uint32_t value, unsigned int positions)
{
    positions %= 28;

    value &= UINT32_C(0x0FFFFFFF);

    return ((value << positions) |
            (value >> (28 - positions))) & UINT32_C(0x0FFFFFFF);
}



// 3. DES key schedule
// 3.1 Apply PC-1 permutation
uint64_t apply_pc1(uint64_t key)
{
    return permute(key, PC1, 64, 56);
}

// 3.2 split a 56-bit key into two 28-bit halves
void split_key(uint64_t key, uint32_t *C, uint32_t *D)
{
    *C = (uint32_t)((key >> 28) & UINT32_C(0x0FFFFFFF));
    *D = (uint32_t)(key & UINT32_C(0x0FFFFFFF));
}

// 3.3 rotate the halves according to the shift schedule
void rotate_key_halves(uint32_t *C, uint32_t *D, unsigned int round)
{
    if (round < 1 || round > 16)
    {
        return;
    }

    unsigned int shift = SHIFTS[round - 1];

    *C = rotate_left_28(*C, shift);
    *D = rotate_left_28(*D, shift);
}

// 3.4 Apply PC-2 permutation to generate a 48-bit subkey
uint64_t apply_pc2(uint32_t C, uint32_t D)
{
    uint64_t combined = ((uint64_t)C << 28) | (uint64_t)D;

    return permute(combined, PC2, 56, 48);
}

// 3.5 Generate all 16 subkeys from the original key
void generate_subkeys(uint64_t key, uint64_t subkeys[16])
{
    uint64_t permuted_key = apply_pc1(key);

    uint32_t C, D;
    split_key(permuted_key, &C, &D);

    for (unsigned int round = 1; round <= 16; ++round)
    {
        rotate_key_halves(&C, &D, round);
        subkeys[round - 1] = apply_pc2(C, D);
    }
}


// 4. DES round function
// 4.1 Expansion permutation
uint64_t expand_right(uint32_t right){
    return permute((uint64_t)right, E, 32, 48);
}

// 4.2 XOR with subkey
uint64_t xor_with_subkey(uint64_t expanded_right, uint64_t subkey){
    return expanded_right ^ subkey;
}

// 4.3 S-box substitution: 48 bits -> 32 bits
uint32_t s_box_substitution(uint64_t input)
{
    uint32_t output = 0;

    for (unsigned int i = 0; i < 8; ++i)
    {
        // Extract the current 6-bit group
        unsigned int shift = 42 - 6 * i;

        unsigned int six_bits =
            (unsigned int)((input >> shift) & UINT64_C(0x3F));

        // Row = first bit * 2 + last bit
        unsigned int row =
            ((six_bits & 0x20) >> 4) | (six_bits & 0x01);

        // Column = middle four bits
        unsigned int col = (six_bits >> 1) & 0x0F;

        // Look up the S-box result and append 4 bits
        unsigned int value = SBOX[i][row][col];

        output = (output << 4) | value;
    }

    return output;
}

// 4.4 P-permutation
uint32_t apply_p(uint32_t input)
{
    return (uint32_t)permute((uint64_t)input, P, 32, 32);
}

// 4.5 Complete round function
uint32_t des_round_function(uint32_t right, uint64_t round_key)
{
    uint64_t expanded = expand_right(right);

    uint64_t mixed = expanded ^ round_key;

    uint32_t substituted = s_box_substitution(mixed);

    return apply_p(substituted);
}



// 5. DES block processing
uint64_t des_process_block(uint64_t block, uint64_t subkeys[16], int decrypt){
    
    // Initial permutation
    uint64_t permuted_block = permute(block, IP, 64, 64);

    // Split into left and right halves
    uint32_t left = (uint32_t)(permuted_block >> 32);
    uint32_t right = (uint32_t)(permuted_block & UINT32_C(0xFFFFFFFF));

    // Determine the order of subkeys based on encryption or decryption
    int start = decrypt ? 15 : 0;
    int end = decrypt ? -1 : 16;
    int step = decrypt ? -1 : 1;

    // Perform 16 rounds of processing
    for (int round = start; round != end; round += step)
    {
        uint32_t temp = right;
        right = left ^ des_round_function(right, subkeys[round]);
        left = temp;
    }

    // Combine the halves in reverse order and apply final permutation
    uint64_t combined = ((uint64_t)right << 32) | (uint64_t)left;
    return permute(combined, FP, 64, 64);
}

// 6. File processing
// 6.1 Validate that the input file size is divisible by 8
// Returns: 1 = valid, 0 = invalid size, -1 = error
static int validate_input_size(
    FILE *input,
    unsigned long long *file_size
)
{
    // Move to the end of the file.
    if (_fseeki64(input, 0, SEEK_END) != 0)
    {
        fprintf(stderr, "Error: Unable to seek through input file.\n");
        return -1;
    }

    // Get the file size using a 64-bit file offset.
    long long size = _ftelli64(input);

    if (size < 0)
    {
        fprintf(stderr, "Error: Unable to determine input file size.\n");
        return -1;
    }

    *file_size = (unsigned long long)size;

    // Return to the beginning before processing.
    if (_fseeki64(input, 0, SEEK_SET) != 0)
    {
        fprintf(stderr, "Error: Unable to rewind input file.\n");
        return -1;
    }

    // DES requires complete 8-byte blocks.
    if ((*file_size % 8ULL) != 0)
    {
        fprintf(
            stderr,
            "Error: Input file size (%llu bytes) "
            "is not divisible by 8.\n",
            *file_size
        );

        return 0;
    }

    return 1;
}

// Returns 1 if paths refer to the same normalized path, 0 otherwise.
static int same_file_path(const char *input_path,
                          const char *output_path)
{
    char input_full[4096];
    char output_full[4096];

    if (_fullpath(input_full, input_path, sizeof(input_full)) == NULL ||
        _fullpath(output_full, output_path, sizeof(output_full)) == NULL)
    {
        fprintf(stderr, "Error: Unable to resolve file paths.\n");
        return -1;
    }

    return _stricmp(input_full, output_full) == 0;
}

// 6.2 Process a file using DES in buffered ECB mode
// decrypt = 0: Encrypt
// decrypt = 1: Decrypt
// Returns 1 on success, 0 on failure.
// Safety policy: do not overwrite an existing output file.
static int process_file(
    const char *input_path,
    const char *output_path,
    uint64_t key,
    int decrypt
)
{
    FILE *input = NULL;
    FILE *output = NULL;
    FILE *probe = NULL;

    unsigned char buffer[65536]; // 64 KiB buffer
    unsigned long long file_size = 0;
    unsigned long long total_processed = 0;
    uint64_t subkeys[16];

    char temp_path[8192];
    int success = 0;
    int temp_created = 0;

    int same = same_file_path(input_path, output_path);
    if (same != 0)
    {
        if (same == 1)
            fprintf(stderr, "Error: Input and output paths must be different.\n");
        return 0;
    }

    // Step 1: Open and validate the input before creating any output.
    input = fopen(input_path, "rb");
    if (input == NULL)
    {
        fprintf(stderr, "Error: Cannot open input file.\n");
        goto cleanup;
    }

    int validation = validate_input_size(input, &file_size);
    if (validation != 1)
        goto cleanup;

    // Step 2: Build a temporary path beside the requested output.
    // Keeping it in the same directory allows rename() to publish it there.
    int path_len = snprintf(temp_path, sizeof(temp_path), "%s.tmp", output_path);
    if (path_len < 0 || (size_t)path_len >= sizeof(temp_path))
    {
        fprintf(stderr, "Error: Output path is too long.\n");
        goto cleanup;
    }

    // Step 3: Never overwrite an existing final output.
    probe = fopen(output_path, "rb");
    if (probe != NULL)
    {
        fclose(probe);
        probe = NULL;
        fprintf(stderr,
                "Error: Output file already exists; choose a different output path.\n");
        goto cleanup;
    }

    // Refuse to reuse or truncate a pre-existing temporary file.
    probe = fopen(temp_path, "rb");
    if (probe != NULL)
    {
        fclose(probe);
        probe = NULL;
        fprintf(stderr,
                "Error: Temporary file already exists (%s). Remove or rename it first.\n",
                temp_path);
        goto cleanup;
    }

    // Step 4: Generate the subkeys once for the whole file.
    generate_subkeys(key, subkeys);

    // Step 5: Write only to the temporary file until processing succeeds.
    output = fopen(temp_path, "wb");
    if (output == NULL)
    {
        fprintf(stderr, "Error: Cannot create temporary output file.\n");
        goto cleanup;
    }
    temp_created = 1;

    // Step 6: Stream through the input in fixed-size chunks.
    while (1)
    {
        size_t bytes_read = fread(buffer, 1, sizeof(buffer), input);

        if (ferror(input))
        {
            fprintf(stderr, "Error: Failed to read input file.\n");
            goto cleanup;
        }

        // Detect a file that grew beyond the size measured during validation.
        if (total_processed > file_size ||
            (unsigned long long)bytes_read > file_size - total_processed)
        {
            fprintf(stderr, "Error: Input file grew during processing.\n");
            goto cleanup;
        }

        if (bytes_read == 0)
            break;

        if ((bytes_read % 8) != 0)
        {
            fprintf(stderr, "Error: Incomplete DES block encountered.\n");
            goto cleanup;
        }

        for (size_t offset = 0; offset < bytes_read; offset += 8)
        {
            uint64_t block = load_block(buffer + offset);
            block = des_process_block(block, subkeys, decrypt);
            store_block(block, buffer + offset);
        }

        size_t bytes_written = fwrite(buffer, 1, bytes_read, output);
        if (bytes_written != bytes_read)
        {
            fprintf(stderr, "Error: Failed to write temporary output file.\n");
            goto cleanup;
        }

        total_processed += (unsigned long long)bytes_written;
    }

    // Confirm that the full validated file was processed.
    if (total_processed != file_size)
    {
        fprintf(stderr, "Error: Input file size changed during processing.\n");
        goto cleanup;
    }

    success = 1;

cleanup:
    if (probe != NULL)
        fclose(probe);

    if (input != NULL)
    {
        if (fclose(input) != 0)
        {
            fprintf(stderr, "Error: Failed to close input file.\n");
            success = 0;
        }
    }

    if (output != NULL)
    {
        if (fclose(output) != 0)
        {
            fprintf(stderr, "Error: Failed to close temporary output file.\n");
            success = 0;
        }
    }

    // Publish only after all processing and close operations succeeded.
    if (success)
    {
        if (rename(temp_path, output_path) != 0)
        {
            fprintf(stderr,
                    "Error: Could not publish temporary output as the final output.\n"
                    "The destination may already exist or be inaccessible.\n");
            success = 0;
        }
        else
        {
            temp_created = 0;
        }
    }

    // Remove incomplete temporary output after any failure.
    if (temp_created)
    {
        if (remove(temp_path) != 0)
            fprintf(stderr, "Warning: Could not remove temporary file: %s\n", temp_path);
    }

    if (success)
    {
        printf("%s successful. Processed %llu bytes.\n",
               decrypt ? "Decryption" : "Encryption",
               file_size);
    }

    return success;
}

// 7. Parse exactly 16 hexadecimal characters into a 64-bit DES key.
// Accepts both uppercase and lowercase hexadecimal digits.
static int parse_hex_key(const char *text, uint64_t *key)
{
    uint64_t value = 0;

    if (text == NULL || key == NULL)
        return 0;

    // A DES key is represented here by exactly 16 hexadecimal digits.
    for (int i = 0; i < 16; ++i)
    {
        unsigned char c = (unsigned char)text[i];
        unsigned int nibble;

        if (c >= '0' && c <= '9')
            nibble = (unsigned int)(c - '0');
        else if (c >= 'A' && c <= 'F')
            nibble = (unsigned int)(c - 'A' + 10);
        else if (c >= 'a' && c <= 'f')
            nibble = (unsigned int)(c - 'a' + 10);
        else
            return 0;

        value = (value << 4) | (uint64_t)nibble;
    }

    // Reject strings longer than 16 characters.
    if (text[16] != '\0')
        return 0;

    *key = value;
    return 1;
}

// 8. Run the built-in DES encryption/decryption test vectors.
static int run_tests(void)
{
    static const struct {
        uint64_t key;
        uint64_t plaintext;
        uint64_t expected;
    } tests[] = {
        {
            UINT64_C(0x133457799BBCDFF1),
            UINT64_C(0x0123456789ABCDEF),
            UINT64_C(0x85E813540F0AB405)
        },
        {
            UINT64_C(0x0000000000000000),
            UINT64_C(0x0000000000000000),
            UINT64_C(0x8CA64DE9C1B123A7)
        },
        {
            UINT64_C(0xFFFFFFFFFFFFFFFF),
            UINT64_C(0xFFFFFFFFFFFFFFFF),
            UINT64_C(0x7359B2163E4EDC58)
        },
        {
            UINT64_C(0x133457799BBCDFF1),
            UINT64_C(0x0000000000000000),
            UINT64_C(0x948A43F98A834F7E)
        },
        {
            UINT64_C(0x133457799BBCDFF1),
            UINT64_C(0xFFFFFFFFFFFFFFFF),
            UINT64_C(0x5A3DB304D64924FD)
        }
    };

    const unsigned int count =
        (unsigned int)(sizeof(tests) / sizeof(tests[0]));

    unsigned int passed = 0;
    uint64_t subkeys[16];

    for (unsigned int i = 0; i < count; ++i)
    {
        generate_subkeys(tests[i].key, subkeys);

        uint64_t ciphertext =
            des_process_block(tests[i].plaintext, subkeys, 0);

        uint64_t recovered =
            des_process_block(ciphertext, subkeys, 1);

        int encryption_ok = ciphertext == tests[i].expected;
        int decryption_ok = recovered == tests[i].plaintext;

        printf("Test %u: %s\n", i + 1,
               encryption_ok && decryption_ok ? "PASS" : "FAIL");
        printf("  Key:        %016llX\n",
               (unsigned long long)tests[i].key);
        printf("  Plaintext:  %016llX\n",
               (unsigned long long)tests[i].plaintext);
        printf("  Expected:   %016llX\n",
               (unsigned long long)tests[i].expected);
        printf("  Actual:     %016llX\n",
               (unsigned long long)ciphertext);
        printf("  Recovered:  %016llX\n\n",
               (unsigned long long)recovered);

        if (encryption_ok && decryption_ok)
            ++passed;
    }

    printf("Results: %u/%u tests passed.\n", passed, count);
    return passed == count ? 0 : 1;
}

// 9. Command-line interface
// Usage: program e|d 16_HEX_DIGIT_KEY input_file output_file
// Running with no arguments executes the built-in test vectors.
int main(int argc, char *argv[])
{
    uint64_t key;
    int decrypt;

    if (argc == 1)
        return run_tests();

    if (argc != 5)
    {
        fprintf(stderr,
                "Usage:\n"
                "  %s e|d <16-hex-digit-key> <input-file> <output-file>\n"
                "  %s                 (run built-in tests)\n",
                argv[0], argv[0]);
        return 1;
    }

    if (argv[1][0] == 'e' && argv[1][1] == '\0')
        decrypt = 0;
    else if (argv[1][0] == 'd' && argv[1][1] == '\0')
        decrypt = 1;
    else
    {
        fprintf(stderr, "Error: Mode must be 'e' (encrypt) or 'd' (decrypt).\n");
        return 1;
    }

    if (!parse_hex_key(argv[2], &key))
    {
        fprintf(stderr,
                "Error: The DES key must contain exactly 16 hexadecimal digits.\n");
        return 1;
    }

    return process_file(argv[3], argv[4], key, decrypt) ? 0 : 1;
}
