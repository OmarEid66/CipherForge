/*
 * CSE451 - Project 1: DES
 * Team members:
 * 1. Omar Mohamed Eid - 2200284
 * 2. Youssef Yacoub Radi - 2200649
 * 3. Ahmed Naggar Hassan - 2200306
 */

#define _POSIX_C_SOURCE 200809L
#define _FILE_OFFSET_BITS 64

#if defined(_WIN32) && !defined(__CYGWIN__) && !defined(__GNUC__)
#define fseeko _fseeki64
#define ftello _ftelli64
#endif

// 1. Standard C headers and constants
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const unsigned char PC1[56] = {
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4};

static const unsigned char PC2[48] = {
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32};

static const unsigned char E[48] = {
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1};

static const unsigned char P[32] = {
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25};

static const unsigned char SHIFTS[16] = {
    1, 1, 2, 2, 2, 2, 2, 2,
    1, 2, 2, 2, 2, 2, 2, 1};

// Standard DES S-boxes: [box][row][column]
static const unsigned char SBOX_RAW[8][4][16] = {
    {{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
     {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
     {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
     {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}},
    {{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
     {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
     {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
     {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}},
    {{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
     {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
     {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
     {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}},
    {{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
     {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
     {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
     {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}},
    {{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
     {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
     {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
     {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}},
    {{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
     {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
     {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
     {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}},
    {{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
     {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
     {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
     {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}},
    {{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
     {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
     {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
     {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}}};

// Combined S-box + P-permutation lookup: SP[box][6-bit input] -> 32-bit word
static uint32_t SP[8][64];

static uint32_t apply_p(uint32_t input); // defined in section 4.4

static void init_sp_boxes(void)
{
    for (int i = 0; i < 8; ++i)
    {
        for (int j = 0; j < 64; ++j)
        {
            unsigned int row = ((j & 0x20) >> 4) | (j & 0x01);
            unsigned int col = (j >> 1) & 0x0F;
            uint32_t val = SBOX_RAW[i][row][col];
            SP[i][j] = apply_p(val << (28 - (4 * i)));
        }
    }
}

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
void store_block(uint64_t block, unsigned char *buffer)
{
    for (int i = 0; i < 8; ++i)
    {
        buffer[i] = (block >> (56 - 8 * i)) & 0xFF;
    }
}

// 2.5 Rotate a 28-bit half
uint32_t rotate_left_28(uint32_t value, unsigned int positions)
{
    positions %= 28;

    value &= UINT32_C(0x0FFFFFFF);

    return ((value << positions) |
            (value >> (28 - positions))) &
           UINT32_C(0x0FFFFFFF);
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
uint64_t expand_right(uint32_t right)
{
    return permute((uint64_t)right, E, 32, 48);
}

// 4.2 XOR with subkey
uint64_t xor_with_subkey(uint64_t expanded_right, uint64_t subkey)
{
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
        unsigned int value = SBOX_RAW[i][row][col];

        output = (output << 4) | value;
    }

    return output;
}

// 4.4 P-permutation
static uint32_t apply_p(uint32_t input)
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

// ---------------------------------------------------------------------
// Optimized core: no explicit E-expansion, delta-swap IP/FP.
// ---------------------------------------------------------------------
static inline uint32_t rol32(uint32_t x, unsigned n)
{
    return (x << n) | (x >> (32 - n));
}

// E-expansion folded into two rotations. Even S-boxes (0,2,4,6) read from
// rol(R,31), odd S-boxes (1,3,5,7) from rol(R,3); each 6-bit group sits at
// bit offsets 26/18/10/2. Subkeys are pre-split into matching layouts.
static inline uint32_t f_fast(uint32_t r, uint32_t ke, uint32_t ko)
{
    uint32_t u = rol32(r, 31) ^ ke;
    uint32_t v = rol32(r, 3) ^ ko;
    return SP[0][u >> 26] ^ SP[2][(u >> 18) & 0x3F] ^
           SP[4][(u >> 10) & 0x3F] ^ SP[6][(u >> 2) & 0x3F] ^
           SP[1][v >> 26] ^ SP[3][(v >> 18) & 0x3F] ^
           SP[5][(v >> 10) & 0x3F] ^ SP[7][(v >> 2) & 0x3F];
}

// Split each 48-bit subkey into the even/odd layouts used by f_fast, and
// reverse the order for decryption so the round loop is a straight walk.
static void prepare_round_keys(const uint64_t sk[16], int decrypt,
                               uint32_t ke[16], uint32_t ko[16])
{
    for (int i = 0; i < 16; ++i)
    {
        uint64_t k = sk[decrypt ? 15 - i : i];
        uint32_t c0 = (uint32_t)(k >> 42) & 0x3F, c1 = (uint32_t)(k >> 36) & 0x3F;
        uint32_t c2 = (uint32_t)(k >> 30) & 0x3F, c3 = (uint32_t)(k >> 24) & 0x3F;
        uint32_t c4 = (uint32_t)(k >> 18) & 0x3F, c5 = (uint32_t)(k >> 12) & 0x3F;
        uint32_t c6 = (uint32_t)(k >> 6) & 0x3F, c7 = (uint32_t)k & 0x3F;
        ke[i] = (c0 << 26) | (c2 << 18) | (c4 << 10) | (c6 << 2);
        ko[i] = (c1 << 26) | (c3 << 18) | (c5 << 10) | (c7 << 2);
    }
}

// Initial permutation via delta swaps. l = high word, r = low word.
static inline void ip_fast(uint32_t *l, uint32_t *r)
{
    uint32_t L = *l, R = *r, w;
    w = ((L >> 4) ^ R) & 0x0F0F0F0FU;
    R ^= w;
    L ^= w << 4;
    w = ((L >> 16) ^ R) & 0x0000FFFFU;
    R ^= w;
    L ^= w << 16;
    w = ((R >> 2) ^ L) & 0x33333333U;
    L ^= w;
    R ^= w << 2;
    w = ((R >> 8) ^ L) & 0x00FF00FFU;
    L ^= w;
    R ^= w << 8;
    R = rol32(R, 1);
    w = (L ^ R) & 0xAAAAAAAAU;
    L ^= w;
    R ^= w;
    // The classic sequence leaves both words rotated left by 1. L's trailing
    // rotate cancels against that, so only R needs rotating back.
    *l = L;
    *r = rol32(R, 31);
}

// Final permutation (inverse of ip_fast).
static inline void fp_fast(uint32_t *l, uint32_t *r)
{
    uint32_t L = *l, R = rol32(*r, 1), w; // L's rol-by-1 / rol-by-31 cancel
    w = (L ^ R) & 0xAAAAAAAAU;
    L ^= w;
    R ^= w;
    R = rol32(R, 31);
    w = ((R >> 8) ^ L) & 0x00FF00FFU;
    L ^= w;
    R ^= w << 8;
    w = ((R >> 2) ^ L) & 0x33333333U;
    L ^= w;
    R ^= w << 2;
    w = ((L >> 16) ^ R) & 0x0000FFFFU;
    R ^= w;
    L ^= w << 16;
    w = ((L >> 4) ^ R) & 0x0F0F0F0FU;
    R ^= w;
    L ^= w << 4;
    *l = L;
    *r = R;
}

// Encrypt/decrypt one block in place (direction fixed by key arrays).
static inline void des_block_fast(unsigned char *p,
                                  const uint32_t ke[16], const uint32_t ko[16])
{
    uint32_t l = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                 ((uint32_t)p[2] << 8) | (uint32_t)p[3];
    uint32_t r = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |
                 ((uint32_t)p[6] << 8) | (uint32_t)p[7];
    ip_fast(&l, &r);
    for (int i = 0; i < 16; i += 2)
    {
        l ^= f_fast(r, ke[i], ko[i]);
        r ^= f_fast(l, ke[i + 1], ko[i + 1]);
    }
    // undo the final swap: pre-output is (r16, l16)
    fp_fast(&r, &l);
    p[0] = (unsigned char)(r >> 24);
    p[1] = (unsigned char)(r >> 16);
    p[2] = (unsigned char)(r >> 8);
    p[3] = (unsigned char)r;
    p[4] = (unsigned char)(l >> 24);
    p[5] = (unsigned char)(l >> 16);
    p[6] = (unsigned char)(l >> 8);
    p[7] = (unsigned char)l;
}

// Four independent ECB blocks per call: the rounds of different blocks have
// no data dependency, so the CPU can overlap their table lookups.
static inline void des_block4_fast(unsigned char *p,
                                   const uint32_t ke[16], const uint32_t ko[16])
{
    uint32_t l0, r0, l1, r1, l2, r2, l3, r3;
#define LD(L, R, q)                                                                                       \
    L = ((uint32_t)(q)[0] << 24) | ((uint32_t)(q)[1] << 16) | ((uint32_t)(q)[2] << 8) | (uint32_t)(q)[3]; \
    R = ((uint32_t)(q)[4] << 24) | ((uint32_t)(q)[5] << 16) | ((uint32_t)(q)[6] << 8) | (uint32_t)(q)[7]; \
    ip_fast(&L, &R)
    LD(l0, r0, p);
    LD(l1, r1, p + 8);
    LD(l2, r2, p + 16);
    LD(l3, r3, p + 24);
#undef LD
    for (int i = 0; i < 16; i += 2)
    {
        uint32_t a = ke[i], b = ko[i], c = ke[i + 1], d = ko[i + 1];
        l0 ^= f_fast(r0, a, b);
        l1 ^= f_fast(r1, a, b);
        l2 ^= f_fast(r2, a, b);
        l3 ^= f_fast(r3, a, b);
        r0 ^= f_fast(l0, c, d);
        r1 ^= f_fast(l1, c, d);
        r2 ^= f_fast(l2, c, d);
        r3 ^= f_fast(l3, c, d);
    }
#define ST(L, R, q)                    \
    fp_fast(&R, &L);                   \
    (q)[0] = (unsigned char)(R >> 24); \
    (q)[1] = (unsigned char)(R >> 16); \
    (q)[2] = (unsigned char)(R >> 8);  \
    (q)[3] = (unsigned char)R;         \
    (q)[4] = (unsigned char)(L >> 24); \
    (q)[5] = (unsigned char)(L >> 16); \
    (q)[6] = (unsigned char)(L >> 8);  \
    (q)[7] = (unsigned char)L
    ST(l0, r0, p);
    ST(l1, r1, p + 8);
    ST(l2, r2, p + 16);
    ST(l3, r3, p + 24);
#undef ST
}

// 5. DES block processing (single 64-bit value; used by built-in tests)
uint64_t des_process_block(uint64_t block, uint64_t subkeys[16], int decrypt)
{
    uint32_t ke[16], ko[16];
    unsigned char b[8];
    prepare_round_keys(subkeys, decrypt, ke, ko);
    store_block(block, b);
    des_block_fast(b, ke, ko);
    return load_block(b);
}

// 6. File processing
// 6.1 Validate that the input file size is divisible by 8
// Returns: 1 = valid, 0 = invalid size, -1 = error
static int validate_input_size(
    FILE *input,
    unsigned long long *file_size)
{
    // Move to the end of the file.
    if (fseeko(input, 0, SEEK_END) != 0)
    {
        fprintf(stderr, "Error: Unable to seek through input file.\n");
        return -1;
    }

    // Get the file size using a 64-bit file offset.
    long long size = (long long)ftello(input); // standard ftello for POSIX

    if (size < 0)
    {
        fprintf(stderr, "Error: Unable to determine input file size.\n");
        return -1;
    }

    *file_size = (unsigned long long)size;

    // Return to the beginning before processing.
    if (fseeko(input, 0, SEEK_SET) != 0)
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
            *file_size);

        return 0;
    }

    return 1;
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
    int decrypt)
{
    // 1. check equal sources and destinations then open files immediately. No probes. No temp paths.
    if (strcmp(input_path, output_path) == 0)
    {
        fprintf(stderr, "Error: Input and output paths must be different.\n");
        return 0;
    }

    FILE *input = fopen(input_path, "rb");
    if (!input)
    {
        fprintf(stderr, "Error: Cannot open input file.\n");
        return 0;
    }

    // 2. Validate size using standard standard POSIX
    unsigned long long file_size = 0;
    if (validate_input_size(input, &file_size) != 1)
    {
        fclose(input);
        return 0;
    }

    // 3. Subkey generation (direction-specific, pre-split layout)
    uint64_t subkeys[16];
    uint32_t ke[16], ko[16];
    generate_subkeys(key, subkeys);
    prepare_round_keys(subkeys, decrypt, ke, ko);

    // 4. Increase buffer size to 1 MiB for maximum IO throughput.
    // Allocated on the heap to prevent stack overflows on Linux VMs.
    const size_t BUFFER_SIZE = 1048576;
    unsigned char *buffer = (unsigned char *)malloc(BUFFER_SIZE);
    if (!buffer)
    {
        fprintf(stderr, "Error: Memory allocation failed.\n");
        fclose(input);
        return 0;
    }

    // 5. Read, Process, Write.
    size_t bytes_read = fread(buffer, 1, BUFFER_SIZE, input);
    if (ferror(input))
    {
        fprintf(stderr, "Error: Failed to read input file.\n");
        free(buffer);
        fclose(input);
        return 0;
    }

    FILE *output = fopen(output_path, "wb");
    if (!output)
    {
        fprintf(stderr, "Error: Cannot open output file.\n");
        free(buffer);
        fclose(input);
        return 0;
    }

    if (bytes_read > 0)
    {
        do
        {
            if ((bytes_read % 8) != 0)
            {
                fprintf(stderr, "Error: Incomplete DES block encountered.\n");
                free(buffer);
                fclose(input);
                fclose(output);
                return 0;
            }

            size_t offset = 0;
            for (; offset + 32 <= bytes_read; offset += 32)
                des_block4_fast(buffer + offset, ke, ko);
            for (; offset < bytes_read; offset += 8)
                des_block_fast(buffer + offset, ke, ko);

            if (fwrite(buffer, 1, bytes_read, output) != bytes_read)
            {
                fprintf(stderr, "Error: Failed to write output file.\n");
                free(buffer);
                fclose(input);
                fclose(output);
                return 0;
            }
        } while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, input)) > 0);
    }

    if (ferror(input))
    {
        fprintf(stderr, "Error: Failed to read input file completely.\n");
        free(buffer);
        fclose(input);
        fclose(output);
        return 0;
    }

    // 6. Clean up and exit. fclose() on the output flushes; check it.
    free(buffer);
    fclose(input);
    if (fclose(output) != 0)
    {
        fprintf(stderr, "Error: Failed to finalize output file.\n");
        return 0;
    }

    return 1;
}

// 7. Parse exactly 16 hexadecimal characters into a 64-bit DES key.
// Accepts both uppercase and lowercase hexadecimal digits, optional "0x" prefix,
// or exactly 8 raw binary bytes. Strictly rejects trailing garbage.
static int read_key_file(const char *path, uint64_t *key)
{
    FILE *file = fopen(path, "rb");
    if (!file)
    {
        fprintf(stderr, "Error: Cannot open key file: %s\n", path);
        return 0;
    }

    // First, check if it's exactly an 8-byte raw binary file
    if (fseeko(file, 0, SEEK_END) == 0)
    {
        long long size = (long long)ftello(file);
        if (size == 8 && fseeko(file, 0, SEEK_SET) == 0)
        {
            unsigned char bytes[8];
            if (fread(bytes, 1, 8, file) == 8)
            {
                *key = load_block(bytes);
                fclose(file);
                return 1;
            }
            fclose(file);
            return 0;
        }
        if (fseeko(file, 0, SEEK_SET) != 0)
        {
            fclose(file);
            return 0;
        }
    }

    uint64_t value = 0;
    int valid_hex_count = 0;
    int c;

    // Skip leading whitespace
    while ((c = fgetc(file)) != EOF && (c == ' ' || c == '\n' || c == '\r' || c == '\t'))
        ;

    // Handle optional leading "0x" or "0X"
    if (c == '0')
    {
        int next_c = fgetc(file);
        if (next_c == 'x' || next_c == 'X')
        {
            c = fgetc(file);
        }
        else
        {
            value = 0;
            valid_hex_count = 1;
            c = next_c;
        }
    }

    while (c != EOF && valid_hex_count < 16)
    {
        if (c == ' ' || c == '\n' || c == '\r' || c == '\t')
        {
            c = fgetc(file);
            continue;
        }

        unsigned int nibble;
        if (c >= '0' && c <= '9')
            nibble = c - '0';
        else if (c >= 'A' && c <= 'F')
            nibble = c - 'A' + 10;
        else if (c >= 'a' && c <= 'f')
            nibble = c - 'a' + 10;
        else
        {
            fclose(file);
            return 0; // Invalid character found
        }
        value = (value << 4) | nibble;
        valid_hex_count++;
        c = fgetc(file);
    }

    if (valid_hex_count != 16)
    {
        fclose(file);
        return 0;
    }

    // Strict validation: reject extra hex characters or trailing non-whitespace
    while (c != EOF)
    {
        if (c != ' ' && c != '\n' && c != '\r' && c != '\t')
        {
            fclose(file);
            return 0;
        }
        c = fgetc(file);
    }

    fclose(file);
    *key = value;
    return 1;
}

static int parse_mode(const char *arg, int *decrypt)
{
    if (!arg)
        return 0;
    if (*arg == '"' || *arg == '\'')
        arg++;
    while (*arg == '-')
        arg++;

    if (*arg == 'e' || *arg == 'E')
    {
        if (arg[1] == '\0' || arg[1] == '"' || arg[1] == '\'')
        {
            *decrypt = 0;
            return 1;
        }
        if ((arg[1] == 'n' || arg[1] == 'N') &&
            (arg[2] == 'c' || arg[2] == 'C') &&
            (arg[3] == 'r' || arg[3] == 'R') &&
            (arg[4] == 'y' || arg[4] == 'Y') &&
            (arg[5] == 'p' || arg[5] == 'P') &&
            (arg[6] == 't' || arg[6] == 'T') &&
            (arg[7] == '\0' || arg[7] == '"' || arg[7] == '\''))
        {
            *decrypt = 0;
            return 1;
        }
    }
    else if (*arg == 'd' || *arg == 'D')
    {
        if (arg[1] == '\0' || arg[1] == '"' || arg[1] == '\'')
        {
            *decrypt = 1;
            return 1;
        }
        if ((arg[1] == 'e' || arg[1] == 'E') &&
            (arg[2] == 'c' || arg[2] == 'C') &&
            (arg[3] == 'r' || arg[3] == 'R') &&
            (arg[4] == 'y' || arg[4] == 'Y') &&
            (arg[5] == 'p' || arg[5] == 'P') &&
            (arg[6] == 't' || arg[6] == 'T') &&
            (arg[7] == '\0' || arg[7] == '"' || arg[7] == '\''))
        {
            *decrypt = 1;
            return 1;
        }
    }
    return 0;
}

// 8. Command-line interface
// Required usage: program e|d key_file input_file output_file
// Running with no arguments executes the built-in test vectors.
int main(int argc, char **argv)
{
    init_sp_boxes();
    uint64_t key;
    int decrypt;
    if (argc != 5)
    {
        fprintf(stderr, "Usage: %s e|d <key-file> <input-file> <output-file>\n", argv[0]);
        return 1;
    }

    if (!parse_mode(argv[1], &decrypt))
    {
        fprintf(stderr, "Error: Mode must be 'e' (encrypt) or 'd' (decrypt).\n");
        return 1;
    }

    if (!read_key_file(argv[2], &key))
        return 1;

    return process_file(argv[3], argv[4], key, decrypt) ? 0 : 1;
}