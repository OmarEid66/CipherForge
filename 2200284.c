// 1. Standard C headers and constants
#include <stdint.h>
#include <stdio.h>

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

static const unsigned char SHIFTS[16] = {
    1, 1, 2, 2, 2, 2, 2, 2,
    1, 2, 2, 2, 2, 2, 2, 1
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
// 5. DES block processing
// 6. File processing
//7. main(argc, argv)
int main(void)
{
    uint64_t key = UINT64_C(0x133457799BBCDFF1);
    uint64_t subkeys[16];

    generate_subkeys(key, subkeys);

    printf("DES Round Keys:\n\n");

    for (unsigned int i = 0; i < 16; ++i)
    {
        printf("K%02u = %012llX\n",
               i + 1,
               (unsigned long long)subkeys[i]);
    }

    return 0;
}